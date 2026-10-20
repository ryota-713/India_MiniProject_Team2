"""Demo EC shop (customer-side screen) for the AI cyberattack detection presentation.

Standard library only. This is an intentionally insecure TEACHING target that runs
only on localhost against throwaway, fake data. It exists so the team's detection
dashboard (../MyProject) can be shown catching two classic attacks during the demo:

  * SQL injection on the login form (e.g. admin' OR 1=1 --)
  * Brute-force login (many failed attempts from one source)

Every request is recorded in the detection system's own 7-field event schema
(event_id, timestamp, source, method, path, status_code, user_agent) and served at
/api/monitor/events so the dashboard can poll this shop by IP and analyse it live.

Safety notes:
  * No real user data. The "database" is an in-memory SQLite table of two fake rows.
  * The deliberately vulnerable login is only reachable when SHOP_VULNERABLE=1
    (the default for the demo) and the server binds to a local address.
  * Passwords are never written to the event log; only the attempted username is,
    because the detector needs it in the request path to recognise the payload.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"
LOG_FILE = BASE_DIR / "logs" / "ec_events.json"

HOST = os.environ.get("EC_HOST", "127.0.0.1")
PORT = int(os.environ.get("EC_PORT", "8080"))

# Intentionally vulnerable login for the teaching demo (string-concatenated SQL).
# Set SHOP_VULNERABLE=0 to use the safe, parameterised login instead.
VULNERABLE = os.environ.get("SHOP_VULNERABLE", "1") == "1"

# Fake accounts seeded into a throwaway in-memory table. Not real credentials.
ADMIN_USER = os.environ.get("EC_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("EC_ADMIN_PASSWORD", "admin1234")

SESSION_COOKIE = "ec_session"
MAX_BODY = 8192
MAX_PATH = 2000  # keep under the detector's 2048-char path limit
LOGGED_HEADERS = ("User-Agent",)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

PRODUCTS = [
    {"id": 1, "name": "Wireless Headphones", "category": "Electronics", "price": 4999, "rating": 4.5, "emoji": "🎧", "badge": "Best Seller"},
    {"id": 2, "name": "Smart Watch", "category": "Electronics", "price": 8999, "rating": 4.3, "emoji": "⌚", "badge": "New"},
    {"id": 3, "name": "Laptop Backpack", "category": "Fashion", "price": 1899, "rating": 4.6, "emoji": "🎒", "badge": ""},
    {"id": 4, "name": "Running Shoes", "category": "Fashion", "price": 3499, "rating": 4.4, "emoji": "👟", "badge": "20% OFF"},
    {"id": 5, "name": "Masala Chai Set", "category": "Food", "price": 599, "rating": 4.8, "emoji": "🍵", "badge": "Popular"},
    {"id": 6, "name": "Organic Coffee Beans", "category": "Food", "price": 899, "rating": 4.2, "emoji": "☕", "badge": ""},
    {"id": 7, "name": "Bluetooth Speaker", "category": "Electronics", "price": 2799, "rating": 4.1, "emoji": "🔊", "badge": ""},
    {"id": 8, "name": "Desk Plant", "category": "Home", "price": 449, "rating": 4.7, "emoji": "🪴", "badge": "Eco"},
    {"id": 9, "name": "Ceramic Mug Pair", "category": "Home", "price": 699, "rating": 4.5, "emoji": "🫖", "badge": ""},
    {"id": 10, "name": "Sunglasses", "category": "Fashion", "price": 1299, "rating": 4.0, "emoji": "🕶️", "badge": "Sale"},
    {"id": 11, "name": "Mechanical Keyboard", "category": "Electronics", "price": 5599, "rating": 4.6, "emoji": "⌨️", "badge": ""},
    {"id": 12, "name": "Scented Candle", "category": "Home", "price": 349, "rating": 4.3, "emoji": "🕯️", "badge": ""},
]

_sessions: dict[str, str] = {}
_log_lock = threading.Lock()
_events: list[dict] = []


# --------------------------------------------------------------------------- DB
def _fake_db() -> sqlite3.Connection:
    """A throwaway in-memory table of fake accounts — no real data touches this."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE users (username TEXT, password TEXT, role TEXT)")
    conn.executemany(
        "INSERT INTO users VALUES (?, ?, ?)",
        [(ADMIN_USER, ADMIN_PASSWORD, "admin"), ("guest", "guest", "customer")],
    )
    conn.commit()
    return conn


_DB = _fake_db()
_db_lock = threading.Lock()


def check_login(username: str, password: str) -> bool:
    """Return True if the credentials authenticate.

    When VULNERABLE, the username and password are concatenated straight into the
    SQL string — the textbook flaw that lets `admin' OR 1=1 --` log in without a
    valid password. This is deliberate and only ever runs on a local demo build.
    """
    with _db_lock:
        if VULNERABLE:
            query = (
                "SELECT 1 FROM users WHERE username = '"
                + username
                + "' AND password = '"
                + password
                + "'"
            )
            try:
                return _DB.execute(query).fetchone() is not None
            except sqlite3.Error:
                return False
        row = _DB.execute(
            "SELECT 1 FROM users WHERE username = ? AND password = ?", (username, password)
        ).fetchone()
        return row is not None


# ------------------------------------------------------------------------- log
def _load_events() -> None:
    if LOG_FILE.exists():
        try:
            _events.extend(json.loads(LOG_FILE.read_text(encoding="utf-8")).get("events", []))
        except (OSError, ValueError):
            pass


def _clean(text: str, limit: int) -> str:
    return _CONTROL.sub(" ", text)[:limit]


def record_event(method: str, path: str, status: int, source: str, user_agent: str | None) -> None:
    """Append one event in the detection system's 7-field schema and persist it."""
    event = {
        "event_id": "ec-" + secrets.token_hex(8),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z"),
        "source": source,
        "method": method if re.fullmatch(r"[A-Z]{1,16}", method) else "GET",
        "path": _clean(path if path.startswith("/") else "/" + path, MAX_PATH),
        "status_code": status if 100 <= status <= 599 else 400,
        "user_agent": _clean(user_agent, 512) if user_agent else None,
    }
    # ISO-8601 with a timezone, e.g. 2026-10-20T09:00:00+0000 -> +00:00
    event["timestamp"] = event["timestamp"][:-2] + ":" + event["timestamp"][-2:]
    with _log_lock:
        _events.append(event)
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = LOG_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({"events": _events}, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(LOG_FILE)


def recent_events(since: int, limit: int = 2000) -> tuple[list[dict], int]:
    with _log_lock:
        total = len(_events)
        start = max(0, min(since, total))
        return [dict(e) for e in _events[start:][:limit]], total


class ShopHandler(BaseHTTPRequestHandler):
    server_version = "DemoShop/2.0"

    # ---- helpers -------------------------------------------------------------
    def _source(self) -> str:
        return self.client_address[0]

    def _session_user(self) -> str | None:
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        morsel = jar.get(SESSION_COOKIE)
        return _sessions.get(morsel.value) if morsel else None

    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)
        self._status = status

    def _redirect(self, location: str, extra: dict | None = None) -> None:
        self._send(303, b"", "text/plain", {"Location": location, **(extra or {})})

    def _file(self, name: str) -> None:
        path = (PUBLIC_DIR / name).resolve()
        if PUBLIC_DIR not in path.parents or not path.is_file():
            self._send(404, b"Not Found", "text/plain; charset=utf-8")
            return
        ctype = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                 ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml"}.get(path.suffix, "application/octet-stream")
        self._send(200, path.read_bytes(), ctype)

    def _json(self, data, status: int = 200) -> None:
        self._send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _record(self, path_override: str | None = None, status_override: int | None = None) -> None:
        # The status written to the event log may differ from the status sent to the
        # browser: a failed login shows the user a friendly redirect (303) but is
        # logged as 401 so the detector's brute-force rule can group the attempts.
        status = status_override if status_override is not None else getattr(self, "_status", 500)
        record_event(self.command, path_override or self.path, status,
                     self._source(), self.headers.get("User-Agent"))

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {self.client_address[0]} {fmt % args}")

    # ---- GET -----------------------------------------------------------------
    def do_GET(self):
        url = urlsplit(self.path)
        user = self._session_user()
        record = True
        try:
            if url.path in ("/", "/index.html"):
                self._redirect("/home" if user else "/login")
            elif url.path == "/login":
                self._redirect("/home") if user else self._file("login.html")
            elif url.path == "/home":
                self._file("home.html") if user else self._redirect("/login")
            elif url.path == "/logout":
                jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
                if SESSION_COOKIE in jar:
                    _sessions.pop(jar[SESSION_COOKIE].value, None)
                self._redirect("/login", {"Set-Cookie": f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"})
            elif url.path == "/health":
                record = False
                self._json({"ok": True, "vulnerable": VULNERABLE})
            elif url.path == "/api/monitor/events":
                # Polled by the detection dashboard; not part of the attack surface.
                record = False
                qs = parse_qs(url.query)
                try:
                    since = int(qs.get("since", ["0"])[0])
                except ValueError:
                    since = 0
                events, total = recent_events(since)
                self._json({"events": events, "total": total, "returned": len(events)})
            elif url.path == "/api/me":
                self._json({"user": user}) if user else self._json({"error": "unauthorized"}, 401)
            elif url.path == "/api/products":
                if not user:
                    self._json({"error": "unauthorized"}, 401)
                else:
                    qs = parse_qs(url.query)
                    q = qs.get("q", [""])[0].strip().lower()
                    cat = qs.get("category", [""])[0]
                    items = [p for p in PRODUCTS
                             if (not q or q in p["name"].lower() or q in p["category"].lower())
                             and (not cat or cat == "All" or p["category"] == cat)]
                    self._json({"products": items})
            elif url.path.startswith("/static/"):
                self._file(url.path[len("/static/"):])
            else:
                self._send(404, b"Not Found", "text/plain; charset=utf-8")
        finally:
            if record:
                self._record()

    # ---- POST ----------------------------------------------------------------
    def do_POST(self):
        url = urlsplit(self.path)
        length = min(int(self.headers.get("Content-Length", "0") or 0), MAX_BODY)
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        log_path = self.path
        log_status: int | None = None
        try:
            if url.path == "/login":
                form = parse_qs(raw, keep_blank_values=True)
                username = form.get("username", [""])[0]
                password = form.get("password", [""])[0]
                # Record the attempted username in the path (never the password) so the
                # detector can see payloads like admin' OR 1=1 -- in the request path.
                log_path = "/login?username=" + quote(_clean(username, 300), safe="")
                if check_login(username, password):
                    token = secrets.token_urlsafe(32)
                    _sessions[token] = username
                    self._redirect("/home", {"Set-Cookie": f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax"})
                else:
                    # Show the user the login page with an error message (303 redirect),
                    # but log the attempt as 401 so the brute-force rule can group it.
                    self._redirect("/login?error=1")
                    log_status = 401
            else:
                self._send(404, b"Not Found", "text/plain; charset=utf-8")
        finally:
            self._record(log_path, log_status)

    def do_PUT(self):
        self._send(405, b"Method Not Allowed", "text/plain; charset=utf-8")
        self._record()

    do_DELETE = do_PATCH = do_PUT


def _is_local(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost",)


def main() -> None:
    if VULNERABLE and not _is_local(HOST):
        raise SystemExit(
            f"Refusing to expose the intentionally vulnerable demo on non-local host {HOST!r}. "
            "Bind to 127.0.0.1, or set SHOP_VULNERABLE=0."
        )
    _load_events()
    httpd = ThreadingHTTPServer((HOST, PORT), ShopHandler)
    mode = "VULNERABLE demo" if VULNERABLE else "safe"
    print(f"Demo shop ({mode}) on http://{HOST}:{PORT}  monitor feed: /api/monitor/events")
    print(f"Events -> {LOG_FILE}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
