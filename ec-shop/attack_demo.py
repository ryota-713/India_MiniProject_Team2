"""Brute-force / SQL-injection demo driver for the local presentation only.

This sends login attempts to YOUR OWN demo shop (server.py) so the detection
dashboard can be shown catching a brute-force burst and a SQL-injection attempt in
real time. It is a teaching prop, not an attack tool:

  * It refuses any target that is not a loopback or private address. You cannot point
    it at a public host.
  * The request rate and the total number of attempts are capped.
  * It only exercises the login form of a shop you are running yourself.

Example (from the presentation folder):

    python ec-shop/attack_demo.py --target 127.0.0.1:8080 --rate 5 --count 30

Run `python ec-shop/attack_demo.py --help` for all options.
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

MAX_RATE = 20          # attempts per second (hard cap)
MAX_COUNT = 2000       # total attempts (hard cap)
REQUEST_TIMEOUT = 4.0

# A short, obviously-fake wordlist plus the classic SQL-injection tautology, so the
# demo triggers both the brute-force rule and the SQL-injection rule.
PASSWORD_LIST = ["123456", "password", "admin", "qwerty", "letmein", "welcome", "test1234"]
SQLI_USERNAME = "admin' OR 1=1 --"


def _host_is_local(host: str) -> bool:
    candidates = [host]
    try:
        candidates += [info[4][0] for info in socket.getaddrinfo(host, None)]
    except OSError:
        pass
    saw_ip = False
    for value in candidates:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        saw_ip = True
        if not (address.is_loopback or address.is_private or address.is_link_local):
            return False
    return saw_ip or host == "localhost"


def normalise_target(target: str) -> str:
    if "://" not in target:
        target = "http://" + target
    parts = urlsplit(target)
    if parts.scheme != "http":
        raise SystemExit("Only http:// local targets are allowed.")
    host = parts.hostname or ""
    if not _host_is_local(host):
        raise SystemExit(
            f"Refusing to target {host!r}: this demo tool only runs against a loopback "
            "or private address (your own demo shop)."
        )
    port = parts.port or 8080
    return f"http://{host}:{port}"


def attempt_login(base_url: str, username: str, password: str) -> int:
    data = urlencode({"username": username, "password": password}).encode("utf-8")
    request = Request(f"{base_url}/login", data=data, method="POST")
    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT) as response:  # noqa: S310 (local http)
            return response.status
    except HTTPError as exc:
        return exc.code
    except URLError as exc:
        raise SystemExit(f"Cannot reach {base_url}: {exc}. Is the demo shop running?") from exc


def run(base_url: str, rate: float, count: int, include_sqli: bool) -> None:
    interval = 1.0 / rate
    successes = failures = sqli_hits = 0
    print(f"Target        : {base_url}")
    print(f"Rate / count  : ~{rate:g}/s, {count} attempts")
    print(f"SQLi payload  : {'yes' if include_sqli else 'no'}")
    print("-" * 56)
    start = time.monotonic()
    for index in range(count):
        if include_sqli and index == count // 2:
            username, password = SQLI_USERNAME, "x"
        else:
            username, password = "admin", PASSWORD_LIST[index % len(PASSWORD_LIST)]
        status = attempt_login(base_url, username, password)
        if username == SQLI_USERNAME:
            sqli_hits += 1
            label = "SQLi attempt"
        elif status in (301, 302, 303):
            successes += 1
            label = "LOGIN OK"
        else:
            failures += 1
            label = "failed"
        print(f"[{index + 1:>3}/{count}] {username:<20} -> {status} {label}")
        target_time = start + (index + 1) * interval
        time.sleep(max(0.0, target_time - time.monotonic()))
    elapsed = time.monotonic() - start
    print("-" * 56)
    print(
        f"Done in {elapsed:.1f}s: {failures} failed, {successes} succeeded, "
        f"{sqli_hits} SQLi attempts. Watch the dashboard's Live Attack Monitor."
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Brute-force demo driver for the local demo shop.")
    parser.add_argument("--target", default="127.0.0.1:8080", help="Local demo shop (default 127.0.0.1:8080).")
    parser.add_argument("--rate", type=float, default=5.0, help=f"Attempts per second (max {MAX_RATE}).")
    parser.add_argument("--count", type=int, default=30, help=f"Total attempts (max {MAX_COUNT}).")
    parser.add_argument("--no-sqli", action="store_true", help="Do not include a SQL-injection attempt.")
    args = parser.parse_args(argv)

    if not 0 < args.rate <= MAX_RATE:
        raise SystemExit(f"--rate must be between 0 and {MAX_RATE}.")
    if not 0 < args.count <= MAX_COUNT:
        raise SystemExit(f"--count must be between 1 and {MAX_COUNT}.")

    base_url = normalise_target(args.target)
    try:
        run(base_url, args.rate, args.count, include_sqli=not args.no_sqli)
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)


if __name__ == "__main__":
    main()
