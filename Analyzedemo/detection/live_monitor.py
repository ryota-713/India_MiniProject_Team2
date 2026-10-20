"""Live attack-monitoring helpers for the Request Signal dashboard.

The demo EC shop (../ec-shop) serves its request log at /api/monitor/events in this
project's own event schema. These helpers let the dashboard poll that feed by IP,
run the existing detection engine over new events, and summarise two attacks for the
presentation:

  * SQL-injection login attempts (rule SQLI-001), including the classic
    ``admin' OR 1=1 --`` tautology typed into the username field.
  * Brute-force logins: many failed authentication requests from one source inside a
    short time window (also surfaced by rule AUTH-REPEAT-001).

Everything here is standard-library only so it can be unit-tested without Streamlit.
Polling is restricted to loopback / private addresses: this watches your own local
demo shop, not the public internet.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, unquote_plus, urlsplit
from urllib.request import urlopen

from detection.models import DetectionResult
from detection.rules import _normalize  # reuse the detector's URL normaliser

# A login-tautology pattern, aligned with SQLI-001's own alternative, used only to
# label the headline "admin' OR 1=1 --" counter on the dashboard.
import re as _re

_TAUTOLOGY = _re.compile(r"(?:['\"]\s*)\b(?:or|and)\s+\d+\s*=\s*\d+", _re.IGNORECASE)
_LOGIN_PATH = _re.compile(r"(?:login|signin|auth|session)", _re.IGNORECASE)
_FAILED_STATUS = {401, 403}

POLL_TIMEOUT_SECONDS = 4.0
MAX_FEED_BYTES = 5 * 1024 * 1024


class MonitorError(RuntimeError):
    """Raised when the monitor feed cannot be fetched or parsed."""


def _host_is_local(host: str) -> bool:
    """Allow loopback and private/link-local hosts only (guards against SSRF)."""
    candidates: list[str] = []
    try:
        candidates.append(host)
        for info in socket.getaddrinfo(host, None):
            candidates.append(info[4][0])
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
    return saw_ip or host in {"localhost"}


def normalise_base_url(target: str, default_port: int = 8080) -> str:
    """Turn user input like ``127.0.0.1``, ``127.0.0.1:8080`` or a full URL into a
    validated ``http://host:port`` base, rejecting non-local hosts."""
    target = target.strip()
    if not target:
        raise MonitorError("監視対象のIP/URLを入力してください。")
    if "://" not in target:
        target = "http://" + target
    parts = urlsplit(target)
    if parts.scheme != "http":
        raise MonitorError("監視はhttpのローカル宛先のみ対応です（httpsや外部は不可）。")
    host = parts.hostname or ""
    port = parts.port or default_port
    if not _host_is_local(host):
        raise MonitorError(
            f"{host} はローカル/プライベートIPではありません。自分のデモ用ショップ"
            "（127.0.0.1 など）だけを監視できます。"
        )
    return f"http://{host}:{port}"


def poll_events(base_url: str, since: int = 0) -> tuple[list[dict], int]:
    """Fetch events from the shop's monitor feed. Returns (new_events, total_seen)."""
    url = f"{base_url}/api/monitor/events?since={int(since)}"
    try:
        with urlopen(url, timeout=POLL_TIMEOUT_SECONDS) as response:  # noqa: S310 (local http)
            raw = response.read(MAX_FEED_BYTES + 1)
    except OSError as exc:
        raise MonitorError(f"監視対象に接続できません: {exc}") from exc
    if len(raw) > MAX_FEED_BYTES:
        raise MonitorError("監視フィードが大きすぎます。")
    try:
        payload = json.loads(raw.decode("utf-8"))
        events = payload["events"]
        total = int(payload["total"])
    except (ValueError, KeyError, TypeError) as exc:
        raise MonitorError("監視フィードの形式が不正です。") from exc
    if not isinstance(events, list):
        raise MonitorError("監視フィードの形式が不正です。")
    return events, total


def feed_to_json(events: list[dict]) -> str:
    """Wrap raw feed events so they can go through import_json_events unchanged."""
    return json.dumps({"events": events}, ensure_ascii=False)


# --------------------------------------------------------------------------- summary
def _attempted_username(path: str) -> str | None:
    query = urlsplit(path).query
    if not query:
        return None
    values = parse_qs(query, keep_blank_values=True).get("username")
    return unquote_plus(values[0]) if values else None


def is_sqli_login(result: DetectionResult) -> bool:
    return any(finding.rule_id == "SQLI-001" for finding in result.rule_findings) and bool(
        _LOGIN_PATH.search(_normalize(result.event.path))
    )


def is_tautology_login(result: DetectionResult) -> bool:
    username = _attempted_username(result.event.path)
    return bool(username and _TAUTOLOGY.search(username))


def is_failed_login(result: DetectionResult) -> bool:
    return result.event.status_code in _FAILED_STATUS and bool(
        _LOGIN_PATH.search(_normalize(result.event.path))
    )


def is_attack(result: DetectionResult) -> bool:
    return bool(result.rule_findings)


@dataclass(frozen=True, slots=True)
class SourceCount:
    source: str
    failed_logins: int
    over_threshold: bool


@dataclass(frozen=True, slots=True)
class MonitorSummary:
    total_events: int
    sqli_login_attempts: int
    tautology_attempts: int
    failed_logins: int
    brute_force_sources: tuple[SourceCount, ...]
    threshold: int
    window_seconds: int

    @property
    def brute_force_active(self) -> bool:
        return any(source.over_threshold for source in self.brute_force_sources)


def summarise(
    results: tuple[DetectionResult, ...],
    *,
    threshold: int = 5,
    window_seconds: int = 300,
    now: datetime | None = None,
) -> MonitorSummary:
    """Count SQLi login attempts and per-source failed logins in the trailing window."""
    reference = now or datetime.now(timezone.utc)
    window_start = reference - timedelta(seconds=window_seconds)
    failed_by_source: dict[str, int] = {}
    failed_total = 0
    for result in results:
        if not is_failed_login(result):
            continue
        failed_total += 1
        if result.event.timestamp >= window_start:
            failed_by_source[result.event.source] = failed_by_source.get(result.event.source, 0) + 1
    sources = tuple(
        SourceCount(source, count, count >= threshold)
        for source, count in sorted(failed_by_source.items(), key=lambda item: (-item[1], item[0]))
    )
    return MonitorSummary(
        total_events=len(results),
        sqli_login_attempts=sum(is_sqli_login(result) for result in results),
        tautology_attempts=sum(is_tautology_login(result) for result in results),
        failed_logins=failed_total,
        brute_force_sources=sources,
        threshold=threshold,
        window_seconds=window_seconds,
    )


@dataclass(frozen=True, slots=True)
class TimeBucket:
    start: datetime
    total: int = 0
    failed_logins: int = 0
    attacks: int = 0


def time_series(
    results: tuple[DetectionResult, ...], bucket_seconds: int = 10
) -> tuple[TimeBucket, ...]:
    """Bucket events over time for the dashboard's line chart.

    Each bucket reports total requests, failed logins, and detected attacks, so the
    presenter can point at the time band where the brute-force burst happened.
    """
    bucket_seconds = max(1, bucket_seconds)
    counters: dict[datetime, dict[str, int]] = {}
    for result in results:
        moment = result.event.timestamp.astimezone(timezone.utc)
        epoch = int(moment.timestamp())
        start = datetime.fromtimestamp(epoch - epoch % bucket_seconds, tz=timezone.utc)
        slot = counters.setdefault(start, {"total": 0, "failed_logins": 0, "attacks": 0})
        slot["total"] += 1
        if is_failed_login(result):
            slot["failed_logins"] += 1
        if is_attack(result):
            slot["attacks"] += 1
    return tuple(
        TimeBucket(start, slot["total"], slot["failed_logins"], slot["attacks"])
        for start, slot in sorted(counters.items())
    )
