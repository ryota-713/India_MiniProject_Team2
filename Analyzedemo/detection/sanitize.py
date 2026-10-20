from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from detection.models import Event

SENSITIVE_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "session",
    "session_id",
    "token",
}
_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_KEY_VALUE_PATTERN = re.compile(
    r"(?i)\b(password|passwd|token|api[_-]?key|secret|session[_-]?id)\s*[:=]\s*[^&\s,;]+"
)


def _sanitize_value(value: str) -> str:
    value = _BEARER_PATTERN.sub("Bearer [REDACTED]", value)
    return _KEY_VALUE_PATTERN.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)


def sanitize_path(path: str) -> str:
    parts = urlsplit(path)
    sanitized_query = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True, max_num_fields=128):
        replacement = "[REDACTED]" if key.casefold() in SENSITIVE_KEYS else _sanitize_value(value)
        sanitized_query.append((key[:128], replacement[:512]))
    clean_path = _sanitize_value(parts.path[:2048])
    return urlunsplit(("", "", clean_path, urlencode(sanitized_query, doseq=True), ""))[:2048]


def sanitize_event(event: Event) -> Event:
    user_agent = _sanitize_value(event.user_agent)[:512] if event.user_agent else None
    if user_agent:
        user_agent = re.sub(r"[\r\n\t]+", " ", user_agent)
    return Event(
        event_id=_sanitize_value(event.event_id)[:64],
        timestamp=event.timestamp,
        source=_sanitize_value(event.source)[:100],
        method=event.method,
        path=sanitize_path(event.path),
        status_code=event.status_code,
        user_agent=user_agent,
    )
