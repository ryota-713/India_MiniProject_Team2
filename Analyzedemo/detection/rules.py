from __future__ import annotations

import re
from datetime import timedelta
from urllib.parse import unquote, unquote_plus, urlsplit

from detection.models import Event, RuleFinding

_RULES = (
    (
        re.compile(
            r"\bunion(?:\s+all)?\s+select\b|(?:['\"]\s*)\b(?:or|and)\s+\d+\s*=\s*\d+", re.IGNORECASE
        ),
        "SQLI-001",
        "SQL injection indicator",
        "SQL injection",
        "High",
        "Request contains a SQL query-manipulation pattern.",
    ),
    (
        re.compile(r"<\s*script\b|javascript\s*:|\bon\w+\s*=", re.IGNORECASE),
        "XSS-001",
        "Cross-site scripting indicator",
        "Cross-site scripting",
        "High",
        "Request contains markup or script-handler syntax associated with XSS.",
    ),
    (
        re.compile(r"(?:\.\.[/\\]){1,}|%2e%2e(?:[/\\]|%2f|%5c)", re.IGNORECASE),
        "PATH-001",
        "Path traversal indicator",
        "Path traversal",
        "High",
        "Request contains parent-directory traversal syntax.",
    ),
)
_AUTH_PATH_PATTERN = re.compile(r"(?:login|signin|auth|session)", re.IGNORECASE)


def _normalize(value: str) -> str:
    normalized = value.replace("\\", "/")
    for _ in range(3):
        parts = urlsplit(normalized)
        decoded_path = unquote(parts.path)
        decoded_query = unquote_plus(parts.query)
        decoded = decoded_path + (f"?{decoded_query}" if parts.query else "")
        if decoded == normalized:
            break
        normalized = decoded
    return normalized.casefold()


class RuleDetector:
    def detect(
        self, event: Event, previous_events: tuple[Event, ...] = ()
    ) -> tuple[RuleFinding, ...]:
        normalized = _normalize(event.path)
        findings = [
            RuleFinding(rule_id, name, category, severity, evidence)
            for pattern, rule_id, name, category, severity, evidence in _RULES
            if pattern.search(normalized)
        ]

        if event.status_code in {401, 403} and _AUTH_PATH_PATTERN.search(normalized):
            window_start = event.timestamp - timedelta(minutes=5)
            attempts = (
                sum(
                    prior.source == event.source
                    and prior.status_code in {401, 403}
                    and _AUTH_PATH_PATTERN.search(_normalize(prior.path)) is not None
                    and window_start <= prior.timestamp <= event.timestamp
                    for prior in previous_events
                )
                + 1
            )
            if attempts >= 5:
                findings.append(
                    RuleFinding(
                        "AUTH-REPEAT-001",
                        "Repeated authentication failures",
                        "Authentication anomaly",
                        "Medium",
                        f"At least {attempts} failed authentication requests from this source "
                        "occurred within five minutes.",
                    )
                )
        return tuple(findings)
