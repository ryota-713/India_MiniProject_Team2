from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from detection.models import Event

MAX_EVENT_ID = 64
MAX_SOURCE_LENGTH = 100
MAX_PATH_LENGTH = 2048
MAX_USER_AGENT_LENGTH = 512
_METHOD_PATTERN = re.compile(r"^[A-Z]{1,16}$")


class EventValidationError(ValueError):
    pass


def event_from_mapping(value: Mapping[str, Any]) -> Event:
    if not isinstance(value, Mapping):
        raise EventValidationError("Event must be a JSON object.")

    allowed = {"event_id", "timestamp", "source", "method", "path", "status_code", "user_agent"}
    extra = set(value) - allowed
    if extra:
        raise EventValidationError(
            f"Unsupported event fields: {', '.join(sorted(map(str, extra)))}"
        )

    event_id = value.get("event_id") if "event_id" in value else str(uuid.uuid4())
    if not isinstance(event_id, str) or not event_id.strip() or len(event_id) > MAX_EVENT_ID:
        raise EventValidationError("event_id must be a non-empty string of at most 64 characters.")

    raw_timestamp = value.get("timestamp")
    if not isinstance(raw_timestamp, str):
        raise EventValidationError("timestamp must be an ISO-8601 string with a timezone.")
    try:
        timestamp = datetime.fromisoformat(raw_timestamp)
    except ValueError as exc:
        raise EventValidationError("timestamp must be a valid ISO-8601 value.") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise EventValidationError("timestamp must include a timezone.")

    source = value.get("source")
    if (
        not isinstance(source, str)
        or not source.strip()
        or len(source) > MAX_SOURCE_LENGTH
        or any(ord(char) < 32 or ord(char) == 127 for char in source)
    ):
        raise EventValidationError("source must be a non-empty string of at most 100 characters.")

    path = value.get("path")
    if not isinstance(path, str) or not path.startswith("/") or len(path) > MAX_PATH_LENGTH:
        raise EventValidationError("path must start with '/' and be at most 2048 characters.")
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise EventValidationError("path must not contain control characters.")

    method = value.get("method")
    if method is not None and (
        not isinstance(method, str) or not _METHOD_PATTERN.fullmatch(method)
    ):
        raise EventValidationError("method must contain 1-16 uppercase ASCII letters.")

    status_code = value.get("status_code")
    if status_code is not None and (type(status_code) is not int or not 100 <= status_code <= 599):
        raise EventValidationError("status_code must be an integer between 100 and 599.")

    user_agent = value.get("user_agent")
    if user_agent is not None and (
        not isinstance(user_agent, str)
        or len(user_agent) > MAX_USER_AGENT_LENGTH
        or any(ord(char) < 32 and char != "\t" for char in user_agent)
    ):
        raise EventValidationError(
            "user_agent must be at most 512 characters without control characters."
        )

    return Event(
        event_id=event_id.strip(),
        timestamp=timestamp,
        source=source.strip(),
        method=method,
        path=path,
        status_code=status_code,
        user_agent=user_agent,
    )
