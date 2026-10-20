from __future__ import annotations

import csv
import io
import json
import uuid
from collections.abc import Iterable, Mapping
from typing import Any

from detection.models import DetectionResult, Event
from detection.sanitize import sanitize_event
from detection.serialization import result_to_record
from detection.validation import EventValidationError, event_from_mapping

MAX_IMPORT_BYTES = 5 * 1024 * 1024
MAX_IMPORT_EVENTS = 10_000
_EVENT_FIELDS = {"event_id", "timestamp", "source", "method", "path", "status_code", "user_agent"}
_CSV_FIELDS = ("event_id", "timestamp", "source", "method", "path", "status_code", "user_agent")


class ImportDataError(ValueError):
    pass


def _decode_content(content: str | bytes) -> str:
    if isinstance(content, bytes):
        if len(content) > MAX_IMPORT_BYTES:
            raise ImportDataError("Import exceeds the 5 MiB size limit.")
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ImportDataError("Import must be UTF-8 encoded.") from exc
    elif isinstance(content, str):
        text = content
        if len(text.encode("utf-8")) > MAX_IMPORT_BYTES:
            raise ImportDataError("Import exceeds the 5 MiB size limit.")
    else:
        raise ImportDataError("Import must be text or UTF-8 bytes.")
    return text


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ImportDataError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _make_events(rows: list[Mapping[str, Any]]) -> tuple[Event, ...]:
    if len(rows) > MAX_IMPORT_EVENTS:
        raise ImportDataError(f"Import exceeds the {MAX_IMPORT_EVENTS} event limit.")
    events: list[Event] = []
    seen_ids: set[str] = set()
    for row_number, row in enumerate(rows, start=1):
        if not isinstance(row, Mapping):
            raise ImportDataError(f"Event {row_number} must be an object.")
        extra = set(row) - _EVENT_FIELDS
        if extra:
            raise ImportDataError(f"Event {row_number} contains unsupported fields.")
        data = dict(row)
        if not data.get("event_id"):
            stable_id = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            data["event_id"] = str(uuid.uuid5(uuid.NAMESPACE_URL, stable_id))
        try:
            event = sanitize_event(event_from_mapping(data))
        except (EventValidationError, ValueError) as exc:
            raise ImportDataError(f"Event {row_number} is invalid: {exc}") from exc
        if event.event_id in seen_ids:
            raise ImportDataError(f"Event {row_number} duplicates an event_id.")
        seen_ids.add(event.event_id)
        events.append(event)
    return tuple(events)


def import_json_events(content: str | bytes) -> tuple[Event, ...]:
    text = _decode_content(content)
    try:
        payload = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except ImportDataError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ImportDataError("Import is not valid JSON.") from exc
    rows = payload.get("events") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise ImportDataError("JSON must contain an event list or an object with an 'events' list.")
    return _make_events(rows)


def import_csv_events(content: str | bytes) -> tuple[Event, ...]:
    text = _decode_content(content)
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames)):
        raise ImportDataError("CSV must have a unique header row.")
    if (
        set(reader.fieldnames) - _EVENT_FIELDS
        or "timestamp" not in reader.fieldnames
        or "path" not in reader.fieldnames
    ):
        raise ImportDataError(
            "CSV headers must use documented event fields and include timestamp and path."
        )
    rows: list[dict[str, Any]] = []
    for row in reader:
        if None in row:
            raise ImportDataError("CSV row has more values than its header.")
        data = {key: value for key, value in row.items() if value not in (None, "")}
        if "status_code" in data:
            try:
                data["status_code"] = int(data["status_code"])
            except ValueError as exc:
                raise ImportDataError("CSV status_code must be an integer.") from exc
        rows.append(data)
        if len(rows) > MAX_IMPORT_EVENTS:
            raise ImportDataError(f"Import exceeds the {MAX_IMPORT_EVENTS} event limit.")
    return _make_events(rows)


def _spreadsheet_safe(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    if value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def export_json(results: Iterable[DetectionResult]) -> str:
    return json.dumps(
        {"events": [result_to_record(result) for result in results]},
        ensure_ascii=False,
        indent=2,
    )


def export_csv(results: Iterable[DetectionResult]) -> str:
    fields = (
        "event_id",
        "timestamp",
        "source",
        "method",
        "path",
        "status_code",
        "user_agent",
        "rule_ids",
        "rule_categories",
        "rule_severities",
        "rule_evidence",
        "ai_status",
        "ai_suspicious",
        "ai_score",
        "ai_category",
        "ai_evidence",
        "ai_explanation_status",
        "ai_explanation_model",
        "ai_explanation",
        "disagreement",
        "display_severity",
        "detection_sources",
    )
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for result in results:
        record = result_to_record(result)
        event = record["event"]
        ai = record["ai_finding"]
        explanation = record["ai_explanation"] or {}
        rules = record["rule_findings"]
        row = {
            **event,
            "rule_ids": ";".join(finding["rule_id"] for finding in rules),
            "rule_categories": ";".join(finding["category"] for finding in rules),
            "rule_severities": ";".join(finding["severity"] for finding in rules),
            "rule_evidence": "; ".join(finding["evidence"] for finding in rules),
            "ai_status": ai["status"],
            "ai_suspicious": ai["suspicious"],
            "ai_score": ai["score"],
            "ai_category": ai["category"],
            "ai_evidence": ai["evidence"],
            "ai_explanation_status": explanation.get("status"),
            "ai_explanation_model": explanation.get("model"),
            "ai_explanation": explanation.get("text"),
            "disagreement": record["disagreement"],
            "display_severity": record["display_severity"],
            "detection_sources": ";".join(record["detection_sources"]),
        }
        writer.writerow({key: _spreadsheet_safe(value) for key, value in row.items()})
    return output.getvalue()
