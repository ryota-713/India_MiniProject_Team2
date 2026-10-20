from __future__ import annotations

import json
from pathlib import Path

from detection.models import Event
from detection.sanitize import sanitize_event
from detection.validation import event_from_mapping

DATA_DIRECTORY = Path(__file__).resolve().parent.parent / "data"


def load_synthetic_events() -> tuple[Event, ...]:
    payload = json.loads((DATA_DIRECTORY / "sample_events.json").read_text(encoding="utf-8"))
    return tuple(sanitize_event(event_from_mapping(row)) for row in payload["events"])


def load_labeled_events() -> tuple[tuple[Event, bool], ...]:
    payload = json.loads((DATA_DIRECTORY / "labeled_evaluation.json").read_text(encoding="utf-8"))
    return tuple(
        (sanitize_event(event_from_mapping(row["event"])), bool(row["label"]))
        for row in payload["events"]
    )
