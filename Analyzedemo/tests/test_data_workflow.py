import json
from datetime import UTC, datetime

import pytest

from detection.engine import HybridDetector
from detection.evaluation import evaluate_labeled_results
from detection.models import Event
from detection.storage import EventStore
from detection.transfer import (
    ImportDataError,
    export_csv,
    export_json,
    import_csv_events,
    import_json_events,
)


def event_row(event_id: str = "event-1", path: str = "/api/products") -> dict[str, object]:
    return {
        "event_id": event_id,
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "synthetic",
        "method": "GET",
        "path": path,
        "status_code": 200,
    }


def test_json_import_sanitizes_and_rejects_unknown_fields() -> None:
    events = import_json_events(
        json.dumps(
            [
                {
                    **event_row(path="/login?password=secret"),
                }
            ]
        )
    )
    assert len(events) == 1
    assert "secret" not in events[0].path
    with pytest.raises(ImportDataError, match="unsupported fields"):
        import_json_events(json.dumps([{**event_row(), "body": "not accepted"}]))


def test_import_rejects_duplicate_json_keys_and_ids() -> None:
    with pytest.raises(ImportDataError, match="Duplicate JSON key"):
        import_json_events('[{"path":"/","path":"/other"}]')
    with pytest.raises(ImportDataError, match="duplicates"):
        import_json_events(json.dumps([event_row(), event_row()]))


def test_csv_import_and_export_round_trip_sanitized_fields() -> None:
    csv_text = (
        "event_id,timestamp,source,method,path,status_code,user_agent\n"
        'csv-1,2026-01-01T00:00:00Z,synthetic,GET,"/search?q=apple",200,Browser\n'
    )
    imported = import_csv_events(csv_text)
    results = HybridDetector().analyze(imported)
    exported = export_csv(results)
    assert "csv-1" in exported
    assert "ai_status" in exported
    assert (
        import_csv_events(
            "event_id,timestamp,source,method,path,status_code,user_agent\n"
            + "csv-1,2026-01-01T00:00:00Z,synthetic,GET,/search?q=apple,200,Browser\n"
        )[0].path
        == "/search?q=apple"
    )


def test_csv_export_prevents_spreadsheet_formula_execution() -> None:
    event = Event(
        "formula-1", datetime(2026, 1, 1, tzinfo=UTC), "synthetic", "/", user_agent="=1+1"
    )
    result = HybridDetector().analyze((event,))[0]
    assert "'=1+1" in export_csv((result,))


def test_json_export_keeps_rule_and_ai_channels_separate() -> None:
    event = Event(
        "hybrid-1",
        datetime(2026, 1, 1, tzinfo=UTC),
        "synthetic",
        "/search?q=' OR 1=1",
    )
    exported = json.loads(export_json(HybridDetector().analyze((event,))))["events"][0]
    assert exported["rule_findings"]
    assert exported["ai_finding"]["status"] == "analyzed"
    assert "Rule" in exported["detection_sources"]


def test_sqlite_store_round_trips_and_deduplicates_results(tmp_path) -> None:
    event = Event("stored-1", datetime(2026, 1, 1, tzinfo=UTC), "synthetic", "/")
    result = HybridDetector().analyze((event,))[0]
    store = EventStore(tmp_path / "events.sqlite3")
    assert store.save_results((result,)) == 1
    assert store.save_results((result,)) == 0
    assert store.count() == 1
    assert store.list_results()[0] == result


def test_metrics_report_confusion_matrix_and_handle_zero_divisors() -> None:
    events = (
        Event("tp", datetime(2026, 1, 1, tzinfo=UTC), "test", "/search?q=' OR 1=1"),
        Event("tn", datetime(2026, 1, 1, tzinfo=UTC), "test", "/"),
    )
    results = HybridDetector().analyze(events, ai_enabled=False)
    metrics = evaluate_labeled_results(((results[0], True), (results[1], False)))
    assert (
        metrics.true_positive,
        metrics.false_positive,
        metrics.true_negative,
        metrics.false_negative,
    ) == (1, 0, 1, 0)
    assert metrics.precision == metrics.recall == metrics.f1_score == 1.0
    assert metrics.false_positive_rate == 0.0
    empty_predictions = evaluate_labeled_results(((results[1], True),))
    assert empty_predictions.precision == empty_predictions.f1_score == 0.0


def test_metrics_can_measure_each_detection_channel_separately() -> None:
    class QuietDetector:
        def analyze(self, event: Event):
            from detection.models import AIFinding

            return AIFinding(status="analyzed", suspicious=False, score=0.1)

    suspicious = Event(
        "channel-1",
        datetime(2026, 1, 1, tzinfo=UTC),
        "test",
        "/search?q=' OR 1=1",
    )
    result = HybridDetector(ai_detector=QuietDetector()).analyze((suspicious,))[0]  # type: ignore[arg-type]
    rules = evaluate_labeled_results(((result, True),), channel="rules")
    ai = evaluate_labeled_results(((result, False),), channel="ai")
    assert rules.true_positive == 1
    assert ai.true_negative == 1
    with pytest.raises(ValueError, match="channel"):
        evaluate_labeled_results(((result, True),), channel="unknown")  # type: ignore[arg-type]
