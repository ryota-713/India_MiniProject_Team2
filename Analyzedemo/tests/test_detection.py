from datetime import UTC, datetime, timedelta

import pytest

from detection.engine import HybridDetector
from detection.models import AIFinding, Event
from detection.sanitize import sanitize_event
from detection.statistical import StatisticalAnomalyDetector
from detection.validation import EventValidationError, event_from_mapping

BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)


def make_event(path: str, **overrides: object) -> Event:
    values: dict[str, object] = {
        "event_id": "event-1",
        "timestamp": BASE_TIME,
        "source": "synthetic",
        "path": path,
        "method": "GET",
        "status_code": 200,
    }
    values.update(overrides)
    return Event(**values)  # type: ignore[arg-type]


def test_event_validation_requires_timezone_and_rejects_unmodeled_body() -> None:
    event_data = {
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "synthetic",
        "path": "/api/products",
    }
    assert event_from_mapping(event_data).event_id
    with pytest.raises(EventValidationError, match="timezone"):
        event_from_mapping({**event_data, "timestamp": "2026-01-01T00:00:00"})
    with pytest.raises(EventValidationError, match="Unsupported event fields"):
        event_from_mapping({**event_data, "body": "must not be stored"})


def test_event_validation_rejects_bad_path_and_status() -> None:
    base = {"timestamp": "2026-01-01T00:00:00Z", "source": "synthetic"}
    with pytest.raises(EventValidationError, match="path"):
        event_from_mapping({**base, "path": "https://example.invalid"})
    with pytest.raises(EventValidationError, match="status_code"):
        event_from_mapping({**base, "path": "/", "status_code": True})
    with pytest.raises(EventValidationError, match="event_id"):
        event_from_mapping({**base, "path": "/", "event_id": 42})
    with pytest.raises(EventValidationError, match="source"):
        event_from_mapping({**base, "path": "/", "source": "bad\nsource"})


def test_sanitizer_redacts_sensitive_query_and_user_agent_values() -> None:
    event = make_event(
        "/login?password=hunter2&next=%2Fhome&api_key=secret-value",
        user_agent="Browser\r\nBearer abc.def.ghi",
    )
    sanitized = sanitize_event(event)
    assert "hunter2" not in sanitized.path
    assert "secret-value" not in sanitized.path
    assert "next=%2Fhome" in sanitized.path
    assert "\r" not in sanitized.user_agent
    assert "abc.def.ghi" not in sanitized.user_agent


@pytest.mark.parametrize(
    ("path", "expected_rule"),
    [
        ("/search?q=' OR 1=1", "SQLI-001"),
        ("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "XSS-001"),
        ("/download/%252e%252e%252fetc/passwd", "PATH-001"),
    ],
)
def test_rules_detect_suspicious_and_encoded_patterns(path: str, expected_rule: str) -> None:
    findings = HybridDetector().analyze((make_event(path),), ai_enabled=False)[0].rule_findings
    assert expected_rule in {finding.rule_id for finding in findings}


def test_normal_request_has_no_rule_finding() -> None:
    result = HybridDetector().analyze(
        (make_event("/rest/products/search?q=apple"),), ai_enabled=False
    )[0]
    assert result.rule_findings == ()
    assert result.ai_finding.status == "disabled"
    assert not result.is_suspicious


def test_repeated_authentication_failures_are_detected_within_window() -> None:
    events = tuple(
        make_event(
            "/rest/user/login",
            event_id=f"event-{index}",
            timestamp=BASE_TIME + timedelta(seconds=index * 20),
            status_code=401,
        )
        for index in range(5)
    )
    results = HybridDetector().analyze(events, ai_enabled=False)
    assert "AUTH-REPEAT-001" in {finding.rule_id for finding in results[-1].rule_findings}


def test_local_statistical_detector_flags_shape_outlier_without_claiming_probability() -> None:
    detector = StatisticalAnomalyDetector()
    ordinary = detector.analyze(make_event("/rest/products/search?q=apple"))
    unusual = detector.analyze(make_event("/" + "A9%3Cscript%3E" * 20))
    assert ordinary.suspicious is False
    assert unusual.suspicious is True
    assert "not a probability" in detector.score_meaning


def test_hybrid_results_preserve_disagreement_and_rule_findings() -> None:
    class QuietDetector:
        def analyze(self, event: Event) -> AIFinding:
            return AIFinding(status="analyzed", suspicious=False, score=0.1)

    result = HybridDetector(ai_detector=QuietDetector()).analyze(
        (make_event("/search?q=' OR 1=1"),)
    )[0]
    assert result.rule_findings
    assert result.disagreement
    assert "Rule" in result.detection_sources
    assert result.ai_finding.status == "analyzed"


def test_ai_failure_or_disable_never_erases_rule_detection() -> None:
    class BrokenDetector:
        def analyze(self, event: Event) -> AIFinding:
            raise RuntimeError("private failure detail")

    suspicious = make_event("/search?q=' OR 1=1")
    failed = HybridDetector(ai_detector=BrokenDetector()).analyze((suspicious,))[0]  # type: ignore[arg-type]
    disabled = HybridDetector().analyze((suspicious,), ai_enabled=False)[0]
    assert failed.ai_finding.status == "error"
    assert failed.rule_findings
    assert "private failure" not in str(failed.ai_finding)
    assert disabled.ai_finding.status == "disabled"
    assert disabled.rule_findings
