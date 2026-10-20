from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any

from detection.models import AIExplanation, AIFinding, DetectionResult, Event, RuleFinding
from detection.sanitize import sanitize_event


def result_to_record(result: DetectionResult) -> dict[str, Any]:
    event = sanitize_event(result.event)
    return {
        "event": {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "source": event.source,
            "method": event.method,
            "path": event.path,
            "status_code": event.status_code,
            "user_agent": event.user_agent,
        },
        "rule_findings": [asdict(finding) for finding in result.rule_findings],
        "ai_finding": asdict(result.ai_finding),
        "ai_explanation": asdict(result.ai_explanation) if result.ai_explanation else None,
        "disagreement": result.disagreement,
        "is_suspicious": result.is_suspicious,
        "display_severity": result.display_severity,
        "detection_sources": list(result.detection_sources),
    }


def result_from_record(record: dict[str, Any]) -> DetectionResult:
    event_data = record["event"]
    event = Event(
        event_id=event_data["event_id"],
        timestamp=datetime.fromisoformat(event_data["timestamp"]),
        source=event_data["source"],
        method=event_data.get("method"),
        path=event_data["path"],
        status_code=event_data.get("status_code"),
        user_agent=event_data.get("user_agent"),
    )
    rules = tuple(RuleFinding(**finding) for finding in record["rule_findings"])
    explanation = record.get("ai_explanation")
    return DetectionResult(
        event=event,
        rule_findings=rules,
        ai_finding=AIFinding(**record["ai_finding"]),
        disagreement=bool(record["disagreement"]),
        ai_explanation=AIExplanation(**explanation) if explanation else None,
    )
