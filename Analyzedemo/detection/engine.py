from __future__ import annotations

from collections.abc import Sequence

from detection.models import AIFinding, DetectionResult, Event
from detection.rules import RuleDetector
from detection.sanitize import sanitize_event
from detection.statistical import StatisticalAnomalyDetector


class HybridDetector:
    def __init__(
        self,
        rule_detector: RuleDetector | None = None,
        ai_detector: StatisticalAnomalyDetector | None = None,
    ) -> None:
        self.rule_detector = rule_detector or RuleDetector()
        self.ai_detector = ai_detector or StatisticalAnomalyDetector()

    def analyze(
        self, events: Sequence[Event], ai_enabled: bool = True
    ) -> tuple[DetectionResult, ...]:
        sanitized_events = tuple(sanitize_event(event) for event in events)
        ordered = sorted(sanitized_events, key=lambda event: event.timestamp)
        prior_events: list[Event] = []
        results: list[DetectionResult] = []
        for event in ordered:
            rule_findings = self.rule_detector.detect(event, tuple(prior_events))
            if not ai_enabled:
                ai_finding = AIFinding(status="disabled", limitation="AI detection was disabled.")
            else:
                try:
                    ai_finding = self.ai_detector.analyze(event)
                except (ConnectionError, OSError, RuntimeError, TimeoutError, ValueError):
                    ai_finding = AIFinding(
                        status="error",
                        limitation="AI analysis failed; rule findings remain available.",
                    )
            rule_flag = bool(rule_findings)
            ai_flag = ai_finding.suspicious if ai_finding.status == "analyzed" else None
            results.append(
                DetectionResult(
                    event=event,
                    rule_findings=rule_findings,
                    ai_finding=ai_finding,
                    disagreement=ai_flag is not None and rule_flag != ai_flag,
                )
            )
            prior_events.append(event)
        return tuple(results)
