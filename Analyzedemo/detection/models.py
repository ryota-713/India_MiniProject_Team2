from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

Severity = Literal["Info", "Low", "Medium", "High"]
AIStatus = Literal["analyzed", "disabled", "unavailable", "error"]
AIExplanationStatus = Literal[
    "generated",
    "error",
    "invalid_response",
    "auth_error",
    "rate_limited",
    "model_unavailable",
    "billing_error",
    "unavailable",
]


@dataclass(frozen=True, slots=True)
class Event:
    event_id: str
    timestamp: datetime
    source: str
    path: str
    method: str | None = None
    status_code: int | None = None
    user_agent: str | None = None


@dataclass(frozen=True, slots=True)
class RuleFinding:
    rule_id: str
    name: str
    category: str
    severity: Severity
    evidence: str


@dataclass(frozen=True, slots=True)
class AIFinding:
    status: AIStatus
    suspicious: bool | None = None
    score: float | None = None
    category: str | None = None
    evidence: str | None = None
    limitation: str | None = None


@dataclass(frozen=True, slots=True)
class AIExplanation:
    status: AIExplanationStatus
    text: str | None = None
    model: str | None = None
    message: str | None = None
    cached: bool = False


@dataclass(frozen=True, slots=True)
class DetectionResult:
    event: Event
    rule_findings: tuple[RuleFinding, ...]
    ai_finding: AIFinding
    disagreement: bool
    ai_explanation: AIExplanation | None = None

    @property
    def is_suspicious(self) -> bool:
        return bool(self.rule_findings) or self.ai_finding.suspicious is True

    @property
    def detection_sources(self) -> tuple[str, ...]:
        sources: list[str] = []
        if self.rule_findings:
            sources.append("Rule")
        if self.ai_finding.suspicious is True:
            sources.append("AI")
        return tuple(sources)

    @property
    def display_severity(self) -> Severity:
        severities = {"Info": 0, "Low": 1, "Medium": 2, "High": 3}
        if self.rule_findings:
            return max((finding.severity for finding in self.rule_findings), key=severities.get)
        if self.ai_finding.suspicious:
            return "Medium" if (self.ai_finding.score or 0) >= 0.7 else "Low"
        return "Info"
