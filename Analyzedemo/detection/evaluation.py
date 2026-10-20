from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from detection.models import DetectionResult


@dataclass(frozen=True, slots=True)
class EvaluationMetrics:
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float


def evaluate_labeled_results(
    rows: Iterable[tuple[DetectionResult, bool]],
    channel: Literal["rules", "ai", "hybrid"] = "hybrid",
) -> EvaluationMetrics:
    if channel not in {"rules", "ai", "hybrid"}:
        raise ValueError("channel must be 'rules', 'ai', or 'hybrid'.")
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    total = 0
    for result, label in rows:
        total += 1
        if channel == "rules":
            predicted = bool(result.rule_findings)
        elif channel == "ai":
            predicted = (
                result.ai_finding.status == "analyzed" and result.ai_finding.suspicious is True
            )
        else:
            predicted = result.is_suspicious
        if predicted and label:
            counts["tp"] += 1
        elif predicted:
            counts["fp"] += 1
        elif label:
            counts["fn"] += 1
        else:
            counts["tn"] += 1
    if total == 0:
        raise ValueError("At least one labeled result is required.")
    precision = counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else 0.0
    recall = counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else 0.0
    f1_score = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = counts["fp"] / (counts["fp"] + counts["tn"]) if counts["fp"] + counts["tn"] else 0.0
    return EvaluationMetrics(
        true_positive=counts["tp"],
        false_positive=counts["fp"],
        true_negative=counts["tn"],
        false_negative=counts["fn"],
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        false_positive_rate=fpr,
    )
