from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from urllib.parse import urlsplit

from detection.models import AIFinding, Event

FEATURE_NAMES = (
    "path length",
    "query length",
    "encoded character ratio",
    "operator ratio",
    "character entropy",
)
BENIGN_BASELINE = (
    "/",
    "/api/Products",
    "/api/Products/1",
    "/rest/user/whoami",
    "/rest/products/search?q=apple",
    "/api/Feedbacks",
    "/api/Challenges",
    "/assets/public/logo.png",
    "/profile",
    "/login",
    "/rest/basket/1",
    "/api/Users/1",
    "/rest/languages",
    "/api/SecurityQuestions",
    "/rest/track-order/ABC123",
    "/api/Quantitys/1",
)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = [value.count(char) / len(value) for char in set(value)]
    return -sum(frequency * math.log2(frequency) for frequency in frequencies)


def request_features(path: str) -> tuple[float, ...]:
    parsed = urlsplit(path)
    value = parsed.path + ("?" + parsed.query if parsed.query else "")
    length = max(1, len(value))
    encoded_count = sum(
        value[index] == "%" and index + 2 < len(value) for index in range(len(value))
    )
    operator_count = sum(char in "<>='\";`(){}" for char in value)
    return (
        float(len(value)),
        float(len(parsed.query)),
        encoded_count / length,
        operator_count / length,
        _entropy(value),
    )


@dataclass(frozen=True, slots=True)
class _FeatureStats:
    median: float
    scale: float


class StatisticalAnomalyDetector:
    model_name = "robust-mad-request-shape-v1"
    score_meaning = "Normalized maximum robust deviation; not a probability."
    limitation = (
        "Learns request-shape baselines, not attack intent. Benign unusual routes can be flagged."
    )

    def __init__(
        self, baseline_paths: tuple[str, ...] = BENIGN_BASELINE, threshold: float = 4.5
    ) -> None:
        if len(baseline_paths) < 5:
            raise ValueError("At least five benign baseline paths are required.")
        if threshold <= 0:
            raise ValueError("threshold must be positive.")
        rows = [request_features(path) for path in baseline_paths]
        self._stats: tuple[_FeatureStats, ...] = tuple(
            _FeatureStats(
                median=statistics.median(column),
                scale=max(
                    1.4826
                    * statistics.median(abs(value - statistics.median(column)) for value in column),
                    3.0,
                ),
            )
            for column in zip(*rows, strict=True)
        )
        self.threshold = threshold

    def analyze(self, event: Event) -> AIFinding:
        features = request_features(event.path)
        deviations = [
            abs(value - stats.median) / stats.scale
            for value, stats in zip(features, self._stats, strict=True)
        ]
        maximum_index = max(range(len(deviations)), key=deviations.__getitem__)
        maximum = deviations[maximum_index]
        suspicious = maximum >= self.threshold
        score = min(maximum / 10.0, 1.0)
        return AIFinding(
            status="analyzed",
            suspicious=suspicious,
            score=round(score, 4),
            category="Anomalous request shape" if suspicious else None,
            evidence=(
                f"{FEATURE_NAMES[maximum_index]} deviates {maximum:.2f} robust scale units "
                "from the benign baseline."
            ),
            limitation=self.limitation,
        )
