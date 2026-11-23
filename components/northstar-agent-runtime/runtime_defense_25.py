"""Runtime defense 25: Anomaly detection (mock), Simulated.

Z-score based anomaly detection over numeric signals (latency, call
rate, error rate).  Baseline is seeded by the host; samples beyond
``z_threshold`` standard deviations are flagged.

What this IS: streaming z-score detector with seeded baseline.

What this IS NOT:
* Not ML -- pure statistics; host provides meaningful signals.
"""

from __future__ import annotations

import ast
import math
from dataclasses import dataclass, field
from typing import List, Tuple

#: Module version.
RUNTIME_DEFENSE_25_VERSION = "runtime-defense-25.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-25.v1"


class AnomalyError(Exception):
    """Fail-closed: bad config raises."""


@dataclass(frozen=True)
class AnomalyConfig:
    """Detector config."""

    z_threshold: float = 3.0
    min_samples: int = 10

    def __post_init__(self):
        if self.z_threshold <= 0:
            raise AnomalyError("z_threshold must be positive")
        if self.min_samples < 2:
            raise AnomalyError("min_samples must be >= 2")


@dataclass
class AnomalyDetector:
    """Streaming z-score detector."""

    config: AnomalyConfig = field(default_factory=AnomalyConfig)
    samples: List[float] = field(default_factory=list)

    def seed(self, values: List[float]) -> None:
        """Seed the baseline."""
        if len(values) < self.config.min_samples:
            raise AnomalyError(
                f"need >= {self.config.min_samples} seed samples"
            )
        self.samples = list(values)

    def _mean_std(self) -> Tuple[float, float]:
        n = len(self.samples)
        mean = sum(self.samples) / n
        var = sum((x - mean) ** 2 for x in self.samples) / n
        return mean, math.sqrt(var)

    def check(self, value: float) -> Tuple[bool, float]:
        """Check a sample.  Returns (is_anomaly, z_score).

        Anomalous samples are NOT added to the baseline.
        """
        if len(self.samples) < self.config.min_samples:
            # Not enough baseline: adopt, don't flag.
            self.samples.append(value)
            return False, 0.0
        mean, std = self._mean_std()
        if std == 0:
            return (value != mean), 0.0
        z = abs(value - mean) / std
        if z > self.config.z_threshold:
            return True, z
        self.samples.append(value)
        return False, z


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "math", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    det = AnomalyDetector()
    # Baseline with realistic variance (mean 100, std ~0.28).
    det.seed([100.0 + ((i * 7) % 5 - 2) * 0.2 for i in range(20)])
    anomalous, z = det.check(100.3)
    assert anomalous is False
    anomalous, z = det.check(500.0)
    assert anomalous is True
    assert z > 3.0
    # Anomalous sample not adopted: next normal sample still ok.
    anomalous, _ = det.check(100.1)
    assert anomalous is False
    try:
        AnomalyDetector().seed([1.0])
        raise AssertionError("should raise")
    except AnomalyError:
        pass
    assert stdlib_only()
    print("runtime-defense-25 OK: anomaly detection, z-score, fail-closed")


if __name__ == "__main__":
    main()
