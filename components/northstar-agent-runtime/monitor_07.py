"""Anomaly alerts: rolling z-score detector (mock), Simulated.

Keeps a rolling window of metric observations; computes mean/std and
flags an observation anomalous when |z| >= threshold. Supports
per-metric state so many metrics can be tracked independently.

What this IS: lightweight univariate anomaly detection for gate
latency, deny rates, tool-call volume.

What this IS NOT:
* Not multivariate / ML -- single-metric z-score only.
"""

from __future__ import annotations

import ast
import math
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional

#: Module version.
MONITOR_07_VERSION = "monitor-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-07.v1"


class AnomalyError(Exception):
    """Fail-closed."""


@dataclass
class Detector:
    window: int = 50
    z_threshold: float = 3.0
    _obs: Deque[float] = field(default_factory=lambda: deque(maxlen=50))

    def __post_init__(self) -> None:
        if not isinstance(self.window, int) or self.window < 2:
            raise AnomalyError("window must be int >= 2")
        if self.z_threshold <= 0:
            raise AnomalyError("z_threshold must be positive")
        self._obs = deque(maxlen=self.window)

    def observe(self, value: float) -> None:
        if not isinstance(value, (int, float)) or math.isnan(value):
            raise AnomalyError("value must be a real number")
        self._obs.append(float(value))

    def stats(self) -> Dict[str, float]:
        if len(self._obs) < 2:
            raise AnomalyError("not enough observations")
        n = len(self._obs)
        mean = sum(self._obs) / n
        var = sum((x - mean) ** 2 for x in self._obs) / (n - 1)
        return {"mean": mean, "std": math.sqrt(var), "n": float(n)}

    def is_anomaly(self, value: float) -> bool:
        """z-score of value against the current window."""
        if not isinstance(value, (int, float)) or math.isnan(value):
            raise AnomalyError("value must be a real number")
        s = self.stats()
        if s["std"] == 0:
            return abs(value - s["mean"]) > 0
        return abs((value - s["mean"]) / s["std"]) >= self.z_threshold


class AnomalyMonitor:
    """Tracks many named metrics."""

    def __init__(self, window: int = 50, z_threshold: float = 3.0) -> None:
        self._window = window
        self._z = z_threshold
        self._detectors: Dict[str, Detector] = {}

    def check(self, metric: str, value: float) -> bool:
        """Observe and report anomaly. Creates detector on first use."""
        if not metric:
            raise AnomalyError("metric name required")
        det = self._detectors.get(metric)
        if det is None:
            det = Detector(window=self._window, z_threshold=self._z)
            self._detectors[metric] = det
        anomalous = len(det._obs) >= 2 and det.is_anomaly(value)
        det.observe(value)
        return anomalous


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "collections", "dataclasses", "math", "pathlib", "typing"}
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
    """Self-check."""
    mon = AnomalyMonitor(window=10, z_threshold=3.0)
    for _ in range(10):
        assert mon.check("latency", 0.05) is False
    assert mon.check("latency", 5.0) is True  # spike
    assert mon.check("latency", 0.05) is False  # back to normal-ish
    d = Detector(window=5)
    try:
        d.stats()
        raise AssertionError("should raise")
    except AnomalyError:
        pass
    try:
        Detector(window=1)
        raise AssertionError("should raise")
    except AnomalyError:
        pass
    try:
        mon.check("", 1.0)
        raise AssertionError("should raise")
    except AnomalyError:
        pass
    assert stdlib_only()
    print("monitor-07 OK: z-score, multi-metric, fail-closed, stdlib")


if __name__ == "__main__":
    main()
