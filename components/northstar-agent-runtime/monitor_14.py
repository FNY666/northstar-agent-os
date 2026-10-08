"""Behavioral baselines (mock), Simulated.

Per-entity baselines: rolling mean/std per (entity, metric). Compares
a current observation to the baseline, producing a drift score
(|z|). Entities graduate from "learning" to "established" after
min_observations. Evaluation before establishment raises (fail-closed).

What this IS: per-agent/per-tool normal-behavior profiles feeding
the observer.

What this IS NOT:
* Not cross-entity correlation -- one baseline per (entity, metric).
"""

from __future__ import annotations

import ast
import math
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Tuple

#: Module version.
MONITOR_14_VERSION = "monitor-14.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-14.v1"


class BaselineError(Exception):
    """Fail-closed."""


@dataclass
class Baseline:
    entity: str
    metric: str
    min_observations: int = 20
    _obs: Deque[float] = field(default_factory=deque)

    def __post_init__(self) -> None:
        if not self.entity or not self.metric:
            raise BaselineError("entity and metric required")
        if self.min_observations < 2:
            raise BaselineError("min_observations must be >= 2")

    def observe(self, value: float) -> None:
        if not isinstance(value, (int, float)) or math.isnan(value):
            raise BaselineError("value must be a real number")
        self._obs.append(float(value))

    @property
    def established(self) -> bool:
        return len(self._obs) >= self.min_observations

    def drift(self, value: float) -> float:
        """|z| of value vs baseline. Raises if not established."""
        if not self.established:
            raise BaselineError(
                f"baseline not established ({len(self._obs)}/{self.min_observations})"
            )
        if not isinstance(value, (int, float)) or math.isnan(value):
            raise BaselineError("value must be a real number")
        n = len(self._obs)
        mean = sum(self._obs) / n
        var = sum((x - mean) ** 2 for x in self._obs) / (n - 1)
        std = math.sqrt(var)
        if std == 0:
            return 0.0 if value == mean else float("inf")
        return abs((value - mean) / std)


class BaselineStore:
    """Holds baselines for many (entity, metric) pairs."""

    def __init__(self, min_observations: int = 20) -> None:
        if min_observations < 2:
            raise BaselineError("min_observations must be >= 2")
        self._min = min_observations
        self._baselines: Dict[Tuple[str, str], Baseline] = {}

    def observe(self, entity: str, metric: str, value: float) -> None:
        key = (entity, metric)
        base = self._baselines.get(key)
        if base is None:
            if not entity or not metric:
                raise BaselineError("entity and metric required")
            base = Baseline(entity, metric, min_observations=self._min)
            self._baselines[key] = base
        base.observe(value)

    def drift(self, entity: str, metric: str, value: float) -> float:
        base = self._baselines.get((entity, metric))
        if base is None:
            raise BaselineError(f"no baseline for {(entity, metric)}")
        return base.drift(value)

    def established(self, entity: str, metric: str) -> bool:
        base = self._baselines.get((entity, metric))
        return base is not None and base.established


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
    store = BaselineStore(min_observations=5)
    for _ in range(5):
        store.observe("agent-1", "tool_calls_per_min", 10.0)
    assert store.established("agent-1", "tool_calls_per_min") is True
    assert store.drift("agent-1", "tool_calls_per_min", 10.0) == 0.0
    assert store.drift("agent-1", "tool_calls_per_min", 100.0) == float("inf")
    store2 = BaselineStore(min_observations=5)
    store2.observe("a", "m", 1.0)
    try:
        store2.drift("a", "m", 1.0)
        raise AssertionError("should raise")
    except BaselineError:
        pass
    try:
        store2.drift("nobody", "m", 1.0)
        raise AssertionError("should raise")
    except BaselineError:
        pass
    assert stdlib_only()
    print("monitor-14 OK: baselines, drift, fail-closed, stdlib")


if __name__ == "__main__":
    main()
