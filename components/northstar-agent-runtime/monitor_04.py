"""Alert rules: threshold alerts, Simulated.

Evaluates metric samples against threshold rules (>, <, >=, <=, ==, !=)
over a sliding window. Firing alerts carry labels, severity, and the
window that triggered them. Supports for-duration (alert only fires
if the condition holds for N consecutive evaluations).

What this IS: the rule-evaluation core for paging on gate anomalies
(deny spikes, latency, queue depth).

What this IS NOT:
* Not a notifier -- host delivers pages from returned Alert objects.
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

#: Module version.
MONITOR_04_VERSION = "monitor-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-04.v1"

_VALID_OPS = {">", "<", ">=", "<=", "==", "!="}
_VALID_SEVERITIES = {"info", "warning", "critical"}


class AlertError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AlertRule:
    name: str
    metric: str
    op: str
    threshold: float
    severity: str = "warning"
    for_evals: int = 1
    labels: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name or not self.metric:
            raise AlertError("rule name and metric required")
        if self.op not in _VALID_OPS:
            raise AlertError(f"bad operator {self.op!r}")
        if self.severity not in _VALID_SEVERITIES:
            raise AlertError(f"bad severity {self.severity!r}")
        if not isinstance(self.for_evals, int) or self.for_evals < 1:
            raise AlertError("for_evals must be positive int")


@dataclass(frozen=True)
class Alert:
    name: str
    metric: str
    severity: str
    value: float
    threshold: float
    op: str
    labels: Dict[str, str]
    fired_at_ns: int


def _matches(op: str, value: float, threshold: float) -> bool:
    return {
        ">": value > threshold,
        "<": value < threshold,
        ">=": value >= threshold,
        "<=": value <= threshold,
        "==": value == threshold,
        "!=": value != threshold,
    }[op]


class AlertManager:
    """Evaluates rules against samples."""

    def __init__(self) -> None:
        self._rules: List[AlertRule] = []
        self._streaks: Dict[str, int] = {}
        self._active: Dict[str, Alert] = {}

    def add_rule(self, rule: AlertRule) -> None:
        if not isinstance(rule, AlertRule):
            raise AlertError("rule must be AlertRule")
        if any(r.name == rule.name for r in self._rules):
            raise AlertError(f"duplicate rule {rule.name!r}")
        self._rules.append(rule)
        self._streaks[rule.name] = 0

    def evaluate(self, samples: Dict[str, float]) -> List[Alert]:
        """Evaluate all rules against current samples.

        Returns newly fired alerts (not already active).
        """
        if not isinstance(samples, dict):
            raise AlertError("samples must be dict")
        fired: List[Alert] = []
        for rule in self._rules:
            value = samples.get(rule.metric)
            cond = value is not None and _matches(rule.op, value, rule.threshold)
            if cond:
                self._streaks[rule.name] += 1
            else:
                self._streaks[rule.name] = 0
                self._active.pop(rule.name, None)
            if (
                self._streaks[rule.name] >= rule.for_evals
                and rule.name not in self._active
            ):
                alert = Alert(
                    name=rule.name,
                    metric=rule.metric,
                    severity=rule.severity,
                    value=float(value),  # type: ignore[arg-type]
                    threshold=rule.threshold,
                    op=rule.op,
                    labels=dict(rule.labels),
                    fired_at_ns=time.time_ns(),
                )
                self._active[rule.name] = alert
                fired.append(alert)
        return fired

    def active(self) -> List[Alert]:
        return list(self._active.values())


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "time", "typing"}
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
    mgr = AlertManager()
    mgr.add_rule(
        AlertRule(
            name="deny-spike",
            metric="deny_rate",
            op=">",
            threshold=0.5,
            severity="critical",
            for_evals=2,
        )
    )
    assert mgr.evaluate({"deny_rate": 0.9}) == []  # streak 1, for=2
    fired = mgr.evaluate({"deny_rate": 0.9})
    assert len(fired) == 1 and fired[0].severity == "critical"
    assert mgr.evaluate({"deny_rate": 0.9}) == []  # already active, no dup
    assert mgr.evaluate({"deny_rate": 0.1}) == []  # resolves
    assert mgr.active() == []
    try:
        AlertRule(name="x", metric="m", op="~", threshold=1)
        raise AssertionError("should raise")
    except AlertError:
        pass
    try:
        mgr.evaluate("bad")  # type: ignore[arg-type]
        raise AssertionError("should raise")
    except AlertError:
        pass
    assert stdlib_only()
    print("monitor-04 OK: thresholds, for-duration, fail-closed, stdlib")


if __name__ == "__main__":
    main()
