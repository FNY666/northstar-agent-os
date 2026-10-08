"""obs_22: Error budgets, Simulated.

Tracks consumption of a service's error budget over a compliance window.
The budget is the fraction of bad events the SLO tolerates:
``(1 - slo_target) * total_events``.  ``consume`` records bad events against
the budget; ``remaining`` reports what is left and whether it is exhausted.

Fail-closed: invalid targets, negative totals, or bad counts above the
total raise.
Stdlib only.
"""

from __future__ import annotations

import ast
from typing import Dict

OBS22_VERSION = "obs-22.v1"
SCHEMA_PIN = "northstar.obs-22.v1"


class Obs22Error(Exception):
    """Fail-closed."""


class ErrorBudget:
    """Error budget for an SLO target over a window in days."""

    def __init__(self, slo_target: float, window_days: float) -> None:
        if not isinstance(slo_target, (int, float)) or isinstance(slo_target, bool):
            raise Obs22Error("slo_target must be a number")
        if not 0.0 < float(slo_target) < 1.0:
            raise Obs22Error("slo_target must be inside (0, 1)")
        if not isinstance(window_days, (int, float)) or isinstance(window_days, bool):
            raise Obs22Error("window_days must be a number")
        if float(window_days) <= 0:
            raise Obs22Error("window_days must be positive")
        self.slo_target = float(slo_target)
        self.window_days = float(window_days)
        self._consumed = 0

    @staticmethod
    def _check_count(value: int, label: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise Obs22Error(f"{label} must be a non-negative int")
        return value

    def allowed_bad_events(self, total_events: int) -> float:
        """Number of bad events the budget tolerates for this total."""
        total = self._check_count(total_events, "total_events")
        return (1.0 - self.slo_target) * total

    def consume(self, bad_count: int) -> int:
        """Record bad events against the budget; returns cumulative consumed."""
        bad = self._check_count(bad_count, "bad_count")
        self._consumed += bad
        return self._consumed

    def remaining(self, total_events: int, bad_used: int) -> Dict[str, object]:
        """Report budget state for a given total and externally counted bad events."""
        total = self._check_count(total_events, "total_events")
        bad = self._check_count(bad_used, "bad_used")
        if bad > total:
            raise Obs22Error("bad_used cannot exceed total_events")
        allowed = self.allowed_bad_events(total)
        left = allowed - bad
        pct = (left / allowed * 100.0) if allowed > 0 else 0.0
        return {
            "allowed": allowed,
            "consumed": bad,
            "remaining": left,
            "pct_remaining": pct,
            "exhausted": left < 0.0,
            "window_days": self.window_days,
        }


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    eb = ErrorBudget(0.999, 30.0)
    assert abs(eb.allowed_bad_events(10000) - 10.0) < 1e-9
    assert eb.consume(3) == 3
    assert eb.consume(2) == 5
    state = eb.remaining(10000, 5)
    assert abs(state["allowed"] - 10.0) < 1e-9
    assert state["consumed"] == 5
    assert abs(state["remaining"] - 5.0) < 1e-9
    assert abs(state["pct_remaining"] - 50.0) < 1e-9
    assert state["exhausted"] is False
    burnt = eb.remaining(10000, 12)
    assert burnt["exhausted"] is True and burnt["remaining"] < 0.0
    try:
        ErrorBudget(1.5, 30.0)
        raise AssertionError("should raise")
    except Obs22Error:
        pass
    try:
        eb.remaining(100, 101)
        raise AssertionError("should raise")
    except Obs22Error:
        pass
    try:
        eb.consume(-2)
        raise AssertionError("should raise")
    except Obs22Error:
        pass
    assert stdlib_only()
    print("obs_22 OK")


if __name__ == "__main__":
    main()
