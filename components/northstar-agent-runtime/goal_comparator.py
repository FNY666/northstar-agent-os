"""Goal comparator: termination oracle (BabyAGI #14), Simulated.

BabyAGI's loop has no termination condition.  The fix: a 4th
non-optional agent that emits equilibrium_reached/not_reached by
comparing current state against the declared objective.

Every autonomous loop needs an explicit halting oracle.

What this IS: prevents infinite loops and drift.

What this IS NOT:
* Not the objective parser -- host provides structured objectives.
* The comparator is heuristic; host can plug in LLM judge.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

#: Module version.
GOAL_COMPARATOR_VERSION = "goal-comparator.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.goal-comparator.v1"


class GoalComparatorError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class ComparisonResult:
    """Result of comparing state to objective."""

    done: bool
    reason: str
    cycles_used: int


class GoalComparator:
    """Checks if the objective is reached."""

    def __init__(
        self,
        objective: str,
        *,
        max_cycles: int = 100,
        comparator_fn: Optional[Callable[[str, Dict[str, Any]], bool]] = None,
    ) -> None:
        if not objective or not objective.strip():
            raise GoalComparatorError("objective required")
        if max_cycles <= 0:
            raise GoalComparatorError("max_cycles must be positive")
        self._objective = objective
        self._max_cycles = max_cycles
        self._comparator_fn = comparator_fn
        self._cycles = 0

    def check(
        self,
        state_summary: Dict[str, Any],
        task_queue: List[str] = None,
    ) -> ComparisonResult:
        """Check if objective is reached.

        Returns ComparisonResult.  Done if:
        - comparator_fn returns True, OR
        - task_queue is empty, OR
        - max_cycles exceeded (forced halt)
        """
        self._cycles += 1
        # Forced halt on max cycles.
        if self._cycles > self._max_cycles:
            return ComparisonResult(
                done=True,
                reason=f"max cycles ({self._max_cycles}) exceeded",
                cycles_used=self._cycles,
            )
        # Empty queue = done.
        if task_queue is not None and len(task_queue) == 0:
            return ComparisonResult(
                done=True, reason="task queue empty", cycles_used=self._cycles
            )
        # Custom comparator.
        if self._comparator_fn is not None:
            try:
                done = self._comparator_fn(self._objective, state_summary)
            except Exception:
                done = False  # comparator failed, not done
            if done:
                return ComparisonResult(
                    done=True,
                    reason="comparator: objective reached",
                    cycles_used=self._cycles,
                )
        return ComparisonResult(
            done=False,
            reason="objective not yet reached",
            cycles_used=self._cycles,
        )

    @property
    def cycles_used(self) -> int:
        return self._cycles


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    # Empty queue = done.
    gc = GoalComparator("write a file", max_cycles=10)
    r = gc.check({}, task_queue=[])
    assert r.done is True
    assert "empty" in r.reason

    # Custom comparator.
    gc2 = GoalComparator(
        "count to 3",
        comparator_fn=lambda obj, state: state.get("count", 0) >= 3,
    )
    r = gc2.check({"count": 1})
    assert r.done is False
    r = gc2.check({"count": 3})
    assert r.done is True

    # Max cycles forces halt.
    gc3 = GoalComparator("impossible", max_cycles=2)
    gc3.check({})
    gc3.check({})
    r = gc3.check({})
    assert r.done is True
    assert "max cycles" in r.reason

    assert stdlib_only()
    print("goal-comparator OK: termination, max cycles, fail-safe")


if __name__ == "__main__":
    main()
