"""Runtime defense 16: Time limits (config), Simulated.

Per-action and per-task wall-clock time limits.  Exceeding the limit
is a deny/halt, never a silent extension.

What this IS: declarative time-budget config enforced by the host.

What this IS NOT:
* Not the clock itself -- host measures elapsed time.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

#: Module version.
RUNTIME_DEFENSE_16_VERSION = "runtime-defense-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-16.v1"


class TimeLimitError(Exception):
    """Fail-closed: bad limits raise."""


@dataclass(frozen=True)
class TimeLimits:
    """Time limits in seconds."""

    max_action_seconds: float = 60.0
    max_task_seconds: float = 3600.0
    # Grace period before hard kill.
    kill_grace_seconds: float = 5.0

    def __post_init__(self):
        if self.max_action_seconds <= 0:
            raise TimeLimitError("max_action_seconds must be positive")
        if self.max_task_seconds < self.max_action_seconds:
            raise TimeLimitError(
                "max_task_seconds must be >= max_action_seconds"
            )
        if self.kill_grace_seconds < 0:
            raise TimeLimitError("kill_grace_seconds must be >= 0")


def action_expired(elapsed: float, limits: TimeLimits) -> bool:
    """True if the action exceeded its time limit."""
    if elapsed < 0:
        raise TimeLimitError("elapsed must be >= 0")
    return elapsed > limits.max_action_seconds


def task_expired(elapsed: float, limits: TimeLimits) -> bool:
    """True if the task exceeded its time limit."""
    if elapsed < 0:
        raise TimeLimitError("elapsed must be >= 0")
    return elapsed > limits.max_task_seconds


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib"}
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
    limits = TimeLimits(max_action_seconds=10.0, max_task_seconds=100.0)
    assert action_expired(11.0, limits) is True
    assert action_expired(5.0, limits) is False
    assert task_expired(101.0, limits) is True
    assert task_expired(50.0, limits) is False
    try:
        TimeLimits(max_action_seconds=0)
        raise AssertionError("should raise")
    except TimeLimitError:
        pass
    assert stdlib_only()
    print("runtime-defense-16 OK: time limits, expiry, fail-closed")


if __name__ == "__main__":
    main()
