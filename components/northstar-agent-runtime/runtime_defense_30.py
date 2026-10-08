"""Runtime defense 30: Timeouts, Simulated.

Deadline-based timeouts for operations: each operation gets a
deadline; the ``expired`` check is pure and monotonic-clock based.
Context-manager helper for scoped timeouts.

What this IS: deadline config + monotonic expiry checks.

What this IS NOT:
* Not preemption -- host cancels the work; this only reports.
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from typing import Optional

#: Module version.
RUNTIME_DEFENSE_30_VERSION = "runtime-defense-30.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-30.v1"


class TimeoutError(Exception):
    """Fail-closed: bad timeouts raise."""


@dataclass(frozen=True)
class Timeout:
    """A timeout duration."""

    seconds: float

    def __post_init__(self):
        if self.seconds <= 0:
            raise TimeoutError("seconds must be positive")


@dataclass
class Deadline:
    """A deadline anchored to the monotonic clock."""

    timeout: Timeout
    started_at: float = field(default_factory=time.monotonic)

    @property
    def deadline_at(self) -> float:
        return self.started_at + self.timeout.seconds

    def expired(self, now: Optional[float] = None) -> bool:
        """True if the deadline has passed."""
        now = time.monotonic() if now is None else now
        return now >= self.deadline_at

    def remaining(self, now: Optional[float] = None) -> float:
        """Seconds left (0 if expired)."""
        now = time.monotonic() if now is None else now
        return max(0.0, self.deadline_at - now)

    def check(self, now: Optional[float] = None) -> None:
        """Raise TimeoutError if expired (fail-closed enforcement hook)."""
        if self.expired(now):
            raise TimeoutError(
                f"deadline exceeded after {self.timeout.seconds}s"
            )


class timeout_scope:
    """Context manager: raises TimeoutError if the block overruns.

    Usage:
        with timeout_scope(5.0):
            ...work...
    The host should check ``expired()`` cooperatively inside the block;
    on exit the scope verifies once more.
    """

    def __init__(self, seconds: float):
        self.deadline = Deadline(Timeout(seconds))

    def __enter__(self) -> Deadline:
        return self.deadline

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.deadline.check()  # raise if overran
        return False  # do not suppress


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
    d = Deadline(Timeout(10.0), started_at=100.0)
    assert d.expired(now=105.0) is False
    assert d.expired(now=111.0) is True
    assert d.remaining(now=105.0) == 5.0
    assert d.remaining(now=200.0) == 0.0
    try:
        d.check(now=200.0)
        raise AssertionError("should raise")
    except TimeoutError:
        pass
    with timeout_scope(60.0) as dl:
        assert dl.expired() is False
    try:
        with timeout_scope(0.000001):
            time.sleep(0.01)
        raise AssertionError("should raise")
    except TimeoutError:
        pass
    try:
        Timeout(0)
        raise AssertionError("should raise")
    except TimeoutError:
        pass
    assert stdlib_only()
    print("runtime-defense-30 OK: timeouts, deadlines, fail-closed")


if __name__ == "__main__":
    main()
