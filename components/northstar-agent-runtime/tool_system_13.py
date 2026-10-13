"""Tool circuit breakers: fail fast, Simulated.

States: CLOSED (normal) -> OPEN (failing fast) -> HALF_OPEN (probing).
After `failure_threshold` consecutive failures, the breaker opens for
`reset_timeout` seconds, then allows one probe (half-open).  A probe
success closes it; failure re-opens.

What this IS: cascading-failure prevention.

What this IS NOT:
* Time is injectable (tests use a fake clock).
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

#: Module version.
TOOL_SYSTEM_13_VERSION = "tool-system-13.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-13.v1"


class ToolSystem13Error(Exception):
    """Fail-closed."""


class CircuitOpenError(ToolSystem13Error):
    """Raised when the circuit is open (fail fast)."""


class State(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Per-tool circuit breaker."""

    def __init__(
        self,
        failure_threshold: int = 3,
        reset_timeout: float = 30.0,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if failure_threshold < 1:
            raise ToolSystem13Error("failure_threshold must be >= 1")
        if reset_timeout <= 0:
            raise ToolSystem13Error("reset_timeout must be positive")
        self._threshold = failure_threshold
        self._timeout = reset_timeout
        self._clock = clock or time.time
        self._state = State.CLOSED
        self._failures = 0
        self._opened_at: Optional[float] = None

    @property
    def state(self) -> State:
        self._maybe_half_open()
        return self._state

    def _maybe_half_open(self) -> None:
        if self._state == State.OPEN and self._opened_at is not None:
            if self._clock() - self._opened_at >= self._timeout:
                self._state = State.HALF_OPEN

    def call(self, fn: Callable[[], Any]) -> Any:
        """Call fn through the breaker."""
        self._maybe_half_open()
        if self._state == State.OPEN:
            raise CircuitOpenError("circuit open: failing fast")
        try:
            result = fn()
        except Exception:
            self._on_failure()
            raise
        self._on_success()
        return result

    def _on_failure(self) -> None:
        self._failures += 1
        if self._state == State.HALF_OPEN:
            # Probe failed: re-open.
            self._state = State.OPEN
            self._opened_at = self._clock()
        elif self._failures >= self._threshold:
            self._state = State.OPEN
            self._opened_at = self._clock()

    def _on_success(self) -> None:
        self._failures = 0
        self._state = State.CLOSED
        self._opened_at = None


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "enum",
               "pathlib", "time", "typing"}
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
    now = {"t": 0.0}
    cb = CircuitBreaker(
        failure_threshold=2, reset_timeout=10.0,
        clock=lambda: now["t"],
    )
    assert cb.state == State.CLOSED

    def boom():
        raise ValueError("x")

    # Two failures open the circuit.
    for _ in range(2):
        try:
            cb.call(boom)
        except ValueError:
            pass
    assert cb.state == State.OPEN
    # Fail fast without calling fn.
    try:
        cb.call(lambda: "never")
        raise AssertionError("should raise")
    except CircuitOpenError:
        pass
    # After timeout: half-open, probe succeeds -> closed.
    now["t"] = 11.0
    assert cb.state == State.HALF_OPEN
    assert cb.call(lambda: "ok") == "ok"
    assert cb.state == State.CLOSED
    # Half-open probe failure re-opens.
    for _ in range(2):
        try:
            cb.call(boom)
        except ValueError:
            pass
    now["t"] = 25.0
    try:
        cb.call(boom)
    except ValueError:
        pass
    assert cb.state == State.OPEN
    assert stdlib_only()
    print("tool_system_13 OK: open, half-open, re-open")


if __name__ == "__main__":
    main()
