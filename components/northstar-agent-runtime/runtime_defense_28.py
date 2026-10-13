"""Runtime defense 28: Circuit breakers, Simulated.

Classic closed/open/half-open circuit breaker per dependency.  After
``failure_threshold`` consecutive failures the circuit opens for
``cooldown_seconds``; a half-open probe decides recovery.

What this IS: failure containment for downstream dependencies.

What this IS NOT:
* Not retry policy -- it stops calls, the host retries later.
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Tuple

#: Module version.
RUNTIME_DEFENSE_28_VERSION = "runtime-defense-28.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-28.v1"


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerError(Exception):
    """Fail-closed: bad config raises."""


@dataclass
class CircuitBreaker:
    """Per-dependency circuit breaker."""

    name: str
    failure_threshold: int = 5
    cooldown_seconds: float = 30.0
    state: CircuitState = CircuitState.CLOSED
    consecutive_failures: int = 0
    opened_at: float = 0.0

    def __post_init__(self):
        if not self.name:
            raise CircuitBreakerError("name required")
        if self.failure_threshold <= 0:
            raise CircuitBreakerError("failure_threshold must be positive")
        if self.cooldown_seconds < 0:
            raise CircuitBreakerError("cooldown_seconds must be >= 0")

    def _maybe_half_open(self, now: float) -> None:
        if self.state == CircuitState.OPEN and now - self.opened_at >= self.cooldown_seconds:
            self.state = CircuitState.HALF_OPEN

    def allow(self, now: float | None = None) -> bool:
        """True if a call may proceed."""
        now = time.time() if now is None else now
        self._maybe_half_open(now)
        return self.state in (CircuitState.CLOSED, CircuitState.HALF_OPEN)

    def record_success(self) -> None:
        """Record success: close the circuit."""
        self.consecutive_failures = 0
        self.state = CircuitState.CLOSED

    def record_failure(self, now: float | None = None) -> None:
        """Record failure: open after threshold."""
        now = time.time() if now is None else now
        self.consecutive_failures += 1
        if self.state == CircuitState.HALF_OPEN:
            # Probe failed: back to open.
            self.state = CircuitState.OPEN
            self.opened_at = now
        elif self.consecutive_failures >= self.failure_threshold:
            self.state = CircuitState.OPEN
            self.opened_at = now


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "enum", "pathlib", "time", "typing"}
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
    cb = CircuitBreaker("db", failure_threshold=2, cooldown_seconds=10.0)
    assert cb.allow(now=0.0) is True
    cb.record_failure(now=1.0)
    assert cb.allow(now=2.0) is True  # still closed (1 < 2)
    cb.record_failure(now=3.0)
    assert cb.allow(now=4.0) is False  # open
    assert cb.allow(now=20.0) is True  # half-open after cooldown
    cb.record_failure(now=21.0)  # probe fails -> open again
    assert cb.allow(now=22.0) is False
    cb2 = CircuitBreaker("ok", failure_threshold=2)
    cb2.record_failure()
    cb2.record_success()
    assert cb2.state == CircuitBreaker.CLOSED if False else cb2.state == CircuitState.CLOSED
    try:
        CircuitBreaker("", failure_threshold=1)
        raise AssertionError("should raise")
    except CircuitBreakerError:
        pass
    assert stdlib_only()
    print("runtime-defense-28 OK: circuit breaker, states, fail-closed")


if __name__ == "__main__":
    main()
