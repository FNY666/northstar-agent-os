"""Circuit breaker: fail-fast gate for an unreliable operation.

Research note: circuit breakers are a classic resilience pattern (Nygard,
*Release It!*) now applied to AI safety — an agent subsystem that starts
failing (a flaky tool, a degrading model endpoint, a poisoned data feed)
should be *cut off* before its failures cascade into the rest of the run,
rather than retried blindly until the budget or the audit log is exhausted.

* **Three states** — ``CLOSED`` (normal: calls pass through),
  ``OPEN`` (tripped: calls fail fast without invoking the function),
  ``HALF_OPEN`` (one trial call allowed; success closes, failure re-opens).
* **Failure threshold** — ``failure_threshold`` consecutive failures trip
  the breaker. Successes reset the consecutive-failure count.
* **No wall-clock** — the recovery window is measured in caller-supplied
  ``seq`` integers (the host's own monotonic counter), not seconds, so the
  module is deterministic and replayable. ``cooldown_seqs`` is how many
  seqs must elapse before a half-open trial is allowed.
* **Fail-closed** — a tripped breaker refuses with ``CircuitOpenError``
  instead of invoking the protected function; malformed inputs raise,
  they are not silently counted.

Honest scope: this is the *state machine* of a circuit breaker, not a
watchdog — it only knows what the caller reports through ``call`` /
``report_success`` / ``report_failure``. It cannot observe an operation
the caller never routes through it, and ``closed`` means "the breaker is
not tripped", never "the operation is healthy". Half-open allows exactly
one trial call; concurrent callers must serialize at the host (one trial
at a time is enforced by state, not by locks).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

#: Module version.
CIRCUIT_BREAKER_VERSION = "circuit-breaker.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.circuit-breaker.v1"


class CircuitState(str, Enum):
    """Breaker state."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half-open"


class CircuitOpenError(Exception):
    """Raised when a call is refused because the breaker is open."""

    def __init__(self, state: CircuitState, failures: int):
        self.state = state
        self.failures = failures
        super().__init__(
            f"circuit breaker is {state.value}: refusing call "
            f"({failures} consecutive failures)"
        )


class CircuitBreakerError(Exception):
    """Malformed input to the breaker (programming error)."""


def _check_seq(seq: Any, name: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise CircuitBreakerError(f"{name} must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise CircuitBreakerError(f"{name} must be non-negative")
    return seq


@dataclass(frozen=True)
class BreakerEvent:
    """One recorded state transition or refusal."""

    kind: str  # "closed" | "opened" | "half-open" | "refused" | "reset"
    seq: int
    consecutive_failures: int

    def __post_init__(self) -> None:
        if self.kind not in ("closed", "opened", "half-open", "refused", "reset"):
            raise CircuitBreakerError(f"unknown event kind: {self.kind!r}")
        _check_seq(self.seq)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": CIRCUIT_BREAKER_VERSION,
            "kind": self.kind,
            "seq": self.seq,
            "consecutive_failures": self.consecutive_failures,
        }


class CircuitBreaker:
    """Consecutive-failure circuit breaker with seq-based recovery."""

    def __init__(
        self,
        failure_threshold: int = 3,
        cooldown_seqs: int = 10,
    ) -> None:
        """Create a closed breaker.

        ``failure_threshold`` — consecutive failures that trip it (>= 1).
        ``cooldown_seqs`` — seqs to wait after tripping before a trial
        call is allowed (>= 0; 0 means the very next call may trial).
        """
        if isinstance(failure_threshold, bool) or not isinstance(
            failure_threshold, int
        ):
            raise CircuitBreakerError("failure_threshold must be an int")
        if failure_threshold < 1:
            raise CircuitBreakerError("failure_threshold must be >= 1")
        if isinstance(cooldown_seqs, bool) or not isinstance(cooldown_seqs, int):
            raise CircuitBreakerError("cooldown_seqs must be an int")
        if cooldown_seqs < 0:
            raise CircuitBreakerError("cooldown_seqs must be >= 0")
        self._failure_threshold = failure_threshold
        self._cooldown_seqs = cooldown_seqs
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at_seq: int | None = None
        self._events: list[BreakerEvent] = []

    # -- introspection -------------------------------------------------
    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    @property
    def failure_threshold(self) -> int:
        return self._failure_threshold

    @property
    def cooldown_seqs(self) -> int:
        return self._cooldown_seqs

    def events(self) -> tuple[BreakerEvent, ...]:
        """Append-only view of recorded events (registration order)."""
        return tuple(self._events)

    # -- state transitions ---------------------------------------------
    def _record(self, kind: str, seq: int) -> None:
        self._events.append(
            BreakerEvent(
                kind=kind, seq=seq, consecutive_failures=self._consecutive_failures
            )
        )

    def _trip(self, seq: int) -> None:
        self._state = CircuitState.OPEN
        self._opened_at_seq = seq
        self._record("opened", seq)

    def report_success(self, seq: int) -> CircuitState:
        """Report a successful call; resets the failure count.

        A success while HALF_OPEN closes the breaker.
        """
        seq = _check_seq(seq)
        self._consecutive_failures = 0
        if self._state in (CircuitState.OPEN, CircuitState.HALF_OPEN):
            self._state = CircuitState.CLOSED
            self._opened_at_seq = None
            self._record("closed", seq)
        return self._state

    def report_failure(self, seq: int) -> CircuitState:
        """Report a failed call; trips the breaker at the threshold."""
        seq = _check_seq(seq)
        self._consecutive_failures += 1
        if self._state == CircuitState.HALF_OPEN:
            # Failed trial: back to open, restart the cooldown.
            self._trip(seq)
        elif self._consecutive_failures >= self._failure_threshold:
            self._trip(seq)
        return self._state

    def reset(self, seq: int) -> CircuitState:
        """Manual reset: force the breaker closed, clear failure count."""
        seq = _check_seq(seq)
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at_seq = None
        self._record("reset", seq)
        return self._state

    def open(self, seq: int) -> CircuitState:
        """Manual trip: force the breaker open from closed or half-open.

        The operator's override for "this subsystem is bad" — trips even
        when ``consecutive_failures`` is below ``failure_threshold``.
        Records an ``"opened"`` event only on an actual transition and
        starts the cooldown window at the trip seq. Calling ``open()``
        on an already-open breaker is a no-op returning
        ``CircuitState.OPEN`` (idempotent, mirroring ``reset()``).
        """
        seq = _check_seq(seq)
        if self._state is CircuitState.OPEN:
            return self._state
        self._trip(seq)
        return self._state

    def _maybe_half_open(self, seq: int) -> None:
        if (
            self._state is CircuitState.OPEN
            and self._opened_at_seq is not None
            and seq - self._opened_at_seq >= self._cooldown_seqs
        ):
            self._state = CircuitState.HALF_OPEN
            self._record("half-open", seq)

    # -- guarded calls ---------------------------------------------------
    def allow_call(self, seq: int) -> bool:
        """True if a call may proceed now (advances to half-open first)."""
        seq = _check_seq(seq)
        self._maybe_half_open(seq)
        return self._state in (CircuitState.CLOSED, CircuitState.HALF_OPEN)

    def call(self, func: Callable[..., Any], *args: Any, seq: int, **kwargs: Any) -> Any:
        """Run ``func`` through the breaker, or fail fast.

        - CLOSED: invoke; success reports success, an exception reports
          failure and re-raises the *original* exception (not wrapped).
        - HALF_OPEN: one trial call; the outcome decides open vs closed.
        - OPEN: raise ``CircuitOpenError`` without invoking ``func``.
        ``seq`` is the caller-supplied monotonic sequence number.
        """
        seq = _check_seq(seq)
        if not callable(func):
            raise CircuitBreakerError("func must be callable")
        self._maybe_half_open(seq)
        if self._state is CircuitState.OPEN:
            self._record("refused", seq)
            raise CircuitOpenError(self._state, self._consecutive_failures)
        try:
            result = func(*args, **kwargs)
        except Exception:
            self.report_failure(seq)
            raise
        self.report_success(seq)
        return result


def main() -> None:
    breaker = CircuitBreaker(failure_threshold=3, cooldown_seqs=5)

    def ok() -> str:
        return "ok"

    def boom() -> str:
        raise RuntimeError("subsystem down")

    assert breaker.call(ok, seq=1) == "ok"
    assert breaker.state is CircuitState.CLOSED

    for s in (2, 3):
        try:
            breaker.call(boom, seq=s)
        except RuntimeError:
            pass
    assert breaker.state is CircuitState.CLOSED  # 2 < 3, not tripped yet
    try:
        breaker.call(boom, seq=4)
    except RuntimeError:
        pass
    assert breaker.state is CircuitState.OPEN

    # Fail fast while open: func is never invoked.
    invoked = []
    try:
        breaker.call(lambda: invoked.append(1), seq=5)
    except CircuitOpenError:
        pass
    assert invoked == []

    # Cooldown elapsed (seq 4 + 5): half-open trial succeeds -> closed.
    assert breaker.call(ok, seq=9) == "ok"
    assert breaker.state is CircuitState.CLOSED

    breaker.reset(seq=10)
    assert breaker.state is CircuitState.CLOSED
    assert breaker.consecutive_failures == 0
    print("circuit-breaker OK: trip at 3, fail-fast, half-open recovery, reset")


if __name__ == "__main__":
    main()
