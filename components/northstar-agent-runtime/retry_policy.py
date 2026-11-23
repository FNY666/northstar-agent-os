"""Retry policy: bounded, backoff-shaped retries for a fallible operation.

Research note: retry with backoff is a classic resilience pattern (Nygard,
*Release It!*) — a transient failure (a flaky tool endpoint, a rate-limited
model API, a momentarily unreachable store) should be retried a bounded
number of times with growing delays, not retried forever and not failed
on the first wobble. The complementary pattern is the circuit breaker
(see :mod:`circuit_breaker`): retries handle *transient* blips, the breaker
cuts off *sustained* degradation. Used together, the retry policy sits
inside the breaker's closed path.

* **Bounded attempts** — ``max_attempts`` caps total tries (1 = no retry).
  The bound is structural: retries can never become an infinite loop that
  burns budget or fills the audit log.
* **Backoff strategies** — ``CONSTANT`` (fixed delay), ``LINEAR``
  (base * retry_index), ``EXPONENTIAL`` (base * 2**(retry_index - 1)),
  all in integer milliseconds and all capped by ``max_delay_ms``.
  Deterministic: the same policy and attempt number always yield the
  same delay, so a run is replayable from the audit record.
* **No wall-clock in the policy** — delays are *computed*, not *waited*;
  ``execute`` accepts an injectable ``sleeper`` (default: ``time.sleep``),
  so tests record the schedule without sleeping and production passes the
  real one.
* **Fail-closed classification** — only exceptions listed in ``retry_on``
  are retried. Anything else (a programming error, a ``KeyboardInterrupt``,
  a fail-closed ``TypeError`` from a sibling module) propagates immediately
  without consuming an attempt budget.
* **Exhaustion** — when every attempt fails, ``RetryExhausted`` is raised
  with the last error chained (``__cause__``) and the frozen
  ``RetryReport`` attached; the caller sees *what* failed and *how long*
  the policy waited.

Honest scope: this is the *schedule and decision logic* of retrying, not
a guarantee of success — a retry cannot fix a permanently broken operation,
and retrying a non-idempotent side effect can *repeat* it (the idempotency
contract is the caller's job, not this module's). ``succeeded=True`` in a
report means "the function returned", never "the world changed".
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

#: Module version.
RETRY_POLICY_VERSION = "retry-policy.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.retry-policy.v1"


class BackoffStrategy(str, Enum):
    """Delay growth between retries."""

    CONSTANT = "constant"
    LINEAR = "linear"
    EXPONENTIAL = "exponential"


class RetryPolicyError(Exception):
    """Malformed input to the retry policy (programming error)."""


class RetryExhausted(Exception):
    """Raised when every attempt failed.

    Carries the frozen :class:`RetryReport` in ``report`` and chains the
    last attempt's exception as ``__cause__``.
    """

    def __init__(self, report: "RetryReport", last_error: BaseException):
        self.report = report
        self.last_error = last_error
        super().__init__(
            f"retry policy exhausted after {report.attempts_made} attempt(s): "
            f"{type(last_error).__name__}: {last_error}"
        )
        self.__cause__ = last_error


def _check_attempts(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RetryPolicyError(f"max_attempts must be an int, got {type(value).__name__}")
    if value < 1:
        raise RetryPolicyError("max_attempts must be >= 1")
    return value


def _check_delay_ms(value: Any, name: str, allow_none: bool = False) -> Optional[int]:
    if value is None:
        if allow_none:
            return None
        raise RetryPolicyError(f"{name} must be an int of milliseconds, got None")
    if isinstance(value, bool) or not isinstance(value, int):
        raise RetryPolicyError(f"{name} must be an int of milliseconds, got {type(value).__name__}")
    if value < 0:
        raise RetryPolicyError(f"{name} must be non-negative")
    return value


def _check_strategy(value: Any) -> BackoffStrategy:
    if isinstance(value, BackoffStrategy):
        return value
    if isinstance(value, str):
        try:
            return BackoffStrategy(value.lower())
        except ValueError:
            pass
    raise RetryPolicyError(
        f"backoff_strategy must be one of {[s.value for s in BackoffStrategy]}, "
        f"got {value!r}"
    )


def _check_retry_on(value: Any) -> tuple[type[BaseException], ...]:
    if isinstance(value, type) and issubclass(value, BaseException):
        return (value,)
    if isinstance(value, (tuple, list)) and value:
        for item in value:
            if not (isinstance(item, type) and issubclass(item, BaseException)):
                raise RetryPolicyError(
                    f"retry_on entries must be exception classes, got {item!r}"
                )
        return tuple(value)
    raise RetryPolicyError("retry_on must be an exception class or a non-empty tuple/list of them")


@dataclass(frozen=True)
class RetryReport:
    """Frozen record of one ``execute`` run."""

    attempts_made: int
    succeeded: bool
    delays_ms: tuple[int, ...]  # delays actually waited, in order
    last_error_type: Optional[str]  # None on success

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": RETRY_POLICY_VERSION,
            "attempts_made": self.attempts_made,
            "succeeded": self.succeeded,
            "delays_ms": list(self.delays_ms),
            "last_error_type": self.last_error_type,
        }


class RetryPolicy:
    """Bounded retry schedule with a deterministic backoff."""

    def __init__(
        self,
        max_attempts: int = 3,
        backoff_strategy: BackoffStrategy | str = BackoffStrategy.EXPONENTIAL,
        base_delay_ms: int = 100,
        max_delay_ms: Optional[int] = None,
        retry_on: Any = Exception,
    ) -> None:
        self.max_attempts = _check_attempts(max_attempts)
        self.backoff_strategy = _check_strategy(backoff_strategy)
        self.base_delay_ms = _check_delay_ms(base_delay_ms, "base_delay_ms")
        assert self.base_delay_ms is not None
        self.max_delay_ms = _check_delay_ms(max_delay_ms, "max_delay_ms", allow_none=True)
        if self.max_delay_ms is not None and self.max_delay_ms < self.base_delay_ms:
            raise RetryPolicyError("max_delay_ms must be >= base_delay_ms")
        self.retry_on = _check_retry_on(retry_on)

    def delay_before_attempt(self, attempt: int) -> int:
        """Delay (ms) to wait before ``attempt`` (1-based, ``attempt >= 2``).

        Pure and deterministic: same inputs always yield the same delay.
        """
        if isinstance(attempt, bool) or not isinstance(attempt, int):
            raise RetryPolicyError(f"attempt must be an int, got {type(attempt).__name__}")
        if attempt < 2:
            raise RetryPolicyError("attempt must be >= 2 (attempt 1 needs no delay)")
        retry_index = attempt - 1  # 1 for the first retry
        if self.backoff_strategy is BackoffStrategy.CONSTANT:
            delay = self.base_delay_ms
        elif self.backoff_strategy is BackoffStrategy.LINEAR:
            delay = self.base_delay_ms * retry_index
        else:  # EXPONENTIAL
            delay = self.base_delay_ms * (2 ** (retry_index - 1))
        if self.max_delay_ms is not None:
            delay = min(delay, self.max_delay_ms)
        return delay

    def retry_schedule(self) -> tuple[int, ...]:
        """All delays (ms) the policy would wait, in order.

        Length is ``max_attempts - 1``; empty when ``max_attempts == 1``.
        """
        return tuple(self.delay_before_attempt(n) for n in range(2, self.max_attempts + 1))

    def execute(
        self,
        func: Callable[..., Any],
        *args: Any,
        sleeper: Optional[Callable[[float], None]] = None,
        **kwargs: Any,
    ) -> tuple[Any, RetryReport]:
        """Run ``func`` with retries. Returns ``(result, report)``.

        ``sleeper`` receives each delay in *seconds* (``time.sleep``-shaped);
        the default is the real ``time.sleep``. Pass a recording stub in
        tests to assert the schedule without waiting.
        """
        if not callable(func):
            raise RetryPolicyError(f"func must be callable, got {type(func).__name__}")
        if sleeper is not None and not callable(sleeper):
            raise RetryPolicyError("sleeper must be callable")
        sleep = sleeper if sleeper is not None else time.sleep

        delays_waited: list[int] = []
        last_error: Optional[BaseException] = None
        for attempt in range(1, self.max_attempts + 1):
            if attempt > 1:
                delay_ms = self.delay_before_attempt(attempt)
                sleep(delay_ms / 1000.0)
                delays_waited.append(delay_ms)
            try:
                result = func(*args, **kwargs)
            except self.retry_on as exc:  # noqa: BLE001 - classification is the point
                last_error = exc
                continue
            report = RetryReport(
                attempts_made=attempt,
                succeeded=True,
                delays_ms=tuple(delays_waited),
                last_error_type=None,
            )
            return result, report
        # Every attempt raised a retryable error.
        assert last_error is not None  # max_attempts >= 1 guarantees one attempt
        report = RetryReport(
            attempts_made=self.max_attempts,
            succeeded=False,
            delays_ms=tuple(delays_waited),
            last_error_type=type(last_error).__name__,
        )
        raise RetryExhausted(report, last_error)


def retry_audit_event(report: RetryReport, seq: Any) -> dict[str, Any]:
    """Shape a report as an ``audit.ndjson/1``-style record."""
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise RetryPolicyError("seq must be a non-negative int")
    record = report.as_dict()
    record["audit_seq"] = seq
    record["event"] = "retry-policy"
    return record


def main() -> None:
    """Self-check: schedule, success-after-retry, exhaustion."""
    policy = RetryPolicy(max_attempts=3, backoff_strategy="exponential", base_delay_ms=100)
    assert policy.retry_schedule() == (100, 200), policy.retry_schedule()

    waited: list[float] = []
    calls = {"n": 0}

    def flaky() -> str:
        calls["n"] += 1
        if calls["n"] < 3:
            raise ValueError("transient")
        return "ok"

    result, report = policy.execute(flaky, sleeper=waited.append)
    assert result == "ok" and report.succeeded and report.attempts_made == 3
    assert waited == [0.1, 0.2], waited

    def always() -> None:
        raise RuntimeError("permanent")

    try:
        policy.execute(always, sleeper=lambda s: None)
    except RetryExhausted as exc:
        assert exc.report.attempts_made == 3
        assert isinstance(exc.__cause__, RuntimeError)
    else:  # pragma: no cover
        raise AssertionError("expected RetryExhausted")

    print("retry-policy OK: schedule deterministic, retry-then-succeed, exhaustion chained")


if __name__ == "__main__":
    main()
