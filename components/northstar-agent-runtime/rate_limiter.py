"""Rate limiting for API safety: token-bucket enforcement over caller-supplied time.

A ``RateLimiter`` bounds how often the host may act on behalf of an agent:
``allow_request(now_ms)`` returns ``True`` when the current request fits within
the configured rate and consumes one token; ``get_wait_time(now_ms)`` reports
milliseconds until the next request would be allowed (0 when allowed now).

House style: no wall-clock — all timestamps are caller-supplied monotonic
milliseconds (ints). Time never flows backwards: a ``now_ms`` earlier than the
last seen one is a programming error and raises ``TypeError`` fail-closed
(rather than silently resetting the bucket). stdlib-only, deterministic,
frozen decision records, version/schema pins, ``main()`` self-check.

Honest scope: bounds *attempted* call rate as observed by the host. Cannot see
calls the host never reports, and does not distinguish a legit burst of
retries from an abuse burst -- that triage is the caller's job. A quiet
limiter means "no known over-rate shape", never "no abuse".

Version pin: rate-limiter.v1
Schema pin: northstar.rate-limiter.v1
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

RATE_LIMITER_VERSION = "rate-limiter.v1"
SCHEMA_PIN = "northstar.rate-limiter.v1"


def _require_nonneg_int(name: str, value) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")


def _require_positive_int(name: str, value) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value <= 0:
        raise ValueError(f"{name} must be positive")


@dataclass(frozen=True)
class LimitDecision:
    """One rate-limit verdict (frozen record)."""

    allowed: bool
    tokens_after: int
    wait_ms: int
    now_ms: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise TypeError("allowed must be a bool")
        _require_nonneg_int("tokens_after", self.tokens_after)
        _require_nonneg_int("wait_ms", self.wait_ms)
        _require_nonneg_int("now_ms", self.now_ms)

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "tokens_after": self.tokens_after,
            "wait_ms": self.wait_ms,
            "now_ms": self.now_ms,
            "schema": self.schema,
        }


class RateLimiter:
    """Token-bucket rate limiter over caller-supplied millisecond timestamps.

    ``capacity`` is the burst size (max tokens). ``refill_per_second`` is the
    sustained rate: tokens are added in whole units; fractional accumulation
    is tracked exactly via integer math (``elapsed_ms * refill_per_second``)
    so there is no float drift.
    """

    def __init__(self, capacity: int, refill_per_second: int) -> None:
        _require_positive_int("capacity", capacity)
        _require_positive_int("refill_per_second", refill_per_second)
        self._capacity = capacity
        self._refill_per_second = refill_per_second
        self._tokens = capacity
        self._leftover_ms = 0  # elapsed ms not yet converted to a token
        self._last_ms: int | None = None

    # -- introspection ----------------------------------------------------
    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def refill_per_second(self) -> int:
        return self._refill_per_second

    @property
    def version(self) -> str:
        return RATE_LIMITER_VERSION

    def _advance(self, now_ms: int) -> None:
        _require_nonneg_int("now_ms", now_ms)
        if self._last_ms is None:
            self._last_ms = now_ms
            return
        if now_ms < self._last_ms:
            raise TypeError("now_ms moved backwards; timestamps must be monotonic")
        elapsed = now_ms - self._last_ms
        self._last_ms = now_ms
        if elapsed <= 0:
            return
        total_ms = self._leftover_ms + elapsed
        new_tokens, self._leftover_ms = divmod(
            total_ms * self._refill_per_second, 1000
        )
        self._tokens = min(self._capacity, self._tokens + new_tokens)

    def allow_request(self, now_ms: int) -> bool:
        """True when the request fits the rate; consumes one token."""
        self._advance(now_ms)
        if self._tokens >= 1:
            self._tokens -= 1
            return True
        return False

    def get_wait_time(self, now_ms: int) -> int:
        """Ms until the next request would be allowed (0 when allowed now)."""
        self._advance(now_ms)
        if self._tokens >= 1:
            return 0
        # ms needed to accumulate exactly one token from the leftover pool
        needed = (1000 - self._leftover_ms * self._refill_per_second)
        # ceil division by refill_per_second
        return (needed + self._refill_per_second - 1) // self._refill_per_second

    def decide(self, now_ms: int) -> LimitDecision:
        """Full verdict: refill, attempt the request, report wait time."""
        allowed = self.allow_request(now_ms)
        # wait until the NEXT request would be allowed, from current state
        if self._tokens >= 1:
            wait = 0
        else:
            needed = 1000 - self._leftover_ms * self._refill_per_second
            wait = (needed + self._refill_per_second - 1) // self._refill_per_second
        return LimitDecision(
            allowed=allowed,
            tokens_after=self._tokens,
            wait_ms=wait,
            now_ms=now_ms,
        )

    def reset(self) -> None:
        """Restore full capacity (host-initiated; does not rewind time)."""
        self._tokens = self._capacity
        self._leftover_ms = 0


def main() -> None:
    rl = RateLimiter(capacity=3, refill_per_second=1)
    # burst of 3 allowed
    results = [rl.allow_request(0) for _ in range(4)]
    assert results == [True, True, True, False], results
    # wait time says 1 second
    assert rl.get_wait_time(0) == 1000, rl.get_wait_time(0)
    # after 1s, one token is back
    assert rl.allow_request(1000) is True
    assert rl.version == "rate-limiter.v1"
    print("rate-limiter OK: burst capped, refill tracked, wait time exact")


if __name__ == "__main__":
    sys.exit(main())
