"""Token-bucket budget: rate-limited alternative to per-call ceilings.

The :mod:`per_call_budget` gate enforces *spending caps*: a call is refused
when its estimate exceeds a per-type ceiling or would push total run spend
over the max. That bounds cost but says nothing about *rate*: a run may
legitimately spend its whole budget in the first turn, hammering a provider
or a rate-limited API, and still be "within budget".

A token bucket bounds **rate**. Tokens refill over time (sequence ticks, no
wall-clock — the runtime house style), and every call consumes tokens equal
to its estimated cost. A burst is allowed up to the bucket's capacity, but
sustained high-rate spend drains the bucket and forces the caller to wait
for refill. This is the classic traffic-shaping primitive: it smooths
demand, absorbs legitimate bursts, and protects downstream systems from
spiky agents.

House style: no wall-clock (``seq`` is the caller-supplied integer tick),
frozen dataclasses where cheap, fail-closed (unknown call types and
malformed inputs raise rather than pass), deterministic.

Honest scope: this bounds *estimated* spend rate, not metered provider
invoices — estimates are estimates. A bucket that allows a call to proceed
does not promise the provider will charge what the estimate said. This is
a rate gate, not an accounting system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Mapping

#: Version pin for the bucket protocol described here.
TOKEN_BUCKET_VERSION = "token-bucket.v1"

#: Per-call-type bucket parameters: (capacity, refill_rate_per_seq).
#: Capacities allow bursts; refill rates cap sustained spend.
BUCKET_PARAMS: Dict[str, tuple[float, float]] = {
    "model": (1.0, 0.05),        # bursts of 1.0, ~0.05/seq sustained
    "tool": (0.10, 0.01),        # bursts of 0.10, ~0.01/seq sustained
    "memory_read": (0.05, 0.01),  # cheap ops: small bursts, fast refill
    "memory_write": (0.05, 0.005),
}

_CALL_TYPES = tuple(BUCKET_PARAMS)


class TokenBucketError(ValueError):
    """Raised for malformed bucket parameters or inputs."""


def _check_seq(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TokenBucketError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise TokenBucketError(f"{name} must be non-negative, got {value}")


def _check_cost(value: float, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TokenBucketError(f"{name} must be a number, got {type(value).__name__}")
    if value < 0:
        raise TokenBucketError(f"{name} must be non-negative, got {value}")


class TokenBucket:
    """A single token bucket: capacity-bounded burst with linear refill.

    ``capacity`` is the maximum tokens the bucket holds (burst allowance).
    ``refill_rate_per_seq`` is tokens added per sequence tick.
    ``last_refill_seq`` is the seq at which tokens were last recomputed.
    """

    def __init__(self, capacity: float, refill_rate_per_seq: float, *, start_seq: int = 0) -> None:
        _check_cost(capacity, "capacity")
        _check_cost(refill_rate_per_seq, "refill_rate_per_seq")
        if capacity <= 0:
            raise TokenBucketError(f"capacity must be positive, got {capacity}")
        _check_seq(start_seq, "start_seq")
        self._capacity = capacity
        self._rate = refill_rate_per_seq
        self._tokens = capacity  # buckets start full: first burst is allowed
        self._last_refill_seq = start_seq

    @property
    def capacity(self) -> float:
        return self._capacity

    @property
    def refill_rate_per_seq(self) -> float:
        return self._rate

    @property
    def tokens(self) -> float:
        return self._tokens

    def refill(self, current_seq: int) -> None:
        """Recompute tokens from seqs elapsed since last refill. Idempotent."""
        _check_seq(current_seq, "current_seq")
        if current_seq < self._last_refill_seq:
            raise TokenBucketError(
                f"current_seq {current_seq} is before last refill seq "
                f"{self._last_refill_seq}: seqs must not move backwards"
            )
        elapsed = current_seq - self._last_refill_seq
        if elapsed > 0:
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
            self._last_refill_seq = current_seq

    def consume(self, cost: float, current_seq: int) -> bool:
        """Try to consume ``cost`` tokens. Refills first, then spends.

        Returns True and deducts when tokens suffice; returns False and
        deducts nothing when they do not. Never raises for insufficient
        tokens — refusal is a normal control signal, not an error.
        """
        _check_cost(cost, "cost")
        self.refill(current_seq)
        if self._tokens + 1e-12 >= cost:
            self._tokens -= cost
            return True
        return False

    def time_until_available(self, cost: float, current_seq: int) -> int:
        """Seqs the caller must wait before ``cost`` tokens are available.

        Returns 0 when already available. Rounds up (ceil) since a
        fractional tick is not a tick. If the refill rate is zero and
        tokens are insufficient, returns a sentinel ``-1`` (never).
        """
        _check_cost(cost, "cost")
        self.refill(current_seq)
        if self._tokens + 1e-12 >= cost:
            return 0
        if self._rate <= 0:
            return -1
        deficit = cost - self._tokens
        import math

        return math.ceil(deficit / self._rate)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"TokenBucket(capacity={self._capacity}, rate={self._rate}, "
            f"tokens={self._tokens:.4f}, seq={self._last_refill_seq})"
        )


@dataclass
class BucketRejection:
    """Frozen record of a refused call."""

    call_type: str
    cost: float
    current_seq: int
    retry_in_seqs: int


class TokenBucketBudget:
    """Per-call-type token buckets: rate enforcement across a run.

    Each call type (model/tool/memory_read/memory_write) gets its own
    bucket so expensive model calls cannot starve cheap memory reads and
    vice versa. Rejections are recorded in an append-only log for audit.
    """

    def __init__(
        self,
        buckets: Mapping[str, TokenBucket] | None = None,
        *,
        start_seq: int = 0,
    ) -> None:
        _check_seq(start_seq, "start_seq")
        self._rejections: list[BucketRejection] = []
        if buckets is None:
            self._buckets: Dict[str, TokenBucket] = {
                ctype: TokenBucket(cap, rate, start_seq=start_seq)
                for ctype, (cap, rate) in BUCKET_PARAMS.items()
            }
        else:
            unknown = set(buckets) - set(_CALL_TYPES)
            if unknown:
                raise TokenBucketError(f"unknown call types: {sorted(unknown)}")
            self._buckets = dict(buckets)

    def check_and_consume(self, call_type: str, cost: float, current_seq: int) -> bool:
        """Consume ``cost`` from ``call_type``'s bucket. Returns True/False.

        Fail-closed: unknown call types raise :class:`TokenBucketError`
        rather than falling through to a default bucket.
        """
        if not isinstance(call_type, str) or call_type not in self._buckets:
            raise TokenBucketError(f"unknown call type: {call_type!r}")
        bucket = self._buckets[call_type]
        ok = bucket.consume(cost, current_seq)
        if not ok:
            retry_in = bucket.time_until_available(cost, current_seq)
            self._rejections.append(
                BucketRejection(call_type, cost, current_seq, retry_in)
            )
        return ok

    @property
    def rejections(self) -> tuple:
        return tuple(self._rejections)

    def tokens_for(self, call_type: str) -> float:
        if call_type not in self._buckets:
            raise TokenBucketError(f"unknown call type: {call_type!r}")
        return self._buckets[call_type].tokens

    def retry_in_seqs(self, call_type: str, cost: float, current_seq: int) -> int:
        if call_type not in self._buckets:
            raise TokenBucketError(f"unknown call type: {call_type!r}")
        return self._buckets[call_type].time_until_available(cost, current_seq)

    def as_dict(self) -> dict:
        return {
            "version": TOKEN_BUCKET_VERSION,
            "buckets": {
                ctype: {
                    "capacity": b.capacity,
                    "refill_rate_per_seq": b.refill_rate_per_seq,
                    "tokens": b.tokens,
                }
                for ctype, b in self._buckets.items()
            },
            "rejections": len(self._rejections),
        }


def main() -> None:
    budget = TokenBucketBudget()
    # Burst: model bucket starts full at 1.0
    assert budget.check_and_consume("model", 0.6, 0) is True
    assert budget.check_and_consume("model", 0.6, 0) is False  # only 0.4 left
    # Refill: 0.05/seq -> after 3 seqs, 0.15 more = 0.55 < 0.6, still refused
    assert budget.check_and_consume("model", 0.6, 3) is False
    wait = budget.retry_in_seqs("model", 0.6, 3)
    assert wait > 0
    assert budget.check_and_consume("model", 0.6, 3 + wait) is True
    print("token-bucket OK: burst, drain, refill, wait")


if __name__ == "__main__":
    main()
