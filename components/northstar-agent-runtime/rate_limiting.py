"""Keyed token-bucket quota ledger for multi-subject rate control.

A ``RateLimiting`` ledger manages one named bucket per subject (tenant, API
key, route): ``register()`` books the bucket, ``allow()`` spends tokens and
returns the verdict as data (never raised), ``refill()`` adds tokens back
explicitly up to capacity, and ``quota()`` is a pure read view of a bucket's
current state.

Deliberately distinct from ``rate_limiter``: that module is a *single* bucket
driven by caller-supplied wall-time-ish millisecond timestamps; this module
is a *keyed multi-bucket* ledger driven by caller-supplied strictly-increasing
integer seqs, with *explicit* refill instead of time-based accrual. Use this
one when the host books consumption itself and needs per-key accounting
(e.g. tenant quotas, per-route budgets); use ``rate_limiter`` when the
enforcement point observes real request times.

House style: frozen dataclasses, caller int seqs strictly increasing, no
wall-clock, RLock-guarded, fail-closed, stdlib-only, ``sha256:`` digest
pins, ``audit.ndjson/1`` events. Failed mutations consume their seq
(batch-21 discipline).

Honest scope: books *host-reported* consumption — a quiet bucket means "no
known over-quota shape", never "no abuse". Cannot observe calls the host
never reports.

Version pin: rate-limiting.v1
Schema pin: northstar.rate-limiting.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
RATE_LIMITING_VERSION = "rate-limiting.v1"

#: Schema pin carried by records and audit events.
RATE_LIMITING_SCHEMA = "northstar.rate-limiting.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class RateLimitingError(Exception):
    """Base error for the rate-limiting ledger."""


class BadBucketError(RateLimitingError):
    """Bucket definition (key/capacity) was malformed."""


class DuplicateBucketError(RateLimitingError):
    """A bucket with this key is already registered."""


class UnknownBucketError(RateLimitingError):
    """No bucket is registered under this key."""


class BadCostError(RateLimitingError):
    """Requested cost was not a positive int."""


class BadRefillError(RateLimitingError):
    """Refill amount was not a positive int."""


class SeqOrderError(RateLimitingError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadBucketError(f"{name} must be a non-empty string")
    return value.strip()


def _check_positive_int(value: Any, name: str, exc: type) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise exc(f"{name} must be a positive int")
    return value


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([RATE_LIMITING_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BucketRecord:
    """One registered bucket (frozen)."""

    key: str
    capacity: int
    seq: int
    digest: str
    schema: str = RATE_LIMITING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("bucket", self.key, self.capacity, self.seq)


@dataclass(frozen=True)
class Allowance:
    """One allow/deny verdict (frozen). ``allowed=False`` is data."""

    key: str
    cost: int
    allowed: bool
    tokens_after: int
    seq: int
    digest: str
    schema: str = RATE_LIMITING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "allow", self.key, self.cost, self.allowed, self.tokens_after,
            self.seq,
        )


@dataclass(frozen=True)
class RefillRecord:
    """One explicit refill (frozen)."""

    key: str
    amount: int
    tokens_after: int
    seq: int
    digest: str
    schema: str = RATE_LIMITING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "refill", self.key, self.amount, self.tokens_after, self.seq
        )


@dataclass(frozen=True)
class QuotaView:
    """Pure read view of a bucket's current quota state (frozen)."""

    key: str
    capacity: int
    tokens: int
    digest: str
    schema: str = RATE_LIMITING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "quota", self.key, self.capacity, self.tokens
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_REGISTERED = "rate-limiting.bucket-registered"
KIND_ALLOWED = "rate-limiting.allowed"
KIND_DENIED = "rate-limiting.denied"
KIND_REFILLED = "rate-limiting.refilled"
KIND_REJECTED = "rate-limiting.rejected"
_KINDS = (
    KIND_REGISTERED, KIND_ALLOWED, KIND_DENIED, KIND_REFILLED, KIND_REJECTED,
)


def rate_limiting_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the rate-limiting module."""
    if kind not in _KINDS:
        raise RateLimitingError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise RateLimitingError("detail must be a mapping")
    # Quota internals never cross the audit boundary; pins only.
    banned = {"tokens", "capacity", "cost", "amount"}
    if any(k in detail for k in banned):
        raise RateLimitingError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": RATE_LIMITING_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class RateLimiting:
    """Deterministic keyed token-bucket quota ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic logical
    time); no wall-clock is read anywhere. Failed mutations consume their
    seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._capacity: Dict[str, int] = {}
        self._tokens: Dict[str, int] = {}
        self._buckets: Dict[str, BucketRecord] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- internal helpers ---------------------------------------------------

    def _consume_seq(self, seq: int) -> None:
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq

    def _reject(self, seq: int, reason: str, **detail: Any) -> None:
        self._audit.append(
            rate_limiting_audit_event(
                KIND_REJECTED, {"reason": reason, **detail}, seq
            )
        )

    def _fail(self, seq: int, exc: Exception, reason: str,
              **detail: Any) -> Exception:
        """Consume seq, book the rejection, then hand back the error."""
        if seq > self._last_seq:
            self._last_seq = seq
        self._reject(seq, reason, **detail)
        return exc

    # -- mutations ----------------------------------------------------------

    def register(self, key: str, capacity: int, seq: int) -> BucketRecord:
        """Book a named bucket. Starts full (tokens == capacity)."""
        _check_seq(seq, "seq")
        with self._lock:
            try:
                key = _check_nonempty_str(key, "key")
                capacity = _check_positive_int(
                    capacity, "capacity", BadBucketError
                )
                if key in self._buckets:
                    raise DuplicateBucketError(
                        f"bucket already registered: {key!r}"
                    )
            except RateLimitingError as exc:
                raise self._fail(seq, exc, type(exc).__name__, key=key)
            self._consume_seq(seq)
            record = BucketRecord(
                key=key, capacity=capacity, seq=seq,
                digest=_pin("bucket", key, capacity, seq),
            )
            self._buckets[key] = record
            self._capacity[key] = capacity
            self._tokens[key] = capacity
            self._audit.append(
                rate_limiting_audit_event(
                    KIND_REGISTERED, {"key": key, "digest": record.digest}, seq
                )
            )
            return record

    def allow(self, key: str, cost: int, seq: int) -> Allowance:
        """Spend ``cost`` tokens. Denial is data, never raised."""
        _check_seq(seq, "seq")
        with self._lock:
            try:
                cost = _check_positive_int(cost, "cost", BadCostError)
                if not isinstance(key, str) or key not in self._buckets:
                    raise UnknownBucketError(f"unknown bucket: {key!r}")
            except RateLimitingError as exc:
                raise self._fail(seq, exc, type(exc).__name__)
            self._consume_seq(seq)
            remaining = self._tokens[key]
            allowed = remaining >= cost
            tokens_after = remaining - cost if allowed else remaining
            if allowed:
                self._tokens[key] = tokens_after
            record = Allowance(
                key=key, cost=cost, allowed=allowed,
                tokens_after=tokens_after, seq=seq,
                digest=_pin(
                    "allow", key, cost, allowed, tokens_after, seq
                ),
            )
            self._audit.append(
                rate_limiting_audit_event(
                    KIND_ALLOWED if allowed else KIND_DENIED,
                    {"key": key, "digest": record.digest}, seq,
                )
            )
            return record

    def refill(self, key: str, amount: int, seq: int) -> RefillRecord:
        """Add ``amount`` tokens, capped at capacity. Never raises for a
        full bucket — the refill is simply clamped (reported via
        ``tokens_after``)."""
        _check_seq(seq, "seq")
        with self._lock:
            try:
                amount = _check_positive_int(amount, "amount", BadRefillError)
                if not isinstance(key, str) or key not in self._buckets:
                    raise UnknownBucketError(f"unknown bucket: {key!r}")
            except RateLimitingError as exc:
                raise self._fail(seq, exc, type(exc).__name__)
            self._consume_seq(seq)
            tokens_after = min(self._capacity[key], self._tokens[key] + amount)
            self._tokens[key] = tokens_after
            record = RefillRecord(
                key=key, amount=amount, tokens_after=tokens_after, seq=seq,
                digest=_pin("refill", key, amount, tokens_after, seq),
            )
            self._audit.append(
                rate_limiting_audit_event(
                    KIND_REFILLED, {"key": key, "digest": record.digest}, seq
                )
            )
            return record

    # -- views --------------------------------------------------------------

    def quota(self, key: str) -> QuotaView:
        """Pure read view of a bucket's quota state. Consumes no seq."""
        with self._lock:
            if not isinstance(key, str) or key not in self._buckets:
                raise UnknownBucketError(f"unknown bucket: {key!r}")
            capacity = self._capacity[key]
            tokens = self._tokens[key]
            return QuotaView(
                key=key, capacity=capacity, tokens=tokens,
                digest=_pin("quota", key, capacity, tokens),
            )

    def bucket_record(self, key: str) -> BucketRecord:
        with self._lock:
            if not isinstance(key, str) or key not in self._buckets:
                raise UnknownBucketError(f"unknown bucket: {key!r}")
            return self._buckets[key]

    def bucket_keys(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._buckets))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(row) for row in self._audit)

    # -- misc ---------------------------------------------------------------

    @property
    def version(self) -> str:
        return RATE_LIMITING_VERSION

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"RateLimiting(buckets={len(self._buckets)})"


def main() -> None:
    ledger = RateLimiting()
    ledger.register("tenant-a", 10, 1)
    assert ledger.allow("tenant-a", 4, 2).allowed
    assert ledger.allow("tenant-a", 7, 3).allowed is False
    assert ledger.refill("tenant-a", 100, 4).tokens_after == 10
    assert ledger.quota("tenant-a").tokens == 10
    assert ledger.allow("tenant-a", 10, 5).verify()
    print("rate-limiting OK: register, allow, refill, quota, pins")


if __name__ == "__main__":
    main()
