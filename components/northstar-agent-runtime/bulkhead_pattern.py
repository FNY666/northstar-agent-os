"""Bulkhead pattern — isolation-compartment bookkeeping (resilience thirty-second batch).

Research note (resilience literature): Michael Nygard's "Release It!"
and the Polly .NET resilience library model the *bulkhead pattern*
as the compartmentalization of a shared resource pool into
per-tenant (or per-dependency) partitions. Each partition owns a
capped number of concurrent execution slots; when one partition's
downstream saturates, its callers queue or fail *inside their own
compartment* instead of consuming the whole pool, so a single
failing dependency cannot cascade into total exhaustion. This module
takes the intersection for a single-host deterministic ledger:

* **Isolate**: ``isolate`` books a named compartment with a pinned
  ``capacity`` (max concurrent holders). Compartments never share
  capacity — saturation of one is invisible to the others.
* **Limit as data**: ``limit`` attempts one slot acquisition for a
  ``request_id`` and returns the verdict (``granted``/``rejected``)
  as *data* in a frozen record, never as an exception. Rejections
  are ledger facts, not failures.
* **Release**: ``release`` frees a granted slot; the slot becomes
  bookable again immediately.
* **Monitor**: ``monitor`` is a pure read view over every
  compartment — capacity, in-flight, granted/rejected totals, and
  exact utilization — with no seq consumption and no audit row.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs on mutations (failed mutations consume their seq;
bool/negative/rewind refused), RLock-guarded, fail-closed taxonomy,
stdlib-only (``canonical_json`` sibling helper behind the standard
try/except fallback), sha256 digest pins over type-tagged canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *declared* admission decisions
deterministically. It executes no work, spawns no threads, and
cannot prove a downstream is saturated — the host declares every
acquire/release. A ``granted`` record means "this ledger had a free
slot", never "the call succeeded". Pair with real concurrency
primitives and per-dependency timeouts for production.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Mapping

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
BULKHEAD_PATTERN_VERSION = "bulkhead-pattern.v1"

#: Schema pin carried by records and audit events.
BULKHEAD_PATTERN_SCHEMA = "northstar.bulkhead-pattern.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Admission verdicts (computed data).
VERDICT_GRANTED = "granted"
VERDICT_REJECTED = "rejected"
ADMISSION_VERDICTS = (VERDICT_GRANTED, VERDICT_REJECTED)

#: Rejection reasons (pinned vocabulary).
REASON_FULL = "capacity-full"
REJECTION_REASONS = (REASON_FULL,)

#: Audit event kinds.
KIND_ISOLATED = "bulkhead.isolated"
KIND_ADMITTED = "bulkhead.admitted"
KIND_RELEASED = "bulkhead.released"
KIND_REJECTED = "bulkhead.rejected"
_KINDS = (KIND_ISOLATED, KIND_ADMITTED, KIND_RELEASED, KIND_REJECTED)

_DIGEST_PREFIX = "sha256:"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class BulkheadError(ValueError):
    """Base error for the bulkhead pattern."""


class BadBulkheadError(BulkheadError):
    """Malformed compartment definition (bad id, capacity)."""


class DuplicateBulkheadError(BulkheadError):
    """A compartment with this id already exists."""


class UnknownBulkheadError(BulkheadError):
    """No compartment with this id exists."""


class DuplicateRequestError(BulkheadError):
    """A request with this id is already admitted or was recorded."""


class UnknownRequestError(BulkheadError):
    """No live granted request with this id exists."""


class BadAdmissionError(BulkheadError):
    """Malformed admission request (bad request id)."""


class SeqOrderError(BulkheadError):
    """Seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BulkheadError(f"{field_name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BulkheadError(f"{field_name} must be a non-empty string")
    return value


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
    import json

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) >= 2**53:
                raise BulkheadError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise BulkheadError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise BulkheadError(f"unencodable type: {type(v).__name__}")

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(payload: Any, seed: str = "") -> str:
    return _DIGEST_PREFIX + hmac.new(
        seed.encode("utf-8"), _canonical(payload), hashlib.sha256
    ).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BulkheadRecord:
    """A pinned isolation compartment."""

    bulkhead_id: str
    capacity: int
    seq_created: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                ["bulkhead", self.bulkhead_id, self.capacity, self.seq_created],
                seed,
            ),
        )


@dataclass(frozen=True)
class AdmissionRecord:
    """One slot-acquisition attempt; the verdict is data."""

    request_id: str
    bulkhead_id: str
    verdict: str
    reason: str
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "admission",
                    self.request_id,
                    self.bulkhead_id,
                    self.verdict,
                    self.reason,
                    self.seq,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class ReleaseRecord:
    """One granted slot released back to its compartment."""

    request_id: str
    bulkhead_id: str
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(["release", self.request_id, self.bulkhead_id, self.seq], seed),
        )


@dataclass(frozen=True)
class CompartmentView:
    """One compartment's utilization snapshot (monitor data)."""

    bulkhead_id: str
    capacity: int
    in_flight: int
    granted_total: int
    rejected_total: int
    utilization: str  # exact "in_flight/capacity" text; never floats


@dataclass(frozen=True)
class BulkheadReport:
    """A whole-ledger utilization snapshot (pure read view)."""

    seq_viewed: int
    compartments: tuple
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "bulkhead-report",
                    self.seq_viewed,
                    [
                        [c.bulkhead_id, c.capacity, c.in_flight, c.granted_total,
                         c.rejected_total, c.utilization]
                        for c in self.compartments
                    ],
                ],
                seed,
            ),
        )


def bulkhead_pattern_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the bulkhead pattern."""
    if kind not in _KINDS:
        raise BulkheadError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "bulkhead_pattern",
        "module_version": BULKHEAD_PATTERN_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# BulkheadPattern
# ---------------------------------------------------------------------------


class BulkheadPattern:
    """Deterministic bulkhead isolation bookkeeping.

    All mutations require a caller-supplied strictly increasing ``seq``.
    Failed mutations consume their seq (ledger position stays total).
    ``monitor`` is a pure read view: it validates the seq shape but does
    not consume it and writes no audit row.
    """

    def __init__(self, seed: str = "") -> None:
        self._lock = threading.RLock()
        self._seed = seed
        self._last_seq = -1
        self._bulkheads: dict[str, BulkheadRecord] = {}
        self._capacity: dict[str, int] = {}
        self._live: dict[str, str] = {}  # request_id -> bulkhead_id
        self._granted: dict[str, int] = {}
        self._rejected: dict[str, int] = {}
        self._admissions: dict[str, AdmissionRecord] = {}
        self._releases: dict[str, ReleaseRecord] = {}
        self._audit_log: list[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(bulkhead_pattern_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, reason: str) -> None:
        # Seq already consumed by _next_seq; only book the refusal.
        self._emit(KIND_REJECTED, seq, reason=reason)

    # -- compartments ----------------------------------------------------

    def isolate(self, bulkhead_id: str, capacity: int, seq: int) -> BulkheadRecord:
        """Book a named isolation compartment with pinned capacity."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                bulkhead_id = _check_nonempty_str(bulkhead_id, "bulkhead_id")
                if (
                    isinstance(capacity, bool)
                    or not isinstance(capacity, int)
                    or capacity <= 0
                    or capacity >= 2**53
                ):
                    raise BadBulkheadError("capacity must be a positive int")
                if bulkhead_id in self._bulkheads:
                    raise DuplicateBulkheadError(
                        f"bulkhead already isolated: {bulkhead_id!r}"
                    )
            except BulkheadError as exc:
                self._reject(seq, str(exc))
                raise
            digest = _pin(
                ["bulkhead", bulkhead_id, capacity, seq], self._seed
            )
            record = BulkheadRecord(
                bulkhead_id=bulkhead_id,
                capacity=capacity,
                seq_created=seq,
                digest=digest,
            )
            self._bulkheads[bulkhead_id] = record
            self._capacity[bulkhead_id] = capacity
            self._granted[bulkhead_id] = 0
            self._rejected[bulkhead_id] = 0
            self._emit(
                KIND_ISOLATED,
                seq,
                bulkhead_id=bulkhead_id,
                capacity=capacity,
                digest=digest,
            )
            return record

    # -- admission ---------------------------------------------------------

    def limit(self, bulkhead_id: str, request_id: str, seq: int) -> AdmissionRecord:
        """Attempt one slot acquisition; the verdict is returned as data.

        ``granted`` requests occupy a slot until ``release``. ``rejected``
        requests are ledger facts (capacity full), never exceptions.
        """
        seq = self._next_seq(seq)
        with self._lock:
            try:
                if bulkhead_id not in self._bulkheads:
                    raise UnknownBulkheadError(f"unknown bulkhead: {bulkhead_id!r}")
                request_id = _check_nonempty_str(request_id, "request_id")
                if request_id in self._admissions:
                    raise DuplicateRequestError(
                        f"request already recorded: {request_id!r}"
                    )
            except BulkheadError as exc:
                self._reject(seq, str(exc))
                raise
            in_flight = sum(
                1 for rid, bid in self._live.items() if bid == bulkhead_id
            )
            if in_flight < self._capacity[bulkhead_id]:
                verdict, reason = VERDICT_GRANTED, ""
                self._live[request_id] = bulkhead_id
                self._granted[bulkhead_id] += 1
            else:
                verdict, reason = VERDICT_REJECTED, REASON_FULL
                self._rejected[bulkhead_id] += 1
            digest = _pin(
                ["admission", request_id, bulkhead_id, verdict, reason, seq],
                self._seed,
            )
            record = AdmissionRecord(
                request_id=request_id,
                bulkhead_id=bulkhead_id,
                verdict=verdict,
                reason=reason,
                seq=seq,
                digest=digest,
            )
            self._admissions[request_id] = record
            self._emit(
                KIND_ADMITTED,
                seq,
                request_id=request_id,
                bulkhead_id=bulkhead_id,
                verdict=verdict,
                reason=reason,
                digest=digest,
            )
            return record

    def release(self, request_id: str, seq: int) -> ReleaseRecord:
        """Free a granted slot back to its compartment."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                request_id = _check_nonempty_str(request_id, "request_id")
                if request_id not in self._live:
                    raise UnknownRequestError(
                        f"no live granted request: {request_id!r}"
                    )
            except BulkheadError as exc:
                self._reject(seq, str(exc))
                raise
            bulkhead_id = self._live.pop(request_id)
            digest = _pin(
                ["release", request_id, bulkhead_id, seq], self._seed
            )
            record = ReleaseRecord(
                request_id=request_id,
                bulkhead_id=bulkhead_id,
                seq=seq,
                digest=digest,
            )
            self._releases[request_id] = record
            self._emit(
                KIND_RELEASED,
                seq,
                request_id=request_id,
                bulkhead_id=bulkhead_id,
                digest=digest,
            )
            return record

    # -- views ---------------------------------------------------------------

    def monitor(self, seq: int) -> BulkheadReport:
        """Pure utilization snapshot over every compartment.

        Validates the seq shape, consumes nothing, writes no audit row.
        """
        _check_seq(seq, "seq")
        with self._lock:
            views: list[CompartmentView] = []
            for bulkhead_id in sorted(self._bulkheads):
                in_flight = sum(
                    1 for bid in self._live.values() if bid == bulkhead_id
                )
                capacity = self._capacity[bulkhead_id]
                views.append(
                    CompartmentView(
                        bulkhead_id=bulkhead_id,
                        capacity=capacity,
                        in_flight=in_flight,
                        granted_total=self._granted[bulkhead_id],
                        rejected_total=self._rejected[bulkhead_id],
                        utilization=f"{in_flight}/{capacity}",
                    )
                )
            report = BulkheadReport(
                seq_viewed=seq,
                compartments=tuple(views),
                digest=_pin(
                    [
                        "bulkhead-report",
                        seq,
                        [
                            [c.bulkhead_id, c.capacity, c.in_flight,
                             c.granted_total, c.rejected_total, c.utilization]
                            for c in views
                        ],
                    ],
                    self._seed,
                ),
            )
            return report

    def bulkhead(self, bulkhead_id: str) -> BulkheadRecord:
        """Return a compartment record (unknown ids raise)."""
        with self._lock:
            if bulkhead_id not in self._bulkheads:
                raise UnknownBulkheadError(f"unknown bulkhead: {bulkhead_id!r}")
            return self._bulkheads[bulkhead_id]

    def bulkhead_ids(self) -> tuple:
        """Sorted compartment ids."""
        with self._lock:
            return tuple(sorted(self._bulkheads))

    def admission(self, request_id: str) -> AdmissionRecord:
        """Return an admission record (unknown ids raise)."""
        with self._lock:
            if request_id not in self._admissions:
                raise UnknownRequestError(f"unknown request: {request_id!r}")
            return self._admissions[request_id]

    def stats(self) -> Mapping[str, int]:
        """Ledger counters (bulkheads, live, granted, rejected)."""
        with self._lock:
            return {
                "bulkheads": len(self._bulkheads),
                "live": len(self._live),
                "granted_total": sum(self._granted.values()),
                "rejected_total": sum(self._rejected.values()),
            }

    def audit_log(self) -> tuple:
        """Sealed audit events."""
        with self._lock:
            return tuple(self._audit_log)


def main() -> None:
    """Self-check: isolate, limit, release, monitor, audit pins."""
    bp = BulkheadPattern()
    bp.isolate("payments", 2, seq=1)
    g1 = bp.limit("payments", "req-1", seq=2)
    g2 = bp.limit("payments", "req-2", seq=3)
    r = bp.limit("payments", "req-3", seq=4)
    assert g1.verdict == VERDICT_GRANTED
    assert g2.verdict == VERDICT_GRANTED
    assert r.verdict == VERDICT_REJECTED and r.reason == REASON_FULL
    bp.release("req-1", seq=5)
    g4 = bp.limit("payments", "req-4", seq=6)
    assert g4.verdict == VERDICT_GRANTED
    report = bp.monitor(seq=6)
    assert report.compartments[0].utilization == "2/2"
    assert report.verify()
    kinds = {e["kind"] for e in bp.audit_log()}
    assert KIND_ISOLATED in kinds and KIND_ADMITTED in kinds
    print("bulkhead-pattern OK: isolate, limit, release, monitor, pins, audit")


if __name__ == "__main__":
    main()
