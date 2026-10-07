"""PN counter — deterministic positive-negative counter bookkeeping (batch 34).

Research note (CRDT literature): the Positive-Negative Counter (Shapiro
et al. 2011, "Conflict-free Replicated Data Types") keeps two grow-only
counters — ``inc`` and ``dec`` — and reports ``value = inc - dec``. Because
both halves only ever grow, per-replica max-merge is commutative,
associative, and idempotent: any merge order converges to the same value,
even with decrements. It is the multi-writer counterpart to the
single-writer ledgers in :mod:`per_call_budget` / :mod:`dp_accountant`, and
fits per-agent spend ledgers, probe-hit counters, and per-skill invocation
tallies across unreliable links.

This module is the *single-host ledger* sibling of :mod:`crdt_interface`
(whose ``PNCounter`` is an immutable value object). The ledger holds
replica contribution maps in memory and books every advance/merge as a
frozen, digest-pinned record:

* **Per-replica maps** — each counter keeps ``inc_map`` / ``dec_map``
  (replica id → that replica's reported total, non-negative ints). Only
  reported totals advance; the host pins what replicas declare.
* **inc / dec** — advance this host's view of one replica's half-total by
  a positive delta (host-reported contributions, GIGO on the host).
* **merge** — accept a remote snapshot (two mappings), take the
  per-replica *maximum* on both halves, book the convergence as a frozen
  ``MergeRecord``. Any merge order converges; merging twice is a no-op.
* **value** — pure read view: ``sum(inc) - sum(dec)`` (validates seq
  shape, consumes nothing, writes no audit row).

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs (failed mutations consume their seq), RLock guarding,
fail-closed taxonomy, stdlib-only, sha256 digest pins over canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: merge is *convergent*, not *authenticated* — a Byzantine
replica can inflate its own entry and max-merge adopts it (inflation
detection is the :mod:`federated_attack_detector` layer's job). A value
means "every replica's reported contributions, max-per-replica", never
"the true count". The ledger holds state in memory; cross-restart
persistence is the host's job. Per-replica contribution maps never cross
the audit boundary (ids + net value + digest pins only).
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Tuple

#: Version pin for this module's record shape.
PN_COUNTER_VERSION = "pn-counter.v1"

#: Schema pin carried by records and audit events.
PN_COUNTER_SCHEMA = "northstar.pn-counter.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_CREATED = "pn-counter.created"
KIND_INCREMENTED = "pn-counter.incremented"
KIND_DECREMENTED = "pn-counter.decremented"
KIND_MERGED = "pn-counter.merged"
KIND_REJECTED = "pn-counter.rejected"
_KINDS = (KIND_CREATED, KIND_INCREMENTED, KIND_DECREMENTED, KIND_MERGED, KIND_REJECTED)

#: Max magnitude for any counter entry/delta — keeps canonical JSON
#: precision exact (|n| < 2**53).
_MAX_SAFE = 2 ** 53 - 1

_GENESIS = "genesis"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class PNCounterError(Exception):
    """Base error for the PN counter ledger."""


class BadCounterError(PNCounterError):
    """Malformed counter id or construction input."""


class DuplicateCounterError(PNCounterError):
    """Counter id already registered."""


class UnknownCounterError(PNCounterError):
    """No counter with this id is registered."""


class BadReplicaError(PNCounterError):
    """Malformed replica id or contribution map."""


class BadDeltaError(PNCounterError):
    """Malformed increment/decrement delta."""


class BadMergeError(PNCounterError):
    """Malformed remote snapshot for merge."""


class SeqOrderError(PNCounterError):
    """Caller seq did not strictly increase."""


class AuditKindError(PNCounterError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, compact separators, UTF-8."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    """``sha256:`` hex pin over the canonical encoding of the parts."""
    return "sha256:" + hashlib.sha256(_canonical(list(parts))).hexdigest()


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PNCounterError(
            f"{field_name} must be a non-negative int, saw {value!r}"
        )
    return value


def _check_counter_id(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadCounterError(f"counter_id must be a non-empty str, saw {value!r}")
    if len(value) > 256:
        raise BadCounterError("counter_id must be at most 256 chars")
    return value.strip()


def _check_replica_id(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadReplicaError(f"replica_id must be a non-empty str, saw {value!r}")
    if len(value) > 256:
        raise BadReplicaError("replica_id must be at most 256 chars")
    return value.strip()


def _check_delta(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadDeltaError(f"delta must be a positive int, saw {value!r}")
    if value <= 0:
        raise BadDeltaError(f"delta must be positive, saw {value}")
    if value > _MAX_SAFE:
        raise BadDeltaError(f"delta exceeds safe range, saw {value}")
    return value


def _check_total(value: Any, replica_id: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadMergeError(
            f"replica total must be a non-negative int, saw {value!r} for {replica_id!r}"
        )
    if value < 0 or value > _MAX_SAFE:
        raise BadMergeError(
            f"replica total out of range, saw {value!r} for {replica_id!r}"
        )
    return value


def _check_snapshot(value: Any, what: str) -> Dict[str, int]:
    """Normalize a remote contribution map to an id → total dict."""
    if not isinstance(value, Mapping):
        raise BadMergeError(f"{what} must be a mapping, saw {type(value).__name__}")
    out: Dict[str, int] = {}
    for rid, total in value.items():
        clean = _check_replica_id(rid)
        if clean in out:
            raise BadMergeError(f"duplicate replica id in {what}: {clean!r}")
        out[clean] = _check_total(total, clean)
    return out


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CounterRecord:
    """One registered PN counter (frozen)."""

    counter_id: str
    seq: int
    digest: str
    schema: str = PN_COUNTER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("create", PN_COUNTER_VERSION, self.counter_id, self.seq)


@dataclass(frozen=True)
class IncRecord:
    """One booked increment (frozen)."""

    record_id: str
    counter_id: str
    replica_id: str
    delta: int
    new_total: int
    seq: int
    prev_digest: str
    digest: str
    schema: str = PN_COUNTER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "inc",
            PN_COUNTER_VERSION,
            self.counter_id,
            self.replica_id,
            self.delta,
            self.new_total,
            self.seq,
            self.prev_digest,
        )


@dataclass(frozen=True)
class DecRecord:
    """One booked decrement (frozen)."""

    record_id: str
    counter_id: str
    replica_id: str
    delta: int
    new_total: int
    seq: int
    prev_digest: str
    digest: str
    schema: str = PN_COUNTER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "dec",
            PN_COUNTER_VERSION,
            self.counter_id,
            self.replica_id,
            self.delta,
            self.new_total,
            self.seq,
            self.prev_digest,
        )


@dataclass(frozen=True)
class MergeRecord:
    """One booked merge (frozen) — per-replica max on both halves."""

    record_id: str
    counter_id: str
    merged_replicas: Tuple[str, ...]
    inc_total: int
    dec_total: int
    value: int
    seq: int
    prev_digest: str
    digest: str
    schema: str = PN_COUNTER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "merge",
            PN_COUNTER_VERSION,
            self.counter_id,
            list(self.merged_replicas),
            self.inc_total,
            self.dec_total,
            self.value,
            self.seq,
            self.prev_digest,
        )


@dataclass(frozen=True)
class ValueReport:
    """Pure read view of a counter's net value (frozen)."""

    counter_id: str
    inc_total: int
    dec_total: int
    value: int
    replica_count: int
    seq: int
    digest: str
    schema: str = PN_COUNTER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "value",
            PN_COUNTER_VERSION,
            self.counter_id,
            self.inc_total,
            self.dec_total,
            self.value,
            self.replica_count,
            self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def pn_counter_audit_event(kind: str, seq: int, **detail: Any) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the PN counter ledger.

    Detail carries ids + net values + digest pins only — per-replica
    contribution maps never cross the audit boundary.
    """
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    banned = {"inc_map", "dec_map", "remote_inc", "remote_dec", "contributions"}
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "pn_counter",
        "module_version": PN_COUNTER_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class _CounterState:
    """Mutable per-counter state (ledger-internal, never leaves the lock)."""

    __slots__ = ("counter_id", "inc_map", "dec_map", "head_digest", "record_seq")

    def __init__(self, counter_id: str) -> None:
        self.counter_id = counter_id
        self.inc_map: Dict[str, int] = {}
        self.dec_map: Dict[str, int] = {}
        self.head_digest = _pin("create", PN_COUNTER_VERSION, counter_id, 0)
        self.record_seq = 0


class PNCounter:
    """Deterministic PN-counter ledger for multiple named counters.

    Each counter tracks two per-replica contribution maps (``inc`` and
    ``dec``); ``value = sum(inc) - sum(dec)``. ``inc``/``dec`` advance one
    replica's half-total; ``merge`` folds a remote snapshot in with a
    per-replica maximum on both halves — commutative, associative, and
    idempotent, so any merge order converges.

    All mutations take a caller-supplied ``seq`` that must strictly
    increase across the whole ledger; failed mutations consume their seq
    (fail-closed ledger position). ``value`` is a pure read view.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._counters: Dict[str, _CounterState] = {}
        self._audit: list[Mapping[str, Any]] = []
        self._record_ids = 0

    # -- internal ----------------------------------------------------

    def _claim(self, seq: int) -> None:
        """Validate seq strictly increases; a refused mutation still
        consumes its seq, keeping the ledger totally ordered."""
        _check_seq(seq, "seq")
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._seq}, saw={seq})"
            )
        self._seq = seq

    def _emit_locked(self, kind: str, seq: int, **detail: Any) -> Mapping[str, Any]:
        event = pn_counter_audit_event(kind, seq, **detail)
        self._audit.append(event)
        return event

    def _reject_locked(self, seq: int, reason: str) -> None:
        self._emit_locked(KIND_REJECTED, seq, reason=reason)

    def _next_id(self, prefix: str) -> str:
        self._record_ids += 1
        return f"{prefix}-{self._record_ids}"

    def _state(self, counter_id: str) -> _CounterState:
        state = self._counters.get(counter_id)
        if state is None:
            raise UnknownCounterError(f"unknown counter: {counter_id!r}")
        return state

    def _guarded(self, seq: int, fn, *args):
        """Run a mutation body; emit one ``rejected`` audit row on any
        fail-closed refusal, then re-raise. Seq violations from ``_claim``
        are raised outside this guard (no double audit)."""
        try:
            return fn(*args)
        except PNCounterError as exc:
            self._reject_locked(seq, reason=type(exc).__name__)
            raise

    # -- mutations ---------------------------------------------------

    def create(self, counter_id: str, seq: int) -> CounterRecord:
        """Register a new PN counter."""
        with self._lock:
            self._claim(seq)
            return self._guarded(seq, self._create_locked, counter_id, seq)

    def _create_locked(self, counter_id: str, seq: int) -> CounterRecord:
        clean = _check_counter_id(counter_id)
        if clean in self._counters:
            raise DuplicateCounterError(f"counter already exists: {clean!r}")
        self._counters[clean] = _CounterState(clean)
        record = CounterRecord(
            counter_id=clean,
            seq=seq,
            digest=_pin("create", PN_COUNTER_VERSION, clean, seq),
        )
        self._emit_locked(
            KIND_CREATED,
            seq,
            counter_id=clean,
            digest=record.digest,
        )
        return record

    def inc(self, counter_id: str, replica_id: str, n: int, seq: int) -> IncRecord:
        """Book an increment: advance one replica's inc half-total by ``n``."""
        with self._lock:
            self._claim(seq)
            return self._guarded(seq, self._inc_locked, counter_id, replica_id, n, seq)

    def _inc_locked(
        self, counter_id: str, replica_id: str, n: int, seq: int
    ) -> IncRecord:
        clean = _check_counter_id(counter_id)
        rid = _check_replica_id(replica_id)
        delta = _check_delta(n)
        state = self._state(clean)
        new_total = state.inc_map.get(rid, 0) + delta
        if new_total > _MAX_SAFE:
            raise BadDeltaError(f"inc total would exceed safe range for {rid!r}")
        state.inc_map[rid] = new_total
        record = IncRecord(
            record_id=self._next_id("inc"),
            counter_id=clean,
            replica_id=rid,
            delta=delta,
            new_total=new_total,
            seq=seq,
            prev_digest=state.head_digest,
            digest=_pin(
                "inc", PN_COUNTER_VERSION, clean, rid, delta, new_total,
                seq, state.head_digest,
            ),
        )
        state.head_digest = record.digest
        self._emit_locked(
            KIND_INCREMENTED,
            seq,
            counter_id=clean,
            replica_id=rid,
            delta=delta,
            new_total=new_total,
            digest=record.digest,
        )
        return record

    def dec(self, counter_id: str, replica_id: str, n: int, seq: int) -> DecRecord:
        """Book a decrement: advance one replica's dec half-total by ``n``."""
        with self._lock:
            self._claim(seq)
            return self._guarded(seq, self._dec_locked, counter_id, replica_id, n, seq)

    def _dec_locked(
        self, counter_id: str, replica_id: str, n: int, seq: int
    ) -> DecRecord:
        clean = _check_counter_id(counter_id)
        rid = _check_replica_id(replica_id)
        delta = _check_delta(n)
        state = self._state(clean)
        new_total = state.dec_map.get(rid, 0) + delta
        if new_total > _MAX_SAFE:
            raise BadDeltaError(f"dec total would exceed safe range for {rid!r}")
        state.dec_map[rid] = new_total
        record = DecRecord(
            record_id=self._next_id("dec"),
            counter_id=clean,
            replica_id=rid,
            delta=delta,
            new_total=new_total,
            seq=seq,
            prev_digest=state.head_digest,
            digest=_pin(
                "dec", PN_COUNTER_VERSION, clean, rid, delta, new_total,
                seq, state.head_digest,
            ),
        )
        state.head_digest = record.digest
        self._emit_locked(
            KIND_DECREMENTED,
            seq,
            counter_id=clean,
            replica_id=rid,
            delta=delta,
            new_total=new_total,
            digest=record.digest,
        )
        return record

    def merge(
        self,
        counter_id: str,
        remote_inc: Mapping[str, int],
        remote_dec: Mapping[str, int],
        seq: int,
    ) -> MergeRecord:
        """Merge a remote snapshot: per-replica max on both halves.

        ``remote_inc`` / ``remote_dec`` map replica id → that replica's
        reported half-total. Convergence is order-independent and merging
        the same snapshot twice is a no-op (idempotent).
        """
        with self._lock:
            self._claim(seq)
            return self._guarded(
                seq, self._merge_locked, counter_id, remote_inc, remote_dec, seq
            )

    def _merge_locked(
        self,
        counter_id: str,
        remote_inc: Mapping[str, int],
        remote_dec: Mapping[str, int],
        seq: int,
    ) -> MergeRecord:
        clean = _check_counter_id(counter_id)
        r_inc = _check_snapshot(remote_inc, "remote_inc")
        r_dec = _check_snapshot(remote_dec, "remote_dec")
        state = self._state(clean)
        for rid, total in r_inc.items():
            if total > state.inc_map.get(rid, 0):
                state.inc_map[rid] = total
        for rid, total in r_dec.items():
            if total > state.dec_map.get(rid, 0):
                state.dec_map[rid] = total
        inc_total = sum(state.inc_map.values())
        dec_total = sum(state.dec_map.values())
        value = inc_total - dec_total
        replicas = tuple(sorted(set(state.inc_map) | set(state.dec_map)))
        record = MergeRecord(
            record_id=self._next_id("mrg"),
            counter_id=clean,
            merged_replicas=replicas,
            inc_total=inc_total,
            dec_total=dec_total,
            value=value,
            seq=seq,
            prev_digest=state.head_digest,
            digest=_pin(
                "merge", PN_COUNTER_VERSION, clean, list(replicas),
                inc_total, dec_total, value, seq, state.head_digest,
            ),
        )
        state.head_digest = record.digest
        self._emit_locked(
            KIND_MERGED,
            seq,
            counter_id=clean,
            replicas=list(replicas),
            value=value,
            digest=record.digest,
        )
        return record

    # -- views -------------------------------------------------------

    def value(self, counter_id: str, seq: int) -> ValueReport:
        """Pure read view of a counter's net value (consumes no seq)."""
        _check_seq(seq, "seq")
        with self._lock:
            clean = _check_counter_id(counter_id)
            state = self._state(clean)
            inc_total = sum(state.inc_map.values())
            dec_total = sum(state.dec_map.values())
            report = ValueReport(
                counter_id=clean,
                inc_total=inc_total,
                dec_total=dec_total,
                value=inc_total - dec_total,
                replica_count=len(set(state.inc_map) | set(state.dec_map)),
                seq=seq,
                digest=_pin(
                    "value", PN_COUNTER_VERSION, clean, inc_total, dec_total,
                    inc_total - dec_total,
                    len(set(state.inc_map) | set(state.dec_map)), seq,
                ),
            )
            return report

    def counter_ids(self) -> Tuple[str, ...]:
        """Sorted registered counter ids."""
        with self._lock:
            return tuple(sorted(self._counters))

    def contributions(
        self, counter_id: str, seq: int
    ) -> Tuple[Tuple[str, int], Tuple[str, int]]:
        """Host-only view of per-replica maps (never audited).

        Returns ``(inc_items, dec_items)`` as sorted tuples — the shape a
        ``merge`` call accepts for a remote snapshot.
        """
        _check_seq(seq, "seq")
        with self._lock:
            clean = _check_counter_id(counter_id)
            state = self._state(clean)
            inc_items = tuple(sorted(state.inc_map.items()))
            dec_items = tuple(sorted(state.dec_map.items()))
            return inc_items, dec_items

    def audit_log(self) -> Tuple[Mapping[str, Any], ...]:
        """Append-only audit events (ids + pins only)."""
        with self._lock:
            return tuple(self._audit)

    def as_dict(self) -> Dict[str, Any]:
        """JSON-safe snapshot of the ledger."""
        with self._lock:
            counters = {}
            for cid, state in sorted(self._counters.items()):
                counters[cid] = {
                    "replica_count": len(set(state.inc_map) | set(state.dec_map)),
                    "inc_total": sum(state.inc_map.values()),
                    "dec_total": sum(state.dec_map.values()),
                    "value": sum(state.inc_map.values()) - sum(state.dec_map.values()),
                    "head_digest": state.head_digest,
                }
            return {
                "schema": PN_COUNTER_SCHEMA,
                "module": "pn_counter",
                "module_version": PN_COUNTER_VERSION,
                "counters": counters,
                "audit_events": len(self._audit),
            }


def main() -> None:
    """Self-check: increments, decrements, and order-independent merges."""
    pn = PNCounter()
    pn.create("hits", seq=1)
    pn.inc("hits", "a", 10, seq=2)
    pn.dec("hits", "a", 4, seq=3)
    assert pn.value("hits", seq=0).value == 6

    # Two hosts advance independently, then merge in either order.
    left = PNCounter()
    left.create("c", seq=1)
    left.inc("c", "a", 10, seq=2)
    left.dec("c", "a", 4, seq=3)
    right = PNCounter()
    right.create("c", seq=1)
    right.inc("c", "b", 7, seq=2)
    right.dec("c", "b", 2, seq=3)

    li, ld = left.contributions("c", seq=0)
    ri, rd = right.contributions("c", seq=0)
    m1 = left.merge("c", dict(ri), dict(rd), seq=4)
    m2 = right.merge("c", dict(li), dict(ld), seq=4)
    assert m1.value == m2.value == (10 + 7) - (4 + 2) == 11
    assert m1.verify() and m2.verify()

    # Idempotence: merging the same snapshot twice changes nothing.
    before = left.value("c", seq=0).value
    left.merge("c", dict(ri), dict(rd), seq=5)
    assert left.value("c", seq=0).value == before

    # Refusals: failed mutations consume their seq.
    try:
        pn.inc("hits", "a", -1, seq=4)
    except BadDeltaError:
        pass
    else:
        raise AssertionError("negative delta accepted")
    try:
        pn.inc("hits", "a", 1, seq=4)  # seq 4 burned by the refusal
    except SeqOrderError:
        pass
    else:
        raise AssertionError("burned seq reused")

    ev = pn_counter_audit_event(KIND_MERGED, seq=9, counter_id="c", value=11)
    assert ev["schema"] == AUDIT_SCHEMA and ev["seq"] == 9

    print("pn-counter OK: create, inc, dec, merge, convergence, pins, audit")


if __name__ == "__main__":
    main()
