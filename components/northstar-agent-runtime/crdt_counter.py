"""CRDT counter — state-based PN-counter bookkeeping (thirty-sixth batch).

Research note (CRDT literature): Shapiro, Preguica, Baquero & Zawirski,
"A comprehensive study of Convergent and Commutative Replicated Data
Types" (2011), defines the state-based PN-counter as a pair of
G-counters ``(P, N)`` where ``P`` and ``N`` are per-replica maps of
non-negative ints. The value is ``sum(P) - sum(N)``; the join is the
pointwise max over both maps, which is commutative, associative, and
idempotent — so replicas converge regardless of merge order. Riak and
AntidoteDB ship PN-counters this way; this module takes the
single-host deterministic intersection:

* **G-counter growth**: ``increment`` raises only the caller's own
  replica entry in ``P``. Per-replica entries never decrease.
* **Decrement as negative growth**: ``decrement`` raises only the
  caller's own replica entry in ``N`` — never a borrow against
  someone else's increments.
* **Convergent merge**: ``merge`` takes a remote ``{"pos": {...},
  "neg": {...}}`` state and applies the pointwise-max join. Merges
  commute and are idempotent: ``merge(a, b) == merge(b, a)`` and
  ``merge(x, x) == x`` as values.
* **Deterministic state shipping**: ``state`` returns the frozen
  per-replica maps so a host can gossip them between replicas.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs (failed mutations consume their seq), RLock guarding,
fail-closed taxonomy, stdlib-only, sha256 digest pins over canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *counter decisions*
deterministically on one host. It cannot observe the wire, prove a
remote state was honestly constructed, or deliver gossip — a consumer
wires the frozen state snapshots to its own replication transport.
Remote states are GIGO: the ledger pins what the host declares and
validates the *shape*, not the provenance.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Mapping

#: Version pin for this module's record shape.
CRDT_COUNTER_VERSION = "crdt-counter.v1"

#: Schema pin carried by records and audit events.
CRDT_COUNTER_SCHEMA = "northstar.crdt-counter.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_COUNTER_REGISTERED = "counter.registered"
KIND_INCREMENTED = "counter.incremented"
KIND_DECREMENTED = "counter.decremented"
KIND_MERGED = "counter.merged"
KIND_REJECTED = "counter.rejected"
_KINDS = (
    KIND_COUNTER_REGISTERED,
    KIND_INCREMENTED,
    KIND_DECREMENTED,
    KIND_MERGED,
    KIND_REJECTED,
)

_GENESIS = "genesis"
_DIGEST_PREFIX = "sha256:"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CRDTCounterError(ValueError):
    """Base error for the CRDT counter manager."""


class BadCounterError(CRDTCounterError):
    """Malformed counter id, replica id, or amount."""


class DuplicateCounterError(CRDTCounterError):
    """This counter id is already registered."""


class UnknownCounterError(CRDTCounterError):
    """No counter with this id is registered."""


class BadStateError(CRDTCounterError):
    """Remote state is malformed for the pointwise-max join."""


class SeqOrderError(CRDTCounterError):
    """Mutation seq is not strictly increasing."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CRDTCounterError(
            f"{field_name} must be a non-negative int, saw {value!r}"
        )
    return value


def _check_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadCounterError(f"{field_name} must be a non-empty string")
    return value.strip()


def _check_amount(value: Any, field_name: str = "amount") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise BadCounterError(f"{field_name} must be an int >= 1, saw {value!r}")
    return value


def _check_count(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BadStateError(f"{field_name} must be a non-negative int, saw {value!r}")
    return value


def _check_state_vector(value: Any, field_name: str) -> tuple:
    """Validate one side (pos/neg) of a remote state: str -> non-neg int."""
    if not isinstance(value, Mapping):
        raise BadStateError(f"{field_name} must be a mapping, saw {value!r}")
    items = []
    for replica, count in value.items():
        if not isinstance(replica, str) or not replica.strip():
            raise BadStateError(
                f"{field_name} keys must be non-empty strings, saw {replica!r}"
            )
        items.append((replica.strip(), _check_count(count, f"{field_name}[{replica!r}]")))
    return tuple(sorted(items))


def _check_remote_state(value: Any) -> tuple[tuple, tuple]:
    """Validate a full remote state mapping into (pos, neg) pair-tuples."""
    if not isinstance(value, Mapping):
        raise BadStateError(f"remote_state must be a mapping, saw {value!r}")
    if set(value.keys()) != {"pos", "neg"}:
        raise BadStateError(
            "remote_state must have exactly the keys {'pos', 'neg'}, "
            f"saw {sorted(value.keys())!r}"
        )
    return (
        _check_state_vector(value["pos"], "pos"),
        _check_state_vector(value["neg"], "neg"),
    )


# ---------------------------------------------------------------------------
# Canonical digest helpers
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    # Payloads are str/int/bool/None/dict/list/tuple only — no floats,
    # so no >2^53 precision hazard; ints serialize exactly.
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    """sha256 hex pin over the canonical encoding of the parts."""
    return hashlib.sha256(_canonical(list(parts))).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CounterRecord:
    """One registered counter with its initial (empty) state.

    ``pos``/``neg`` are sorted ``((replica, count), ...)`` tuples —
    the frozen, hashable form of the per-replica G-counter maps.
    """

    counter_id: str
    pos: tuple
    neg: tuple
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_id(self.counter_id, "counter_id")
        for name, vector in (("pos", self.pos), ("neg", self.neg)):
            if not isinstance(vector, tuple):
                raise BadCounterError(f"{name} must be a tuple")
            for replica, count in vector:
                if not isinstance(replica, str) or not replica:
                    raise BadCounterError(f"{name} replica must be a non-empty str")
                _check_count(count, f"{name}[{replica!r}]")
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            CRDT_COUNTER_VERSION,
            "counter",
            self.counter_id,
            [list(pair) for pair in self.pos],
            [list(pair) for pair in self.neg],
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()

    def value(self) -> int:
        """Current counter value: sum(pos) - sum(neg)."""
        return sum(count for _, count in self.pos) - sum(
            count for _, count in self.neg
        )


@dataclass(frozen=True)
class IncrementRecord:
    """One increment: the caller's replica entry in ``pos`` grows by
    ``amount``. ``entry`` is the new per-replica count; ``value`` the
    resulting counter value."""

    counter_id: str
    replica_id: str
    amount: int
    entry: int
    value: int
    prev_digest: str
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_id(self.counter_id, "counter_id")
        _check_id(self.replica_id, "replica_id")
        _check_amount(self.amount)
        _check_count(self.entry, "entry")
        if not isinstance(self.value, int) or isinstance(self.value, bool):
            raise BadCounterError(f"value must be an int, saw {self.value!r}")
        if not isinstance(self.prev_digest, str) or not self.prev_digest:
            raise BadCounterError("prev_digest must be a non-empty string")
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            CRDT_COUNTER_VERSION,
            "increment",
            self.counter_id,
            self.replica_id,
            self.amount,
            self.entry,
            self.value,
            self.prev_digest,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


@dataclass(frozen=True)
class DecrementRecord:
    """One decrement: the caller's replica entry in ``neg`` grows by
    ``amount`` (the PN-counter way — entries only grow)."""

    counter_id: str
    replica_id: str
    amount: int
    entry: int
    value: int
    prev_digest: str
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_id(self.counter_id, "counter_id")
        _check_id(self.replica_id, "replica_id")
        _check_amount(self.amount)
        _check_count(self.entry, "entry")
        if not isinstance(self.value, int) or isinstance(self.value, bool):
            raise BadCounterError(f"value must be an int, saw {self.value!r}")
        if not isinstance(self.prev_digest, str) or not self.prev_digest:
            raise BadCounterError("prev_digest must be a non-empty string")
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            CRDT_COUNTER_VERSION,
            "decrement",
            self.counter_id,
            self.replica_id,
            self.amount,
            self.entry,
            self.value,
            self.prev_digest,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


@dataclass(frozen=True)
class MergeRecord:
    """One merge: the pointwise-max join with a remote state.

    ``remote_digest`` pins the canonical remote state that was joined;
    ``merged_replicas`` counts distinct replicas in the union;
    ``value`` is the converged value after the join.
    """

    counter_id: str
    remote_digest: str
    merged_replicas: int
    value: int
    prev_digest: str
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_id(self.counter_id, "counter_id")
        if (
            not isinstance(self.remote_digest, str)
            or not self.remote_digest.startswith(_DIGEST_PREFIX)
            or len(self.remote_digest) != len(_DIGEST_PREFIX) + 64
        ):
            raise BadStateError(
                "remote_digest must be 'sha256:' + 64 hex chars"
            )
        _check_count(self.merged_replicas, "merged_replicas")
        if not isinstance(self.value, int) or isinstance(self.value, bool):
            raise BadCounterError(f"value must be an int, saw {self.value!r}")
        if not isinstance(self.prev_digest, str) or not self.prev_digest:
            raise BadCounterError("prev_digest must be a non-empty string")
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            CRDT_COUNTER_VERSION,
            "merge",
            self.counter_id,
            self.remote_digest,
            self.merged_replicas,
            self.value,
            self.prev_digest,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


@dataclass(frozen=True)
class ValueReport:
    """Pure read view of a counter's value (no seq consumed, no audit
    row). ``pos``/``neg`` pin the state the value was read from."""

    counter_id: str
    value: int
    pos: tuple
    neg: tuple
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_id(self.counter_id, "counter_id")
        if not isinstance(self.value, int) or isinstance(self.value, bool):
            raise BadCounterError(f"value must be an int, saw {self.value!r}")
        for name, vector in (("pos", self.pos), ("neg", self.neg)):
            if not isinstance(vector, tuple):
                raise BadCounterError(f"{name} must be a tuple")
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            CRDT_COUNTER_VERSION,
            "value-report",
            self.counter_id,
            self.value,
            [list(pair) for pair in self.pos],
            [list(pair) for pair in self.neg],
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the report is intact."""
        return self.digest == self._compute_digest()


def crdt_counter_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the CRDT counter.

    Detail carries ids + values + digest pins only — no raw state
    vector dumps; replicas are named but their full maps stay in the
    ledger, not the audit trail.
    """
    if kind not in _KINDS:
        raise CRDTCounterError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "crdt_counter",
        "module_version": CRDT_COUNTER_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# CRDTCounter
# ---------------------------------------------------------------------------


class CRDTCounter:
    """Deterministic state-based PN-counter bookkeeping.

    Each counter keeps ``pos`` and ``neg`` per-replica G-counter maps.
    ``increment``/``decrement`` grow only the caller's replica entry;
    ``merge`` joins a remote state with the pointwise max (commutative,
    associative, idempotent — replicas converge in any merge order).
    ``value``/``state`` are pure read views. ``state`` returns the
    frozen maps so a host can gossip them to other replicas.

    Mutation seqs must be strictly increasing; failed mutations consume
    their seq (batch-21 ledger discipline). No wall-clock, stdlib-only.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = 0
        self._pos: dict[str, dict[str, int]] = {}
        self._neg: dict[str, dict[str, int]] = {}
        self._head_digest: dict[str, str] = {}
        self._audit: list[Mapping[str, Any]] = []

    # -- internal ---------------------------------------------------------

    def _claim_seq(self, seq: int) -> None:
        # Called first in every mutation: a refused mutation still
        # consumes its seq, keeping the ledger totally ordered.
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing: {seq} <= {self._last_seq}"
            )
        self._last_seq = seq

    def _require(self, counter_id: str, seq: int) -> str:
        counter_id = _check_id(counter_id, "counter_id")
        if counter_id not in self._pos:
            self._reject(seq, counter_id=counter_id)
            raise UnknownCounterError(f"unknown counter: {counter_id!r}")
        return counter_id

    def _snapshot(self, counter_id: str) -> tuple[tuple, tuple]:
        return (
            tuple(sorted(self._pos[counter_id].items())),
            tuple(sorted(self._neg[counter_id].items())),
        )

    def _value_of(self, counter_id: str) -> int:
        return sum(self._pos[counter_id].values()) - sum(
            self._neg[counter_id].values()
        )

    def _state_digest(self, pos: tuple, neg: tuple) -> str:
        return _DIGEST_PREFIX + _pin(
            CRDT_COUNTER_VERSION,
            "state",
            [list(pair) for pair in pos],
            [list(pair) for pair in neg],
        )

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(crdt_counter_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, **detail)

    # -- mutations --------------------------------------------------------

    def register(self, counter_id: str, seq: int) -> CounterRecord:
        """Register a counter; starts with empty pos/neg maps."""
        with self._lock:
            self._claim_seq(seq)
            counter_id = _check_id(counter_id, "counter_id")
            if counter_id in self._pos:
                self._reject(seq, counter_id=counter_id)
                raise DuplicateCounterError(
                    f"counter already registered: {counter_id!r}"
                )
            self._pos[counter_id] = {}
            self._neg[counter_id] = {}
            record = CounterRecord(
                counter_id=counter_id, pos=(), neg=(), seq=seq
            )
            self._head_digest[counter_id] = record.digest
            self._emit(
                KIND_COUNTER_REGISTERED,
                seq,
                counter_id=counter_id,
                digest=record.digest,
            )
            return record

    def increment(
        self, counter_id: str, replica_id: str, seq: int, amount: int = 1
    ) -> IncrementRecord:
        """Grow the caller's ``pos`` entry by ``amount``."""
        with self._lock:
            self._claim_seq(seq)
            counter_id = self._require(counter_id, seq)
            replica_id = _check_id(replica_id, "replica_id")
            try:
                amount = _check_amount(amount)
            except BadCounterError:
                self._reject(seq, counter_id=counter_id, replica_id=replica_id)
                raise
            entry = self._pos[counter_id].get(replica_id, 0) + amount
            self._pos[counter_id][replica_id] = entry
            value = self._value_of(counter_id)
            record = IncrementRecord(
                counter_id=counter_id,
                replica_id=replica_id,
                amount=amount,
                entry=entry,
                value=value,
                prev_digest=self._head_digest[counter_id],
                seq=seq,
            )
            self._head_digest[counter_id] = record.digest
            self._emit(
                KIND_INCREMENTED,
                seq,
                counter_id=counter_id,
                replica_id=replica_id,
                amount=amount,
                value=value,
                digest=record.digest,
            )
            return record

    def decrement(
        self, counter_id: str, replica_id: str, seq: int, amount: int = 1
    ) -> DecrementRecord:
        """Grow the caller's ``neg`` entry by ``amount`` (the PN-counter
        way — no borrowing against other replicas' increments)."""
        with self._lock:
            self._claim_seq(seq)
            counter_id = self._require(counter_id, seq)
            replica_id = _check_id(replica_id, "replica_id")
            try:
                amount = _check_amount(amount)
            except BadCounterError:
                self._reject(seq, counter_id=counter_id, replica_id=replica_id)
                raise
            entry = self._neg[counter_id].get(replica_id, 0) + amount
            self._neg[counter_id][replica_id] = entry
            value = self._value_of(counter_id)
            record = DecrementRecord(
                counter_id=counter_id,
                replica_id=replica_id,
                amount=amount,
                entry=entry,
                value=value,
                prev_digest=self._head_digest[counter_id],
                seq=seq,
            )
            self._head_digest[counter_id] = record.digest
            self._emit(
                KIND_DECREMENTED,
                seq,
                counter_id=counter_id,
                replica_id=replica_id,
                amount=amount,
                value=value,
                digest=record.digest,
            )
            return record

    def merge(
        self, counter_id: str, remote_state: Mapping[str, Any], seq: int
    ) -> MergeRecord:
        """Join a remote ``{"pos": {...}, "neg": {...}}`` state with the
        pointwise max. The join is commutative, associative, and
        idempotent — replicas converge in any merge order."""
        with self._lock:
            self._claim_seq(seq)
            counter_id = self._require(counter_id, seq)
            try:
                remote_pos, remote_neg = _check_remote_state(remote_state)
            except BadStateError:
                self._reject(seq, counter_id=counter_id)
                raise
            local_pos = dict(self._pos[counter_id])
            local_neg = dict(self._neg[counter_id])
            for replica, count in remote_pos:
                local_pos[replica] = max(local_pos.get(replica, 0), count)
            for replica, count in remote_neg:
                local_neg[replica] = max(local_neg.get(replica, 0), count)
            self._pos[counter_id] = local_pos
            self._neg[counter_id] = local_neg
            value = self._value_of(counter_id)
            remote_digest = self._state_digest(remote_pos, remote_neg)
            merged_replicas = len(
                set(local_pos) | set(local_neg)
            )
            record = MergeRecord(
                counter_id=counter_id,
                remote_digest=remote_digest,
                merged_replicas=merged_replicas,
                value=value,
                prev_digest=self._head_digest[counter_id],
                seq=seq,
            )
            self._head_digest[counter_id] = record.digest
            self._emit(
                KIND_MERGED,
                seq,
                counter_id=counter_id,
                remote_digest=remote_digest,
                merged_replicas=merged_replicas,
                value=value,
                digest=record.digest,
            )
            return record

    # -- read views --------------------------------------------------------

    def value(self, counter_id: str, seq: int) -> ValueReport:
        """Pure read view of the counter value (validates seq shape,
        consumes nothing, writes no audit row)."""
        with self._lock:
            _check_seq(seq, "seq")
            counter_id = _check_id(counter_id, "counter_id")
            if counter_id not in self._pos:
                raise UnknownCounterError(f"unknown counter: {counter_id!r}")
            pos, neg = self._snapshot(counter_id)
            return ValueReport(
                counter_id=counter_id,
                value=self._value_of(counter_id),
                pos=pos,
                neg=neg,
                seq=seq,
            )

    def state(self, counter_id: str) -> tuple[tuple, tuple]:
        """Frozen ``(pos, neg)`` replica maps — the state to gossip to
        other replicas."""
        with self._lock:
            counter_id = _check_id(counter_id, "counter_id")
            if counter_id not in self._pos:
                raise UnknownCounterError(f"unknown counter: {counter_id!r}")
            return self._snapshot(counter_id)

    def counter_ids(self) -> tuple:
        """Registered counter ids, sorted."""
        with self._lock:
            return tuple(sorted(self._pos))

    def audit_log(self) -> tuple:
        """Frozen audit rows, oldest first."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check: register, increment, decrement, merge convergence."""
    mgr = CRDTCounter()
    mgr.register("c", seq=1)
    mgr.increment("c", "r1", seq=2, amount=3)
    mgr.decrement("c", "r2", seq=3, amount=1)
    assert mgr.value("c", seq=0).value == 2
    # Two divergent replicas converge after merge both ways.
    a, b = CRDTCounter(), CRDTCounter()
    a.register("x", seq=1)
    b.register("x", seq=1)
    a.increment("x", "ra", seq=2, amount=5)
    b.increment("x", "rb", seq=2, amount=7)
    b.decrement("x", "rb", seq=3, amount=2)
    pos_a, neg_a = a.state("x")
    pos_b, neg_b = b.state("x")
    a.merge("x", {"pos": dict(pos_b), "neg": dict(neg_b)}, seq=4)
    b.merge("x", {"pos": dict(pos_a), "neg": dict(neg_a)}, seq=4)
    assert a.value("x", seq=0).value == b.value("x", seq=0).value == 10
    print("crdt-counter OK: register, increment, decrement, merge, converge")


if __name__ == "__main__":
    main()
