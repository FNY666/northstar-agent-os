"""Last-Write-Wins register: convergent replicated value bookkeeping.

Research motivation: CRDTs (Shapiro et al. 2011) let replicas converge
without coordination. The LWW register is the simplest: every write is
tagged with a logical timestamp ``(seq, node_id)``; concurrent writers
resolve deterministically -- the higher ``seq`` wins, ties broken by the
greater ``node_id``. No wall clock is read anywhere: the caller supplies
monotonic int seqs and the host owns the node-id registry.

Public API:

- ``LWWRegister(register_id="default")`` -- mutable, RLock-guarded ledger
  holding one convergent value.
  - ``assign(value, ts_seq, node_id, seq)`` -> frozen ``AssignmentRecord``:
    books the write tagged with the writer timestamp ``(ts_seq, node_id)``;
    ``applied=False`` (as data, never raised) when the timestamp does not
    beat the current one. The trailing ``seq`` is this ledger own strictly
    increasing mutation counter.
  - ``merge(other, seq)`` -> frozen ``MergeRecord``: ``other`` is an
    ``LWWRegister`` or a frozen ``LWWState`` snapshot from a remote
    replica; the newer timestamp's value wins deterministically.
  - ``value()`` -> the current value, or ``None`` when nothing was ever
    assigned. Pure read: consumes no seq.
  - ``state()`` -> frozen ``LWWState`` snapshot for replica exchange.
- ``lww_register_audit_event(kind, detail, seq)`` -- ``audit.ndjson/1``
  records: ``"lww.assigned"``, ``"lww.merged"``, ``"lww.rejected"``.

Timestamp discipline: ``ts_seq`` is a writer-supplied int >= 0;
``node_id`` a non-empty str. Comparison is lexicographic
``(ts_seq, node_id)`` -- higher ts wins, greater node_id breaks ties.
The genesis state has timestamp ``(-1, "")`` and beats nothing. The
ledger ``seq`` is separate: every mutation on this replica takes a
strictly increasing int, regardless of which timestamps it books.

Values are str/int/float/bool/None, pinned by ``sha256:`` digest over a
type-tagged canonical encoding (bool is not int; |int| >= 2**53 and
non-finite floats are refused fail-closed). Raw values never cross the
audit boundary -- audit rows carry digest pins only.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq; bool/negative/rewind refused),
RLock-guarded, fail-closed taxonomy, stdlib-only (``canonical_json``
sibling helper behind the standard try/except fallback).

Honest scope:

- This module books *declared* assignments and merges; it performs no
  replication, observes no wire, and cannot prove which write was "last"
  in wall-clock terms. "Wins" means the declared timestamp is greater.
- A stale ``assign`` is a no-op, not an error -- that is the LWW
  contract, and the record says so.
- Node ids are host-declared; this module cannot distinguish a
  genuinely new replica from a misspelled id, nor detect that two
  writers' seqs came from the same unsynchronized counter.
- Merging registers with different ``register_id`` values is refused:
  they are different registers, not replicas.

Version pin: ``lww-register.v1`` / schema pin
``northstar.lww-register.v1``.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
LWW_REGISTER_VERSION = "lww-register.v1"

#: Schema pin carried by records and audit events.
LWW_REGISTER_SCHEMA = "northstar.lww-register.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_ASSIGNED = "lww.assigned"
KIND_MERGED = "lww.merged"
KIND_REJECTED = "lww.rejected"
_KINDS = frozenset({KIND_ASSIGNED, KIND_MERGED, KIND_REJECTED})

_MAX_INT = 2**53 - 1


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class LWWRegisterError(Exception):
    """Base class for all LWW register errors."""


class BadValueError(LWWRegisterError):
    """Value is not an encodable scalar (or is an unsafe number)."""


class BadTimestampError(LWWRegisterError):
    """Timestamp seq is not a non-negative int."""


class BadNodeError(LWWRegisterError):
    """node_id is not a non-empty str."""


class BadRegisterIdError(LWWRegisterError):
    """register_id is not a non-empty str."""


class SeqOrderError(LWWRegisterError):
    """Caller seq did not strictly increase."""


class BadMergeError(LWWRegisterError):
    """merge() got a non-replica, or a replica of another register."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_register_id(register_id: Any) -> str:
    if isinstance(register_id, bool) or not isinstance(register_id, str):
        raise BadRegisterIdError(
            f"register_id must be str, got {type(register_id).__name__}"
        )
    if not register_id.strip():
        raise BadRegisterIdError("register_id must be non-empty")
    if len(register_id) > 256:
        raise BadRegisterIdError("register_id exceeds 256 chars")
    return register_id


def _check_node_id(node_id: Any) -> str:
    if isinstance(node_id, bool) or not isinstance(node_id, str):
        raise BadNodeError(f"node_id must be str, got {type(node_id).__name__}")
    if not node_id.strip():
        raise BadNodeError("node_id must be non-empty")
    if len(node_id) > 256:
        raise BadNodeError("node_id exceeds 256 chars")
    return node_id


def _check_ts_seq(ts_seq: Any) -> int:
    if isinstance(ts_seq, bool) or not isinstance(ts_seq, int):
        raise BadTimestampError(
            f"timestamp seq must be int, got {type(ts_seq).__name__}"
        )
    if ts_seq < 0:
        raise BadTimestampError("timestamp seq must be non-negative")
    if ts_seq > _MAX_INT:
        raise BadTimestampError("timestamp seq exceeds safe range")
    return ts_seq


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    return seq


def _value_type(value: Any) -> str:
    """Type tag for an assignable scalar; raises BadValueError."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        if abs(value) > _MAX_INT:
            raise BadValueError("int value outside safe range")
        return "int"
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise BadValueError("non-finite float refused")
        return "float"
    if isinstance(value, str):
        if len(value) > 65536:
            raise BadValueError("str value exceeds 64 KiB")
        return "str"
    raise BadValueError(
        f"value must be str/int/float/bool/None, got {type(value).__name__}"
    )


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise LWWRegisterError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise LWWRegisterError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise LWWRegisterError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        _canonical([LWW_REGISTER_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


def _value_digest(value: Any, vtype: str) -> str:
    return _pin("lww-value", vtype, value)


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LWWState:
    """Immutable snapshot of one register for replica exchange.

    ``value`` is ``None`` before anything was ever assigned; the genesis
    timestamp ``(-1, "")`` beats nothing. ``verify()`` recomputes the
    digest pin from the carried value.
    """

    register_id: str
    value: Any
    value_digest: Optional[str]
    value_type: Optional[str]
    ts_seq: int
    ts_node: str
    schema: str = LWW_REGISTER_SCHEMA

    def verify(self) -> bool:
        if self.value_digest is None:
            return (
                self.value is None
                and self.value_type is None
                and self.ts_seq == -1
                and self.ts_node == ""
            )
        try:
            vtype = _value_type(self.value)
        except LWWRegisterError:
            return False
        return (
            vtype == self.value_type
            and self.value_digest == _value_digest(self.value, vtype)
        )


@dataclass(frozen=True)
class AssignmentRecord:
    """One booked write. ``applied=False`` is a stale write kept as data."""

    register_id: str
    value_digest: str
    value_type: str
    ts_seq: int
    ts_node: str
    applied: bool
    seq: int
    digest: str
    schema: str = LWW_REGISTER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "assign",
            self.register_id,
            self.value_digest,
            self.value_type,
            self.ts_seq,
            self.ts_node,
            self.applied,
            self.seq,
        )


@dataclass(frozen=True)
class MergeRecord:
    """One booked merge. ``adopted`` says whether the remote won."""

    register_id: str
    adopted: bool
    winner_digest: Optional[str]
    winner_ts_seq: int
    winner_ts_node: str
    seq: int
    digest: str
    schema: str = LWW_REGISTER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "merge",
            self.register_id,
            self.adopted,
            self.winner_digest,
            self.winner_ts_seq,
            self.winner_ts_node,
            self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def lww_register_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the LWW register.

    Raw values never cross the audit boundary: ``detail`` may carry
    ``value_digest``/``register_id``/timestamps, never ``value``.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise LWWRegisterError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise LWWRegisterError("detail must be a mapping")
    banned = {"value", "payload", "raw"}
    if any(k in detail for k in banned):
        raise LWWRegisterError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": LWW_REGISTER_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The register
# ---------------------------------------------------------------------------


class LWWRegister:
    """Deterministic Last-Write-Wins register (single-host bookkeeping).

    All mutations take a caller-supplied strictly increasing ``seq``
    (logical time); no wall clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position). A write whose
    timestamp does not beat the current one is booked as
    ``applied=False`` -- that is the LWW contract, not an error.
    """

    def __init__(self, register_id: str = "default") -> None:
        self._register_id = _check_register_id(register_id)
        self._lock = threading.RLock()
        self._last_seq = -1
        self._value: Any = None
        self._value_digest: Optional[str] = None
        self._value_type: Optional[str] = None
        self._ts_seq = -1
        self._ts_node = ""
        self._audit: List[Dict[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _consume_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last {self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, detail: Mapping[str, Any], seq: int) -> None:
        self._audit.append(lww_register_audit_event(kind, detail, seq))

    # -- public --------------------------------------------------------

    def assign(self, value: Any, ts_seq: int, node_id: str,
               seq: int) -> AssignmentRecord:
        """Book a write tagged with the writer's timestamp ``(ts_seq, node_id)``.

        The write wins when its timestamp is lexicographically greater
        than the current one; otherwise it is recorded with
        ``applied=False`` and the value is unchanged. ``seq`` is this
        ledger's own strictly increasing mutation counter -- a stale
        remote write still arrives as a fresh local mutation.
        """
        with self._lock:
            consumed = False
            try:
                seq = self._consume_seq(seq)
                consumed = True
                ts_seq = _check_ts_seq(ts_seq)
                node = _check_node_id(node_id)
                vtype = _value_type(value)
                vdigest = _value_digest(value, vtype)
            except LWWRegisterError as exc:
                if consumed:
                    self._emit(
                        KIND_REJECTED,
                        {
                            "register_id": self._register_id,
                            "error": type(exc).__name__,
                        },
                        seq,
                    )
                raise
            wins = (ts_seq, node) > (self._ts_seq, self._ts_node)
            if wins:
                self._value = value
                self._value_digest = vdigest
                self._value_type = vtype
                self._ts_seq = ts_seq
                self._ts_node = node
            record = AssignmentRecord(
                register_id=self._register_id,
                value_digest=vdigest,
                value_type=vtype,
                ts_seq=ts_seq,
                ts_node=node,
                applied=wins,
                seq=seq,
                digest=_pin(
                    "assign",
                    self._register_id,
                    vdigest,
                    vtype,
                    ts_seq,
                    node,
                    wins,
                    seq,
                ),
            )
            self._emit(
                KIND_ASSIGNED,
                {
                    "register_id": self._register_id,
                    "value_digest": vdigest,
                    "value_type": vtype,
                    "ts_seq": ts_seq,
                    "ts_node": node,
                    "applied": wins,
                },
                seq,
            )
            return record

    def merge(self, other: Any, seq: int) -> MergeRecord:
        """Merge a remote replica's state; the newer timestamp wins.

        ``other`` is an ``LWWRegister`` or a frozen ``LWWState`` of the
        *same* ``register_id``. Merging a different register is refused.
        """
        with self._lock:
            consumed = False
            try:
                seq = self._consume_seq(seq)
                consumed = True
                if isinstance(other, LWWRegister):
                    with other._lock:
                        remote = other.state()
                elif isinstance(other, LWWState):
                    remote = other
                else:
                    raise BadMergeError(
                        "merge expects LWWRegister or LWWState, got "
                        f"{type(other).__name__}"
                    )
                if remote.register_id != self._register_id:
                    raise BadMergeError(
                        f"register_id mismatch: {remote.register_id!r} "
                        f"is not {self._register_id!r}"
                    )
                if not remote.verify():
                    raise BadMergeError("remote state failed verification")
            except LWWRegisterError as exc:
                if consumed:
                    self._emit(
                        KIND_REJECTED,
                        {
                            "register_id": self._register_id,
                            "error": type(exc).__name__,
                        },
                        seq,
                    )
                raise
            remote_wins = (remote.ts_seq, remote.ts_node) > (
                self._ts_seq,
                self._ts_node,
            )
            if remote_wins:
                self._value = remote.value
                self._value_digest = remote.value_digest
                self._value_type = remote.value_type
                self._ts_seq = remote.ts_seq
                self._ts_node = remote.ts_node
            record = MergeRecord(
                register_id=self._register_id,
                adopted=remote_wins,
                winner_digest=self._value_digest,
                winner_ts_seq=self._ts_seq,
                winner_ts_node=self._ts_node,
                seq=seq,
                digest=_pin(
                    "merge",
                    self._register_id,
                    remote_wins,
                    self._value_digest,
                    self._ts_seq,
                    self._ts_node,
                    seq,
                ),
            )
            self._emit(
                KIND_MERGED,
                {
                    "register_id": self._register_id,
                    "adopted": remote_wins,
                    "winner_digest": self._value_digest,
                    "winner_ts_seq": self._ts_seq,
                    "winner_ts_node": self._ts_node,
                },
                seq,
            )
            return record

    def value(self) -> Any:
        """The current value, or ``None`` when nothing was ever assigned."""
        with self._lock:
            return self._value

    def state(self) -> LWWState:
        """Frozen snapshot for replica exchange (no seq consumed)."""
        with self._lock:
            return LWWState(
                register_id=self._register_id,
                value=self._value,
                value_digest=self._value_digest,
                value_type=self._value_type,
                ts_seq=self._ts_seq,
                ts_node=self._ts_node,
            )

    def timestamp(self) -> Tuple[int, str]:
        """Current ``(ts_seq, ts_node)``; ``(-1, "")`` before any assign."""
        with self._lock:
            return (self._ts_seq, self._ts_node)

    def as_dict(self) -> Dict[str, Any]:
        """JSON-safe record (digest pins only; the raw value never leaves)."""
        with self._lock:
            return {
                "schema": LWW_REGISTER_SCHEMA,
                "register_id": self._register_id,
                "value_digest": self._value_digest,
                "value_type": self._value_type,
                "ts_seq": self._ts_seq,
                "ts_node": self._ts_node,
                "last_seq": self._last_seq,
            }

    def audit_log(self) -> List[Dict[str, Any]]:
        """Copy of the booked audit events."""
        with self._lock:
            return list(self._audit)


def main() -> None:
    """Self-check: assign, stale write, tie-break, merge, snapshot, audit."""
    r = LWWRegister("r1")
    assert r.value() is None, "unassigned register reads None"
    assert r.timestamp() == (-1, "")

    rec = r.assign("hello", 1, "node-a", 1)
    assert rec.applied and rec.verify()
    assert r.value() == "hello"
    assert r.timestamp() == (1, "node-a")

    stale = r.assign("stale", 1, "node-a", 2)  # same timestamp: loses
    assert not stale.applied and stale.verify()
    assert r.value() == "hello", "stale write must not change the value"

    r.assign("tie", 2, "node-a", 3)
    tie2 = r.assign("tie-winner", 2, "node-b", 4)  # same ts, greater node
    assert tie2.applied and tie2.verify()
    assert r.value() == "tie-winner", "node_id breaks ts ties deterministically"

    remote = LWWRegister("r1")
    remote.assign("remote-newer", 5, "node-c", 1)
    m = r.merge(remote, 5)
    assert m.adopted and m.verify()
    assert r.value() == "remote-newer"
    assert r.timestamp() == (5, "node-c")

    older = LWWRegister("r1")
    m2 = r.merge(older, 6)  # genesis timestamp beats nothing
    assert not m2.adopted and m2.verify()
    assert r.value() == "remote-newer"

    st = r.state()
    assert st.verify()
    r3 = LWWRegister("r1")
    m3 = r3.merge(st, 1)  # merge from a frozen snapshot
    assert m3.adopted and m3.verify()
    assert r3.value() == "remote-newer"

    other = LWWRegister("r2")  # different register: refused
    try:
        r.merge(other, 10)
    except BadMergeError:
        pass
    else:
        raise AssertionError("cross-register merge must be refused")

    kinds = {e["kind"] for e in r.audit_log()}
    assert {"lww.assigned", "lww.merged"} <= kinds
    for e in r.audit_log():
        assert "value" not in e["detail"], "raw value leaked into audit"

    print("lww-register OK: assign, stale, tie-break, merge, snapshot, audit")


if __name__ == "__main__":
    main()
