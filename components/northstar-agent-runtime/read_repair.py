"""Read repair: Dynamo-style quorum-read divergence bookkeeping.

Research motivation: in Dynamo (DeCandia et al., 2007) a coordinator
reads from R replicas; when the R responses disagree it picks the most
recent value and writes it back to the stale replicas -- *read repair*.
This module books that coordination decision deterministically: which
replicas were read, who disagreed, who won, and which replicas were
declared stale. It performs no reads and no writes -- the host owns the
wire, the timers, and the repair itself.

Public API:

- ``ReadRepair(num_replicas=3, read_quorum=None, write_quorum=None)`` --
  mutable, RLock-guarded ledger.
  - ``read(key, readings, seq)`` -> frozen ``ReadReport``: books one
    quorum read. ``readings`` is a tuple of frozen ``ReplicaReading``
    ``(replica_id, ts_seq, ts_node, value_digest)``. The winner is the
    reading with the greatest ``(ts_seq, ts_node)`` (lexicographic,
    deterministic -- no wall clock). Divergence and the stale replica
    set are reported as data. Fewer readings than the read quorum raise
    ``QuorumNotMetError`` fail-closed.
  - ``reconcile(key, winner_digest, ts_seq, ts_node, stale_replicas, seq)``
    -> frozen ``ReconcileRecord``: books the coordinator's repair
    decision -- which replicas must adopt the winner. Booking only.
  - ``quorum()`` -> frozen ``QuorumConfig``: pure read view of
    ``(num_replicas, read_quorum, write_quorum)``; consumes no seq.
- ``read_repair_audit_event(kind, detail, seq)`` -- ``audit.ndjson/1``
  records: ``"read_repair.read"``, ``"read_repair.reconciled"``,
  ``"read_repair.rejected"``.

Values are pinned by ``sha256:`` digest only -- raw values never enter a
record or cross the audit boundary. Replica timestamps are
host-declared ``(ts_seq, ts_node)`` pairs (same convention as the
``lww_register`` sibling): the module cannot verify that a timestamp
is "true", only that it is well-formed.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq; bool/negative/rewind refused),
RLock-guarded, fail-closed taxonomy, stdlib-only (``canonical_json``
sibling helper behind the standard try/except fallback).

Honest scope:

- This module books *declared* readings; it observes no wire and cannot
  prove a replica actually holds the pinned digest -- replica honesty
  is GIGO at the host boundary.
- A booked ``ReconcileRecord`` is a decision, not an executed write:
  the repair happens only if the host performs it.
- The winner rule is deterministic timestamp order, not a causal proof;
  two replicas with unsynchronized counters may disagree about what is
  "latest". Convergence requires the caller's repair action.

Version pin: ``read-repair.v1`` / schema pin
``northstar.read-repair.v1``.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
READ_REPAIR_VERSION = "read-repair.v1"

#: Schema pin carried by records and audit events.
READ_REPAIR_SCHEMA = "northstar.read-repair.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_READ = "read_repair.read"
KIND_RECONCILED = "read_repair.reconciled"
KIND_REJECTED = "read_repair.rejected"
_KINDS = frozenset({KIND_READ, KIND_RECONCILED, KIND_REJECTED})

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_DIGEST_LEN = len(_DIGEST_PREFIX) + 64


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class ReadRepairError(Exception):
    """Base class for all read-repair errors."""


class BadKeyError(ReadRepairError):
    """Key is not a non-empty str."""


class BadReadingError(ReadRepairError):
    """A ReplicaReading is malformed."""


class BadDigestError(ReadRepairError):
    """value_digest is not a well-formed sha256: pin."""


class BadTimestampError(ReadRepairError):
    """ts_seq is not a non-negative int."""


class BadReplicaError(ReadRepairError):
    """replica_id/ts_node is not a non-empty str."""


class DuplicateReplicaError(ReadRepairError):
    """The same replica_id appears twice in one read."""


class QuorumNotMetError(ReadRepairError):
    """Fewer readings were supplied than the read quorum requires."""


class SeqOrderError(ReadRepairError):
    """Caller seq did not strictly increase."""


class AuditKindError(ReadRepairError):
    """Unknown audit kind for read_repair_audit_event."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_key(key: Any) -> str:
    if isinstance(key, bool) or not isinstance(key, str):
        raise BadKeyError(f"key must be str, got {type(key).__name__}")
    if not key.strip():
        raise BadKeyError("key must be non-empty")
    if len(key) > 1024:
        raise BadKeyError("key exceeds 1024 chars")
    return key


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    return seq


def _check_ts_seq(ts_seq: Any) -> int:
    if isinstance(ts_seq, bool) or not isinstance(ts_seq, int):
        raise BadTimestampError(
            f"ts_seq must be int, got {type(ts_seq).__name__}"
        )
    if ts_seq < 0:
        raise BadTimestampError("ts_seq must be non-negative")
    if ts_seq > _MAX_INT:
        raise BadTimestampError("ts_seq exceeds safe range")
    return ts_seq


def _check_node(node: Any, what: str = "ts_node") -> str:
    if isinstance(node, bool) or not isinstance(node, str):
        raise BadReplicaError(f"{what} must be str, got {type(node).__name__}")
    if not node.strip():
        raise BadReplicaError(f"{what} must be non-empty")
    if len(node) > 256:
        raise BadReplicaError(f"{what} exceeds 256 chars")
    return node


def _check_replica_id(replica_id: Any) -> str:
    if isinstance(replica_id, bool) or not isinstance(replica_id, str):
        raise BadReplicaError(
            f"replica_id must be str, got {type(replica_id).__name__}"
        )
    if not replica_id.strip():
        raise BadReplicaError("replica_id must be non-empty")
    if len(replica_id) > 256:
        raise BadReplicaError("replica_id exceeds 256 chars")
    return replica_id


def _check_digest(digest: Any) -> str:
    if isinstance(digest, bool) or not isinstance(digest, str):
        raise BadDigestError(
            f"value_digest must be str, got {type(digest).__name__}"
        )
    if len(digest) != _DIGEST_LEN or not digest.startswith(_DIGEST_PREFIX):
        raise BadDigestError("value_digest must be 'sha256:' + 64 hex chars")
    hexpart = digest[len(_DIGEST_PREFIX):]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError("value_digest hex part is not lowercase hex")
    return digest


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
                raise ReadRepairError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise ReadRepairError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise ReadRepairError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        _canonical([READ_REPAIR_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReplicaReading:
    """One replica's declared response to a quorum read.

    ``value_digest`` pins the value the replica claims to hold; the raw
    value never enters a record. ``(ts_seq, ts_node)`` is the
    host-declared write timestamp of that value.
    """

    replica_id: str
    ts_seq: int
    ts_node: str
    value_digest: str
    schema: str = READ_REPAIR_SCHEMA

    def verify(self) -> bool:
        """Re-check well-formedness (never raises)."""
        try:
            _check_replica_id(self.replica_id)
            _check_ts_seq(self.ts_seq)
            _check_node(self.ts_node)
            _check_digest(self.value_digest)
        except ReadRepairError:
            return False
        return self.schema == READ_REPAIR_SCHEMA


@dataclass(frozen=True)
class QuorumConfig:
    """Pure read view of the configured replica/quorum sizes."""

    num_replicas: int
    read_quorum: int
    write_quorum: int
    schema: str = READ_REPAIR_SCHEMA


@dataclass(frozen=True)
class ReadReport:
    """Booked outcome of one quorum read.

    ``winner_digest``/``winner_ts_seq``/``winner_ts_node`` name the
    reading with the greatest ``(ts_seq, ts_node)``. ``divergent`` is
    True when the readings disagree; ``stale_replicas`` lists the
    replica ids whose reading lost (candidates for repair), sorted for
    determinism.
    """

    key: str
    read_id: str
    replica_ids: Tuple[str, ...]
    winner_digest: str
    winner_ts_seq: int
    winner_ts_node: str
    divergent: bool
    stale_replicas: Tuple[str, ...]
    digest: str
    seq: int
    schema: str = READ_REPAIR_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "read",
                self.key,
                self.read_id,
                list(self.replica_ids),
                self.winner_digest,
                self.winner_ts_seq,
                self.winner_ts_node,
                self.divergent,
                list(self.stale_replicas),
                self.seq,
            )
        except ReadRepairError:
            return False
        return recomputed == self.digest and self.schema == READ_REPAIR_SCHEMA


@dataclass(frozen=True)
class ReconcileRecord:
    """Booked repair decision: these replicas must adopt the winner."""

    key: str
    reconcile_id: str
    winner_digest: str
    winner_ts_seq: int
    winner_ts_node: str
    stale_replicas: Tuple[str, ...]
    digest: str
    seq: int
    schema: str = READ_REPAIR_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "reconcile",
                self.key,
                self.reconcile_id,
                self.winner_digest,
                self.winner_ts_seq,
                self.winner_ts_node,
                list(self.stale_replicas),
                self.seq,
            )
        except ReadRepairError:
            return False
        return recomputed == self.digest and self.schema == READ_REPAIR_SCHEMA


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def read_repair_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for read repair.

    Raw values never cross the audit boundary: ``detail`` may carry
    digests, ids, timestamps and counts -- never ``value``.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise AuditKindError("detail must be a mapping")
    banned = {"value", "payload", "raw"}
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": READ_REPAIR_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class ReadRepair:
    """Deterministic read-repair coordination ledger (single-host).

    All mutations take a caller-supplied strictly increasing ``seq``
    (logical time); no wall clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position). ``quorum()`` is a
    pure read view and consumes no seq.
    """

    def __init__(
        self,
        num_replicas: int = 3,
        read_quorum: Optional[int] = None,
        write_quorum: Optional[int] = None,
    ) -> None:
        if isinstance(num_replicas, bool) or not isinstance(num_replicas, int):
            raise ReadRepairError("num_replicas must be int")
        if num_replicas < 1 or num_replicas > 64:
            raise ReadRepairError("num_replicas must be in [1, 64]")
        majority = num_replicas // 2 + 1
        if read_quorum is None:
            read_quorum = majority
        if write_quorum is None:
            write_quorum = majority
        for name, value in (("read_quorum", read_quorum),
                            ("write_quorum", write_quorum)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ReadRepairError(f"{name} must be int")
            if value < 1 or value > num_replicas:
                raise ReadRepairError(
                    f"{name} must be in [1, num_replicas]"
                )
        self._num_replicas = num_replicas
        self._read_quorum = read_quorum
        self._write_quorum = write_quorum
        self._lock = threading.RLock()
        self._last_seq = -1
        self._reads: list = []
        self._reconciles: list = []
        self._audit: list = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not exceed last seq {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _reject(self, seq: int, reason: str, key: str = "") -> Dict[str, Any]:
        row = read_repair_audit_event(
            KIND_REJECTED, {"reason": reason, "key": key}, seq
        )
        self._audit.append(row)
        return row

    # -- pure views --------------------------------------------------------

    def quorum(self) -> QuorumConfig:
        """Configured replica/quorum sizes. Pure read; consumes no seq."""
        with self._lock:
            return QuorumConfig(
                num_replicas=self._num_replicas,
                read_quorum=self._read_quorum,
                write_quorum=self._write_quorum,
            )

    def reads(self) -> Tuple[ReadReport, ...]:
        with self._lock:
            return tuple(self._reads)

    def reconciles(self) -> Tuple[ReconcileRecord, ...]:
        with self._lock:
            return tuple(self._reconciles)

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)

    # -- mutations ---------------------------------------------------------

    def read(
        self, key: str, readings: Tuple[ReplicaReading, ...], seq: int
    ) -> ReadReport:
        """Book one quorum read; resolve the winner deterministically.

        Winner is the reading with the greatest ``(ts_seq, ts_node)``.
        Divergence and the stale replica set are reported as data.
        Fewer readings than the read quorum fail closed with
        ``QuorumNotMetError``; failed mutations consume their seq.
        """
        with self._lock:
            self._claim(seq)
            try:
                key = _check_key(key)
                if not isinstance(readings, tuple):
                    raise BadReadingError("readings must be a tuple")
                if len(readings) < self._read_quorum:
                    raise QuorumNotMetError(
                        f"got {len(readings)} readings, "
                        f"read quorum is {self._read_quorum}"
                    )
                if len(readings) > self._num_replicas:
                    raise BadReadingError(
                        "more readings than configured replicas"
                    )
                seen = set()
                ordered_ids = []
                for r in readings:
                    if not isinstance(r, ReplicaReading):
                        raise BadReadingError(
                            "readings must hold ReplicaReading records"
                        )
                    rid = _check_replica_id(r.replica_id)
                    _check_ts_seq(r.ts_seq)
                    _check_node(r.ts_node)
                    _check_digest(r.value_digest)
                    if rid in seen:
                        raise DuplicateReplicaError(
                            f"duplicate replica_id: {rid}"
                        )
                    seen.add(rid)
                    ordered_ids.append(rid)
            except ReadRepairError as exc:
                self._reject(seq, type(exc).__name__, key if isinstance(key, str) else "")
                raise

            winner = max(
                readings, key=lambda r: (r.ts_seq, r.ts_node)
            )
            stale = tuple(
                sorted(
                    r.replica_id
                    for r in readings
                    if (r.ts_seq, r.ts_node, r.value_digest)
                    != (winner.ts_seq, winner.ts_node, winner.value_digest)
                )
            )
            divergent = len(stale) > 0
            read_id = f"read-{len(self._reads)}"
            replica_ids = tuple(sorted(seen))
            digest = _pin(
                "read",
                key,
                read_id,
                list(replica_ids),
                winner.value_digest,
                winner.ts_seq,
                winner.ts_node,
                divergent,
                list(stale),
                seq,
            )
            report = ReadReport(
                key=key,
                read_id=read_id,
                replica_ids=replica_ids,
                winner_digest=winner.value_digest,
                winner_ts_seq=winner.ts_seq,
                winner_ts_node=winner.ts_node,
                divergent=divergent,
                stale_replicas=stale,
                digest=digest,
                seq=seq,
            )
            self._reads.append(report)
            self._audit.append(
                read_repair_audit_event(
                    KIND_READ,
                    {
                        "key": key,
                        "read_id": read_id,
                        "replica_ids": list(replica_ids),
                        "winner_digest": winner.value_digest,
                        "winner_ts_seq": winner.ts_seq,
                        "winner_ts_node": winner.ts_node,
                        "divergent": divergent,
                        "stale_replicas": list(stale),
                    },
                    seq,
                )
            )
            return report

    def reconcile(
        self,
        key: str,
        winner_digest: str,
        ts_seq: int,
        ts_node: str,
        stale_replicas: Tuple[str, ...],
        seq: int,
    ) -> ReconcileRecord:
        """Book the repair decision: stale replicas adopt the winner.

        Booking only -- the host performs the actual writes. The stale
        set must be non-empty; failed mutations consume their seq.
        """
        with self._lock:
            self._claim(seq)
            try:
                key = _check_key(key)
                winner_digest = _check_digest(winner_digest)
                ts_seq = _check_ts_seq(ts_seq)
                ts_node = _check_node(ts_node)
                if not isinstance(stale_replicas, tuple):
                    raise BadReplicaError("stale_replicas must be a tuple")
                if not stale_replicas:
                    raise BadReplicaError("stale_replicas must be non-empty")
                cleaned = []
                seen = set()
                for rid in stale_replicas:
                    rid = _check_replica_id(rid)
                    if rid in seen:
                        raise DuplicateReplicaError(
                            f"duplicate replica_id: {rid}"
                        )
                    seen.add(rid)
                    cleaned.append(rid)
                stale = tuple(sorted(cleaned))
            except ReadRepairError as exc:
                self._reject(seq, type(exc).__name__, key if isinstance(key, str) else "")
                raise

            reconcile_id = f"reconcile-{len(self._reconciles)}"
            digest = _pin(
                "reconcile",
                key,
                reconcile_id,
                winner_digest,
                ts_seq,
                ts_node,
                list(stale),
                seq,
            )
            record = ReconcileRecord(
                key=key,
                reconcile_id=reconcile_id,
                winner_digest=winner_digest,
                winner_ts_seq=ts_seq,
                winner_ts_node=ts_node,
                stale_replicas=stale,
                digest=digest,
                seq=seq,
            )
            self._reconciles.append(record)
            self._audit.append(
                read_repair_audit_event(
                    KIND_RECONCILED,
                    {
                        "key": key,
                        "reconcile_id": reconcile_id,
                        "winner_digest": winner_digest,
                        "winner_ts_seq": ts_seq,
                        "winner_ts_node": ts_node,
                        "stale_replicas": list(stale),
                    },
                    seq,
                )
            )
            return record


def main() -> None:
    """Self-check: quorum view, convergent read, divergent read, repair."""
    rr = ReadRepair(num_replicas=3)
    cfg = rr.quorum()
    assert (cfg.num_replicas, cfg.read_quorum, cfg.write_quorum) == (3, 2, 2)
    assert rr.quorum() == cfg  # pure view is stable

    pin = lambda v: _pin("value", v)
    d_a = pin("a")
    readings = (
        ReplicaReading("r1", 5, "n1", d_a),
        ReplicaReading("r2", 5, "n1", d_a),
    )
    report = rr.read("k", readings, 1)
    assert not report.divergent and report.stale_replicas == ()
    assert report.winner_digest == d_a and report.verify()

    d_b = pin("b")
    mixed = (
        ReplicaReading("r1", 5, "n1", d_a),
        ReplicaReading("r2", 7, "n1", d_b),
        ReplicaReading("r3", 6, "n2", d_a),
    )
    rep = rr.read("k", mixed, 2)
    assert rep.divergent
    assert rep.winner_digest == d_b
    assert rep.stale_replicas == ("r1", "r3")
    assert rep.verify()

    rec = rr.reconcile("k", d_b, 7, "n1", rep.stale_replicas, 3)
    assert rec.stale_replicas == ("r1", "r3") and rec.verify()

    kinds = [row["kind"] for row in rr.audit_log()]
    assert kinds == [KIND_READ, KIND_READ, KIND_RECONCILED], kinds

    try:
        rr.read("k", (ReplicaReading("r1", 1, "n1", d_a),), 4)
    except QuorumNotMetError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected QuorumNotMetError")
    assert rr.audit_log()[-1]["kind"] == KIND_REJECTED

    print("read-repair OK: quorum, read, divergent, reconcile, audit")


if __name__ == "__main__":
    main()
