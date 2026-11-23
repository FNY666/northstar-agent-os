"""Replica manager — primary/replica replication bookkeeping (replication batch).

Research note (replication literature): primary-backup and chain
replication systems (e.g. the replicas behind Kafka topic partitions,
MongoDB replica sets, and ZooKeeper ensembles) keep the same *logical
data* on several hosts so that the loss of one host does not lose the
data or the service. The load-bearing invariants are:

* **One primary per shard**: at any moment a shard has at most one
  writer that other replicas trust. A second primary is split-brain,
  and split-brain is silent data loss.
* **Promotion is fenced**: when a new primary takes over, the epoch
  (term) advances monotonically. Old-primary writes carrying a stale
  epoch must be rejected by the storage layer — this is what stops a
  "zombie" primary that thought it was still in charge.
* **Sync is declared progress**: a replica tells the manager how much
  of the primary's log it has applied. Lag is a *measurement*, not a
  promise; the manager cannot make the replica catch up.

This module takes the intersection for a single-host deterministic
ledger:

* ``replicate(shard_id, replica_id, seq)`` books a replica membership
  for a shard (``secondary`` role). Duplicate memberships are refused
  fail-closed.
* ``promote(shard_id, replica_id, seq)`` promotes a member replica to
  primary: the old primary (if any) is demoted to secondary and the
  shard's epoch advances monotonically (fencing).
* ``sync(shard_id, replica_id, applied_seqs, seq)`` books host-declared
  replication progress: the replica applied ``applied_seqs`` more
  primary-log entries. Progress is monotone; going backwards is a
  caller bug and is refused.
* Pure read views (``replicas``, ``primary``, ``sync_state``,
  ``shard_ids``, ``stats``) validate seq shape but consume nothing and
  write no audit row.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs on mutations (failed mutations consume their seq per the
batch-21 discipline; bool/negative/rewind refused), RLock-guarded,
fail-closed taxonomy, stdlib-only (``canonical_json`` sibling helper
behind the standard try/except fallback), type-tagged ``sha256:``
digest pins, ``audit.ndjson/1`` events.

Honest boundary: this module books *declared* replication topology
and *host-reported* progress. It moves no bytes, runs no elections,
and cannot prove a replica actually applied anything — the host
declares every ``sync``. A ``primary`` record means "this ledger
named a primary", never "the fleet agrees". An ``epoch`` bump is a
fencing *signal* the storage layer must check; this ledger does not
enforce it on the wire.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
REPLICA_MANAGER_VERSION = "replica-manager.v1"

#: Schema pin carried by records and audit events.
REPLICA_MANAGER_SCHEMA = "northstar.replica-manager.v1"

#: Audit event kinds.
EVENT_REPLICATED = "replicated"
EVENT_PROMOTED = "promoted"
EVENT_SYNCED = "synced"
EVENT_REJECTED = "rejected"

_EVENT_TYPES = frozenset(
    {EVENT_REPLICATED, EVENT_PROMOTED, EVENT_SYNCED, EVENT_REJECTED}
)

#: Pinned replica roles.
ROLE_PRIMARY = "primary"
ROLE_SECONDARY = "secondary"
_ROLES = frozenset({ROLE_PRIMARY, ROLE_SECONDARY})


def _canonical(obj: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(obj).encode("utf-8")
    import json

    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(tag: str, obj: Any) -> str:
    return "sha256:" + hashlib.sha256(tag.encode() + b"|" + _canonical(obj)).hexdigest()


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ReplicaManagerError(Exception):
    """Base class for all replica-manager errors."""


class BadShardError(ReplicaManagerError):
    """Shard id is malformed."""


class BadReplicaError(ReplicaManagerError):
    """Replica id is malformed."""


class BadSyncError(ReplicaManagerError):
    """Sync progress payload is malformed."""


class DuplicateReplicaError(ReplicaManagerError):
    """Replica is already a member of the shard."""


class UnknownShardError(ReplicaManagerError):
    """Shard id is not registered."""


class UnknownReplicaError(ReplicaManagerError):
    """Replica is not a member of the shard."""


class PromotionError(ReplicaManagerError):
    """Promotion is not allowed (no such replica, or other violation)."""


class SeqOrderError(ReplicaManagerError):
    """Seq is not a strictly increasing int (bool/negative/rewind)."""


class AuditKindError(ReplicaManagerError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


def _check_id(value: Any, err: type) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise err(f"id must be a non-empty str, got {type(value).__name__}")
    value = value.strip()
    if not value or len(value) > 256 or any(c.isspace() for c in value):
        raise err("id must be non-empty, <=256 chars, no whitespace")
    return value


@dataclass(frozen=True)
class ReplicaRecord:
    """One replica's membership in a shard."""

    shard_id: str
    replica_id: str
    role: str
    epoch: int
    seq: int
    digest: str

    def verify(self) -> bool:
        expect = _pin(
            "replica-manager.replica",
            {
                "shard_id": self.shard_id,
                "replica_id": self.replica_id,
                "role": self.role,
                "epoch": self.epoch,
                "seq": self.seq,
            },
        )
        return self.digest == expect


@dataclass(frozen=True)
class PromoteRecord:
    """A primary change for a shard (fencing epoch advance)."""

    shard_id: str
    new_primary: str
    old_primary: Optional[str]
    epoch: int
    changed: bool
    seq: int
    digest: str

    def verify(self) -> bool:
        expect = _pin(
            "replica-manager.promote",
            {
                "shard_id": self.shard_id,
                "new_primary": self.new_primary,
                "old_primary": self.old_primary,
                "epoch": self.epoch,
                "changed": self.changed,
                "seq": self.seq,
            },
        )
        return self.digest == expect


@dataclass(frozen=True)
class SyncRecord:
    """Host-declared replication progress for one replica."""

    shard_id: str
    replica_id: str
    applied_seqs: int
    applied_total: int
    seq: int
    digest: str

    def verify(self) -> bool:
        expect = _pin(
            "replica-manager.sync",
            {
                "shard_id": self.shard_id,
                "replica_id": self.replica_id,
                "applied_seqs": self.applied_seqs,
                "applied_total": self.applied_total,
                "seq": self.seq,
            },
        )
        return self.digest == expect


@dataclass(frozen=True)
class SyncState:
    """Pure read view of one replica's sync position."""

    shard_id: str
    replica_id: str
    applied_total: int
    lag: int


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class ReplicaManager:
    """Deterministic primary/replica bookkeeping for one host."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # shard_id -> {"epoch": int, "members": {replica_id: role}}
        self._shards: dict[str, dict[str, Any]] = {}
        # (shard_id, replica_id) -> applied_total
        self._applied: dict[Tuple[str, str], int] = {}
        self._audit: list[dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> None:
        """Claim-then-burn: validate seq; failed mutations burn it."""
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
            raise SeqOrderError("seq must be a positive int (bool refused)")
        with self._lock:
            if seq <= self._seq:
                # Burn: a failed (rewound) mutation still advances the head
                # so the offending seq can never be reused.
                self._seq = seq
                raise SeqOrderError(f"seq must strictly increase (head={self._seq})")
            self._seq = seq

    def _emit(
        self, kind: str, shard_id: str, replica_id: str, seq: int, **fields: Any
    ) -> None:
        if kind not in _EVENT_TYPES:
            raise AuditKindError(f"unknown audit kind: {kind!r}")
        row: dict[str, Any] = {
            "type": "audit.ndjson/1",
            "event": kind,
            "shard_id": shard_id,
            "replica_id": replica_id,
            "seq": seq,
            "schema": REPLICA_MANAGER_SCHEMA,
        }
        row.update(fields)
        with self._lock:
            self._audit.append(row)

    def _fail(
        self,
        exc: type,
        message: str,
        shard_id: str,
        replica_id: str,
        seq: int,
        reason: str,
    ) -> ReplicaManagerError:
        self._emit(EVENT_REJECTED, shard_id, replica_id, seq, reason=reason)
        return exc(message)

    # -- mutations ----------------------------------------------------------

    def replicate(self, shard_id: Any, replica_id: Any, seq: Any) -> ReplicaRecord:
        """Book ``replica_id`` as a secondary member of ``shard_id``."""
        self._claim(seq)
        try:
            shard = _check_id(shard_id, BadShardError)
            replica = _check_id(replica_id, BadReplicaError)
        except ReplicaManagerError as exc:
            raise self._fail(
                type(exc), str(exc), str(shard_id), str(replica_id), seq, "bad-id"
            ) from exc
        with self._lock:
            entry = self._shards.setdefault(shard, {"epoch": 0, "members": {}})
            if replica in entry["members"]:
                raise self._fail(
                    DuplicateReplicaError,
                    f"replica {replica!r} already in shard {shard!r}",
                    shard,
                    replica,
                    seq,
                    "duplicate-replica",
                )
            entry["members"][replica] = ROLE_SECONDARY
            self._applied[(shard, replica)] = 0
            digest = _pin(
                "replica-manager.replica",
                {
                    "shard_id": shard,
                    "replica_id": replica,
                    "role": ROLE_SECONDARY,
                    "epoch": entry["epoch"],
                    "seq": seq,
                },
            )
            rec = ReplicaRecord(shard, replica, ROLE_SECONDARY, entry["epoch"], seq, digest)
            self._emit(EVENT_REPLICATED, shard, replica, seq, role=ROLE_SECONDARY)
            return rec

    def promote(self, shard_id: Any, replica_id: Any, seq: Any) -> PromoteRecord:
        """Promote a member replica to primary; advance the fencing epoch."""
        self._claim(seq)
        try:
            shard = _check_id(shard_id, BadShardError)
            replica = _check_id(replica_id, BadReplicaError)
        except ReplicaManagerError as exc:
            raise self._fail(
                type(exc), str(exc), str(shard_id), str(replica_id), seq, "bad-id"
            ) from exc
        with self._lock:
            entry = self._shards.get(shard)
            if entry is None:
                raise self._fail(
                    UnknownShardError,
                    f"unknown shard {shard!r}",
                    shard,
                    replica,
                    seq,
                    "unknown-shard",
                )
            if replica not in entry["members"]:
                raise self._fail(
                    PromotionError,
                    f"replica {replica!r} is not a member of shard {shard!r}",
                    shard,
                    replica,
                    seq,
                    "not-member",
                )
            old_primary: Optional[str] = self.primary(shard)
            changed = old_primary != replica
            if changed:
                entry["epoch"] += 1
                if old_primary is not None:
                    entry["members"][old_primary] = ROLE_SECONDARY
                entry["members"][replica] = ROLE_PRIMARY
            epoch = entry["epoch"]
            digest = _pin(
                "replica-manager.promote",
                {
                    "shard_id": shard,
                    "new_primary": replica,
                    "old_primary": old_primary,
                    "epoch": epoch,
                    "changed": changed,
                    "seq": seq,
                },
            )
            rec = PromoteRecord(shard, replica, old_primary, epoch, changed, seq, digest)
            self._emit(
                EVENT_PROMOTED,
                shard,
                replica,
                seq,
                old_primary=old_primary,
                epoch=epoch,
                changed=changed,
            )
            return rec

    def sync(
        self, shard_id: Any, replica_id: Any, applied_seqs: Any, seq: Any
    ) -> SyncRecord:
        """Book host-declared replication progress for one replica."""
        self._claim(seq)
        try:
            shard = _check_id(shard_id, BadShardError)
            replica = _check_id(replica_id, BadReplicaError)
        except ReplicaManagerError as exc:
            raise self._fail(
                type(exc), str(exc), str(shard_id), str(replica_id), seq, "bad-id"
            ) from exc
        if (
            isinstance(applied_seqs, bool)
            or not isinstance(applied_seqs, int)
            or applied_seqs <= 0
        ):
            raise self._fail(
                BadSyncError,
                "applied_seqs must be a positive int (bool refused)",
                shard,
                replica,
                seq,
                "bad-sync",
            )
        with self._lock:
            entry = self._shards.get(shard)
            if entry is None:
                raise self._fail(
                    UnknownShardError,
                    f"unknown shard {shard!r}",
                    shard,
                    replica,
                    seq,
                    "unknown-shard",
                )
            if replica not in entry["members"]:
                raise self._fail(
                    UnknownReplicaError,
                    f"replica {replica!r} is not a member of shard {shard!r}",
                    shard,
                    replica,
                    seq,
                    "unknown-replica",
                )
            total = self._applied[(shard, replica)] + applied_seqs
            self._applied[(shard, replica)] = total
            digest = _pin(
                "replica-manager.sync",
                {
                    "shard_id": shard,
                    "replica_id": replica,
                    "applied_seqs": applied_seqs,
                    "applied_total": total,
                    "seq": seq,
                },
            )
            rec = SyncRecord(shard, replica, applied_seqs, total, seq, digest)
            self._emit(
                EVENT_SYNCED,
                shard,
                replica,
                seq,
                applied_seqs=applied_seqs,
                applied_total=total,
            )
            return rec

    # -- views (pure; seq shape validated, never consumed) --------------------

    def _check_seq_shape(self, seq: Any) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
            raise SeqOrderError("seq must be a positive int (bool refused)")

    def replicas(self, shard_id: str, seq: Any) -> Tuple[str, ...]:
        """Sorted member replica ids of a shard (pure read)."""
        self._check_seq_shape(seq)
        with self._lock:
            entry = self._shards.get(shard_id)
            if entry is None:
                return ()
            return tuple(sorted(entry["members"]))

    def primary(self, shard_id: str, seq: Any = 1) -> Optional[str]:
        """Current primary of a shard, or None (pure read)."""
        self._check_seq_shape(seq)
        with self._lock:
            entry = self._shards.get(shard_id)
            if entry is None:
                return None
            for replica, role in entry["members"].items():
                if role == ROLE_PRIMARY:
                    return replica
            return None

    def epoch(self, shard_id: str, seq: Any = 1) -> int:
        """Fencing epoch of a shard (pure read)."""
        self._check_seq_shape(seq)
        with self._lock:
            entry = self._shards.get(shard_id)
            return 0 if entry is None else entry["epoch"]

    def sync_state(self, shard_id: str, replica_id: str, seq: Any) -> SyncState:
        """One replica's sync position and lag (pure read)."""
        self._check_seq_shape(seq)
        with self._lock:
            total = self._applied.get((shard_id, replica_id), 0)
            entry = self._shards.get(shard_id)
            members = entry["members"] if entry else {}
            head = max(
                (self._applied.get((shard_id, r), 0) for r in members), default=0
            )
            return SyncState(shard_id, replica_id, total, head - total)

    def shard_ids(self, seq: Any) -> Tuple[str, ...]:
        """All known shard ids, sorted (pure read)."""
        self._check_seq_shape(seq)
        with self._lock:
            return tuple(sorted(self._shards))

    def stats(self, seq: Any) -> Mapping[str, int]:
        """Aggregate counts (pure read)."""
        self._check_seq_shape(seq)
        with self._lock:
            members = sum(len(e["members"]) for e in self._shards.values())
            primaries = sum(
                1 for e in self._shards.values() if ROLE_PRIMARY in e["members"].values()
            )
            return {
                "shards": len(self._shards),
                "replicas": members,
                "primaries": primaries,
                "audit_rows": len(self._audit),
            }

    def audit_log(self) -> Tuple[Mapping[str, Any], ...]:
        """Append-only audit rows."""
        with self._lock:
            return tuple(self._audit)


def replica_manager_audit_event(
    kind: str, shard_id: str, replica_id: str, seq: Any, **fields: Any
) -> Mapping[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a replica event."""
    if kind not in _EVENT_TYPES:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise SeqOrderError("seq must be a positive int (bool refused)")
    row: dict[str, Any] = {
        "type": "audit.ndjson/1",
        "event": kind,
        "shard_id": shard_id,
        "replica_id": replica_id,
        "seq": seq,
        "schema": REPLICA_MANAGER_SCHEMA,
    }
    row.update(fields)
    return row


def main() -> None:
    mgr = ReplicaManager()
    r1 = mgr.replicate("orders", "host-a", 1)
    assert r1.verify() and r1.role == "secondary"
    r2 = mgr.replicate("orders", "host-b", 2)
    assert r2.verify()
    # No primary yet; promote host-a.
    p1 = mgr.promote("orders", "host-a", 3)
    assert p1.verify() and p1.changed and p1.epoch == 1
    assert mgr.primary("orders", 4) == "host-a"
    # Failover: promote host-b; epoch advances, host-a demoted.
    p2 = mgr.promote("orders", "host-b", 5)
    assert p2.verify() and p2.old_primary == "host-a" and p2.epoch == 2
    assert mgr.primary("orders", 6) == "host-b"
    # Re-promote current primary: idempotent, no epoch bump.
    p3 = mgr.promote("orders", "host-b", 7)
    assert not p3.changed and p3.epoch == 2
    # Host-declared sync progress.
    s1 = mgr.sync("orders", "host-a", 10, 8)
    assert s1.verify() and s1.applied_total == 10
    s2 = mgr.sync("orders", "host-a", 5, 9)
    assert s2.applied_total == 15
    st = mgr.sync_state("orders", "host-a", 10)
    assert st.applied_total == 15 and st.lag >= 0
    # Refusals: duplicate member, promote non-member, unknown shard.
    for bad in (
        lambda: mgr.replicate("orders", "host-a", 11),
        lambda: mgr.promote("orders", "host-z", 12),
        lambda: mgr.sync("ghost", "host-a", 1, 13),
    ):
        try:
            bad()
        except ReplicaManagerError:
            pass
        else:
            raise AssertionError("expected refusal")
    # Seq discipline: rewind refused.
    try:
        mgr.replicate("orders", "host-c", 5)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("expected SeqOrderError")
    kinds = [e["event"] for e in mgr.audit_log()]
    assert EVENT_REJECTED in kinds, kinds
    print("replica-manager OK: replicate, promote, sync, fencing, fail-closed")


if __name__ == "__main__":
    main()
