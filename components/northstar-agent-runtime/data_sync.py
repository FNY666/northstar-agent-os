"""Bidirectional data synchronization (thirtieth batch).

Operational interface for *bidirectional sync* between two replicas of a
key/value store, in the shape of host-reported replication batches
(CouchDB/PouchDB-style push/pull, Syncthing-style version vectors). The
module books local mutations, packages outbound batches (push), applies
inbound batches with divergence detection (pull), and records explicit
conflict resolutions (resolve).

Record semantics:

* :meth:`DataSync.put` stages a local mutation for ``key``: a frozen
  :class:`ChangeRecord` (``chg-N`` ids) with a monotonically increasing
  per-key version. :meth:`DataSync.delete` stages a tombstone the same
  way — deletes replicate as data, never as absence.
* :meth:`DataSync.push` packages *all* staged changes since the last
  push into a frozen :class:`PushReceipt` (``batch-N`` ids) and clears
  the staged queue. An empty push is valid (no-op sync, as data).
* :meth:`DataSync.pull` applies a host-reported batch of remote
  changes. Per key, a base-version discipline decides the outcome as
  **data**, never as an exception: adopt-on-fast-forward (remote moved,
  local did not), ignore-stale (remote version at or below the synced
  base), adopt-silent (both moved to byte-identical content), or
  :class:`ConflictRecord` (``cfl-N`` ids, status ``open``) when both
  sides advanced the key past the last synced base. A remote tombstone
  against a local modification also conflicts.
* :meth:`DataSync.resolve` applies a terminal resolution to an open
  conflict under a pinned strategy vocabulary: ``local-wins`` (remote
  dropped), ``remote-wins`` (remote adopted), or ``merge`` (host
  supplies the merged value — fail-closed if absent). Resolution emits
  a frozen :class:`ResolutionRecord` (``res-N`` ids); conflicts resolve
  exactly once (double-resolve refused fail-closed).
* :meth:`DataSync.sync_state` is a pure digest-pinned summary of the
  replica (counts + state digest); reads validate the seq shape but
  consume no seq.

House rules: no wall-clock (callers inject strictly increasing int
``seq`` on mutations; failed mutations consume their seq — the
fail-closed ledger position), frozen dataclasses, RLock-guarded,
fail-closed error taxonomy, stdlib-only, records sealed with a sha256
``record_digest`` over a type-tagged canonical payload (bool != int;
floats and ``|n| >= 2**53`` refused at the boundary, batch-5 JCS
discipline). State transitions emit ``audit.ndjson/1`` events; the
audit boundary carries ids and digest pins only — key values never
cross it (test-verified).

Honest boundary: this module books *host-reported* sync traffic and
applies deterministic divergence rules to it. It performs no network
I/O, runs no transport security, observes no wire, and cannot prove a
remote replica really held the reported versions or that nothing was
withheld. Production replication needs an authenticated transport plus
a content-addressed, tamper-evident log.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any, Mapping, Sequence


#: Version pin for this module's record shape.
DATA_SYNC_VERSION = "data-sync.v1"

#: Schema pin carried by records and audit events.
DATA_SYNC_SCHEMA = "northstar.data-sync.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Genesis chain head.
_GENESIS = "genesis"

#: Value-digest domain.
_VALUE_DIGEST_PREFIX = "sha256:"

#: Tombstone marker: a deleted key replicates as a record whose value is
#: absent and ``deleted`` is True.
DELETED = "deleted"
LIVE = "live"

#: Pinned conflict-resolution strategies.
STRATEGY_LOCAL_WINS = "local-wins"
STRATEGY_REMOTE_WINS = "remote-wins"
STRATEGY_MERGE = "merge"
_STRATEGIES = (STRATEGY_LOCAL_WINS, STRATEGY_REMOTE_WINS, STRATEGY_MERGE)

#: Conflict statuses.
OPEN = "open"
RESOLVED = "resolved"

#: Audit event kinds.
KIND_STAGED = "sync.staged"
KIND_PUSHED = "sync.pushed"
KIND_PULLED = "sync.pulled"
KIND_CONFLICT = "sync.conflict"
KIND_RESOLVED = "sync.resolved"
KIND_AUDIT = "sync.audit"
KIND_REJECTED = "sync.rejected"
_KINDS = (
    KIND_STAGED,
    KIND_PUSHED,
    KIND_PULLED,
    KIND_CONFLICT,
    KIND_RESOLVED,
    KIND_AUDIT,
    KIND_REJECTED,
)


class DataSyncError(ValueError):
    """Base class for all data-sync refusals (fail-closed)."""


class BadKeyError(DataSyncError):
    """Key is not a non-empty string within length bounds."""


class BadValueError(DataSyncError):
    """Value is not encodable: floats, out-of-range ints, bad shapes."""


class BadChangeError(DataSyncError):
    """A host-reported remote change is malformed."""


class BadStrategyError(DataSyncError):
    """Unknown resolution strategy, or strategy precondition unmet."""


class UnknownConflictError(DataSyncError):
    """Conflict id is not known to the ledger."""


class ConflictStateError(DataSyncError):
    """Conflict is already resolved (terminal) or otherwise misplaced."""


class SeqOrderError(DataSyncError):
    """Mutation seq is not a strictly increasing int (bool refused)."""


#: Sentinel marking "no merged value supplied" for ``resolve``.
_NO_MERGE = object()


# ---------------------------------------------------------------------------
# Value canonicalization (batch-5 JCS discipline)
# ---------------------------------------------------------------------------

_MAX_SAFE_INT = 2 ** 53


def _check_key(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise BadKeyError(f"key must be a non-empty str, saw {type(value).__name__}")
    if len(value) > 256:
        raise BadKeyError("key longer than 256 chars refused")
    return value


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{field_name} must be an int, saw {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{field_name} must be non-negative, saw {value}")
    return value


def _tag(value: Any) -> Any:
    """Type-tagged canonical form: bool != int; floats refused."""
    if value is None:
        return ["n"]
    if isinstance(value, bool):
        return ["b", value]
    if isinstance(value, int):
        if abs(value) >= _MAX_SAFE_INT:
            raise BadValueError(f"int outside +/-2^53 refused: {value!r}")
        return ["i", value]
    if isinstance(value, float):
        raise BadValueError(f"floats refused at the sync boundary: {value!r}")
    if isinstance(value, str):
        if len(value) > 65536:
            raise BadValueError("str longer than 65536 chars refused")
        return ["s", value]
    if isinstance(value, (list, tuple)):
        if len(value) > 10000:
            raise BadValueError("list longer than 10000 items refused")
        return ["l", [_tag(item) for item in value]]
    if isinstance(value, dict):
        if len(value) > 10000:
            raise BadValueError("dict larger than 10000 entries refused")
        for k in value:
            if not isinstance(k, str):
                raise BadValueError("dict keys must be str")
        return ["d", [[k, _tag(value[k])] for k in sorted(value)]]
    raise BadValueError(f"unencodable value type: {type(value).__name__}")


def _canonical(value: Any) -> bytes:
    """Canonical bytes for a host-supplied value (JCS-shaped, tagged)."""
    return json.dumps(
        _tag(value), separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _pin(*parts: bytes) -> str:
    """sha256 pin over the concatenated parts."""
    digest = hashlib.sha256()
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return _VALUE_DIGEST_PREFIX + digest.hexdigest()


def compute_value_digest(value: Any) -> str:
    """Digest pin for a host-supplied value."""
    return _pin(b"value", _canonical(value))


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChangeRecord:
    """One staged local mutation (put or tombstone delete)."""

    change_id: str
    key: str
    value_digest: str  # digest of the value; tombstones carry "sha256:" of empty tagged list marker
    deleted: bool
    local_version: int
    staged_seq: int
    prev_digest: str
    record_digest: str = ""

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff intact."""
        return compute_change_digest(self) == self.record_digest


@dataclass(frozen=True)
class SyncItem:
    """Current authoritative per-key state of this replica."""

    key: str
    value_digest: str
    deleted: bool
    base_version: int  # last version both replicas agreed on
    local_version: int  # last local mutation version (>= base_version)
    updated_seq: int
    prev_digest: str
    record_digest: str = ""

    def verify(self) -> bool:
        return compute_item_digest(self) == self.record_digest


@dataclass(frozen=True)
class PushReceipt:
    """Frozen outbound batch packaged by push()."""

    batch_id: str
    change_ids: tuple
    change_count: int
    pushed_seq: int
    batch_digest: str
    prev_digest: str
    record_digest: str = ""

    def verify(self) -> bool:
        return compute_push_digest(self) == self.record_digest


@dataclass(frozen=True)
class AppliedChange:
    """One remote change as applied (or ignored/conflicted) during pull()."""

    remote_change_id: str
    key: str
    outcome: str  # adopted / ignored-stale / adopted-identical / conflict
    conflict_id: str | None
    detail: str

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "remote_change_id": self.remote_change_id,
            "key": self.key,
            "outcome": self.outcome,
            "conflict_id": self.conflict_id,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class PullReceipt:
    """Frozen record of one pull() application."""

    pull_id: str
    remote_batch_size: int
    applied: tuple  # AppliedChange tuples
    conflict_ids: tuple
    pulled_seq: int
    batch_digest: str
    prev_digest: str
    record_digest: str = ""

    def verify(self) -> bool:
        return compute_pull_digest(self) == self.record_digest


@dataclass(frozen=True)
class ConflictRecord:
    """One divergent key awaiting explicit resolution."""

    conflict_id: str
    key: str
    local_version: int
    local_value_digest: str
    local_deleted: bool
    remote_version: int
    remote_value_digest: str
    remote_deleted: bool
    remote_origin: str
    status: str
    opened_seq: int
    prev_digest: str
    record_digest: str = ""

    def verify(self) -> bool:
        return compute_conflict_digest(self) == self.record_digest


@dataclass(frozen=True)
class ResolutionRecord:
    """Terminal record of one conflict resolution."""

    resolution_id: str
    conflict_id: str
    key: str
    strategy: str
    resulting_value_digest: str
    resulting_deleted: bool
    resulting_version: int
    resolved_seq: int
    prev_digest: str
    record_digest: str = ""

    def verify(self) -> bool:
        return compute_resolution_digest(self) == self.record_digest


@dataclass(frozen=True)
class SyncStateReport:
    """Pure digest-pinned summary of the replica."""

    item_count: int
    deleted_count: int
    open_conflict_count: int
    resolved_conflict_count: int
    staged_count: int
    pushed_count: int
    state_digest: str
    at_seq: int


def _change_payload(change: ChangeRecord) -> bytes:
    return json.dumps(
        {
            "change_id": change.change_id,
            "key": change.key,
            "value_digest": change.value_digest,
            "deleted": change.deleted,
            "local_version": change.local_version,
            "staged_seq": change.staged_seq,
            "prev_digest": change.prev_digest,
        },
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def compute_change_digest(change: ChangeRecord) -> str:
    return _pin(b"data-sync.change", _change_payload(change))


def _item_payload(item: SyncItem) -> bytes:
    return json.dumps(
        {
            "key": item.key,
            "value_digest": item.value_digest,
            "deleted": item.deleted,
            "base_version": item.base_version,
            "local_version": item.local_version,
            "updated_seq": item.updated_seq,
            "prev_digest": item.prev_digest,
        },
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def compute_item_digest(item: SyncItem) -> str:
    return _pin(b"data-sync.item", _item_payload(item))


def compute_push_digest(receipt: PushReceipt) -> str:
    return _pin(
        b"data-sync.push",
        receipt.batch_id.encode(),
        json.dumps(list(receipt.change_ids), separators=(",", ":")).encode(),
        str(receipt.pushed_seq).encode(),
        receipt.prev_digest.encode(),
    )


def compute_pull_digest(receipt: PullReceipt) -> str:
    return _pin(
        b"data-sync.pull",
        receipt.pull_id.encode(),
        json.dumps(
            [dict(c.as_dict()) for c in receipt.applied],
            separators=(",", ":"),
        ).encode(),
        str(receipt.pulled_seq).encode(),
        receipt.prev_digest.encode(),
    )


def compute_conflict_digest(conflict: ConflictRecord) -> str:
    return _pin(
        b"data-sync.conflict",
        conflict.conflict_id.encode(),
        conflict.key.encode(),
        str(conflict.local_version).encode(),
        conflict.local_value_digest.encode(),
        str(conflict.local_deleted).encode(),
        str(conflict.remote_version).encode(),
        conflict.remote_value_digest.encode(),
        str(conflict.remote_deleted).encode(),
        conflict.remote_origin.encode(),
        str(conflict.opened_seq).encode(),
        conflict.prev_digest.encode(),
    )


def compute_resolution_digest(resolution: ResolutionRecord) -> str:
    return _pin(
        b"data-sync.resolution",
        resolution.resolution_id.encode(),
        resolution.conflict_id.encode(),
        resolution.key.encode(),
        resolution.strategy.encode(),
        resolution.resulting_value_digest.encode(),
        str(resolution.resulting_deleted).encode(),
        str(resolution.resulting_version).encode(),
        str(resolution.resolved_seq).encode(),
        resolution.prev_digest.encode(),
    )


def _seal_change(change: ChangeRecord) -> ChangeRecord:
    return replace(change, record_digest=compute_change_digest(change))


def _seal_item(item: SyncItem) -> SyncItem:
    return replace(item, record_digest=compute_item_digest(item))


def _seal_push(receipt: PushReceipt) -> PushReceipt:
    return replace(receipt, record_digest=compute_push_digest(receipt))


def _seal_pull(receipt: PullReceipt) -> PullReceipt:
    return replace(receipt, record_digest=compute_pull_digest(receipt))


def _seal_conflict(conflict: ConflictRecord) -> ConflictRecord:
    return replace(conflict, record_digest=compute_conflict_digest(conflict))


def _seal_resolution(resolution: ResolutionRecord) -> ResolutionRecord:
    return replace(resolution, record_digest=compute_resolution_digest(resolution))


def data_sync_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the sync manager."""
    if kind not in _KINDS:
        raise DataSyncError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "data_sync",
        "module_version": DATA_SYNC_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


def _check_remote_change(raw: Any) -> Mapping[str, Any]:
    """Validate one host-reported remote change; fail-closed.

    Accepted shape: a mapping with ``change_id`` (non-empty str),
    ``key`` (non-empty str), ``version`` (non-negative int, not bool),
    ``origin`` (non-empty str), ``deleted`` (bool) and, unless deleted,
    ``value`` (encodable). Returns the normalized mapping.
    """
    if not isinstance(raw, Mapping):
        raise BadChangeError(f"remote change must be a mapping, saw {type(raw).__name__}")
    try:
        change_id = raw["change_id"]
        key = raw["key"]
        version = raw["version"]
        origin = raw["origin"]
        deleted = raw.get("deleted", False)
    except KeyError as exc:
        raise BadChangeError(f"remote change missing field: {exc}") from exc
    if not isinstance(change_id, str) or not change_id:
        raise BadChangeError("remote change_id must be a non-empty str")
    if not isinstance(origin, str) or not origin:
        raise BadChangeError("remote origin must be a non-empty str")
    key = _check_key(key)
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise BadChangeError("remote version must be a non-negative int")
    if not isinstance(deleted, bool):
        raise BadChangeError("remote deleted must be a bool")
    if deleted:
        value_digest = _pin(b"value.tombstone")
    else:
        if "value" not in raw:
            raise BadChangeError("remote change missing 'value' (and not deleted)")
        value_digest = compute_value_digest(raw["value"])
    return {
        "change_id": change_id,
        "key": key,
        "version": version,
        "origin": origin,
        "deleted": deleted,
        "value_digest": value_digest,
    }


# ---------------------------------------------------------------------------
# DataSync
# ---------------------------------------------------------------------------


class DataSync:
    """Bidirectional-sync ledger: stage (put/delete), push, pull, resolve.

    Per key, ``base_version`` is the last version both replicas agreed
    on; ``local_version`` is the last local mutation. ``push`` packages
    staged mutations; ``pull`` applies remote batches with the
    divergence rules documented on the module docstring. Mutation seqs
    must be strictly increasing; failed mutations consume their seq
    (fail-closed ledger position). Thread-safe via an RLock.
    """

    def __init__(self, *, node_id: str = "local") -> None:
        if not isinstance(node_id, str) or not node_id:
            raise DataSyncError("node_id must be a non-empty str")
        self._lock = RLock()
        self._node_id = node_id
        self._last_seq = -1
        self._change_counter = 0
        self._batch_counter = 0
        self._pull_counter = 0
        self._conflict_counter = 0
        self._resolution_counter = 0
        self._items: dict[str, SyncItem] = {}
        self._staged: list[ChangeRecord] = []
        self._conflicts: dict[str, ConflictRecord] = {}
        self._resolutions: dict[str, ResolutionRecord] = {}
        self._chain_head = _GENESIS
        self._audit_log: list[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing (last={self._last_seq}, saw={seq})"
            )
        self._last_seq = seq
        return seq

    def _audit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(data_sync_audit_event(kind, seq, **detail))

    def _extend_chain(self, digest: str) -> str:
        self._chain_head = digest
        return digest

    def _stage(
        self, key: str, value_digest: str, deleted: bool, seq: int
    ) -> ChangeRecord:
        self._next_seq(seq)
        self._change_counter += 1
        item = self._items.get(key)
        base = item.base_version if item is not None else 0
        local_version = max(item.local_version if item is not None else 0, base) + 1
        change = _seal_change(
            ChangeRecord(
                change_id=f"chg-{self._change_counter}",
                key=key,
                value_digest=value_digest,
                deleted=deleted,
                local_version=local_version,
                staged_seq=seq,
                prev_digest=self._chain_head,
            )
        )
        self._extend_chain(change.record_digest)
        new_item = _seal_item(
            SyncItem(
                key=key,
                value_digest=value_digest,
                deleted=deleted,
                base_version=base,
                local_version=local_version,
                updated_seq=seq,
                prev_digest=self._chain_head,
            )
        )
        self._extend_chain(new_item.record_digest)
        self._items[key] = new_item
        self._staged.append(change)
        self._audit(KIND_STAGED, seq, change_id=change.change_id, key=key,
                    deleted=deleted)
        return change

    # -- mutations -----------------------------------------------------

    def put(self, key: str, value: Any, seq: int) -> ChangeRecord:
        """Stage a local mutation for ``key`` (version bumps past base)."""
        key = _check_key(key)
        return self._stage(key, compute_value_digest(value), False, seq)

    def delete(self, key: str, seq: int) -> ChangeRecord:
        """Stage a tombstone delete for ``key`` (replicates as data)."""
        key = _check_key(key)
        return self._stage(key, _pin(b"value.tombstone"), True, seq)

    def push(self, seq: int) -> PushReceipt:
        """Package all staged changes into an outbound batch (clears queue)."""
        with self._lock:
            self._next_seq(seq)
            self._batch_counter += 1
            change_ids = tuple(c.change_id for c in self._staged)
            receipt = _seal_push(
                PushReceipt(
                    batch_id=f"batch-{self._batch_counter}",
                    change_ids=change_ids,
                    change_count=len(change_ids),
                    pushed_seq=seq,
                    batch_digest=_pin(
                        b"batch",
                        *(c.record_digest.encode() for c in self._staged),
                    ),
                    prev_digest=self._chain_head,
                )
            )
            self._extend_chain(receipt.record_digest)
            self._staged = []
            self._audit(
                KIND_PUSHED, seq, batch_id=receipt.batch_id,
                change_count=receipt.change_count,
            )
            return receipt

    def pull(
        self, seq: int, remote_changes: Sequence[Mapping[str, Any]]
    ) -> PullReceipt:
        """Apply a host-reported remote batch; divergence becomes data.

        Per key: adopt-on-fast-forward, ignore-stale, adopt-identical
        (both sides moved to byte-identical content), or open a
        :class:`ConflictRecord` when both sides advanced past the last
        synced base (a remote tombstone against a local modification
        also conflicts). Remote change ids seen twice in one batch are
        applied once (second occurrence reported ``ignored-duplicate``).
        """
        with self._lock:
            self._next_seq(seq)
            self._pull_counter += 1
            if not isinstance(remote_changes, Sequence) or isinstance(
                remote_changes, (str, bytes)
            ):
                raise BadChangeError("remote_changes must be a sequence of mappings")
            applied: list[AppliedChange] = []
            conflict_ids: list[str] = []
            seen_ids: set[str] = set()
            for raw in remote_changes:
                norm = _check_remote_change(raw)
                if norm["change_id"] in seen_ids:
                    applied.append(
                        AppliedChange(
                            remote_change_id=norm["change_id"],
                            key=norm["key"],
                            outcome="ignored-duplicate",
                            conflict_id=None,
                            detail="duplicate remote change id in batch",
                        )
                    )
                    continue
                seen_ids.add(norm["change_id"])
                applied.append(self._apply_one(norm, seq, conflict_ids))
            receipt = _seal_pull(
                PullReceipt(
                    pull_id=f"pull-{self._pull_counter}",
                    remote_batch_size=len(remote_changes),
                    applied=tuple(applied),
                    conflict_ids=tuple(conflict_ids),
                    pulled_seq=seq,
                    batch_digest=_pin(
                        b"remote-batch",
                        *(
                            f"{n['change_id']}:{n['key']}:{n['version']}".encode()
                            for n in (self._normalize_remote(r) for r in remote_changes)
                        ),
                    ),
                    prev_digest=self._chain_head,
                )
            )
            self._extend_chain(receipt.record_digest)
            self._audit(
                KIND_PULLED, seq, pull_id=receipt.pull_id,
                remote_batch_size=receipt.remote_batch_size,
                conflict_count=len(conflict_ids),
            )
            return receipt

    def _normalize_remote(self, raw: Mapping[str, Any]) -> Mapping[str, Any]:
        # Already validated in pull(); normalize again for the batch digest.
        return _check_remote_change(raw)

    def _apply_one(
        self,
        norm: Mapping[str, Any],
        seq: int,
        conflict_ids: list[str],
    ) -> AppliedChange:
        key = norm["key"]
        item = self._items.get(key)
        outcome, conflict_id, detail = self._classify(norm, item)
        if outcome == "conflict":
            self._conflict_counter += 1
            conflict = _seal_conflict(
                ConflictRecord(
                    conflict_id=f"cfl-{self._conflict_counter}",
                    key=key,
                    local_version=item.local_version,
                    local_value_digest=item.value_digest,
                    local_deleted=item.deleted,
                    remote_version=norm["version"],
                    remote_value_digest=norm["value_digest"],
                    remote_deleted=norm["deleted"],
                    remote_origin=norm["origin"],
                    status=OPEN,
                    opened_seq=seq,
                    prev_digest=self._chain_head,
                )
            )
            self._extend_chain(conflict.record_digest)
            self._conflicts[conflict.conflict_id] = conflict
            conflict_id = conflict.conflict_id
            conflict_ids.append(conflict_id)
            self._audit(
                KIND_CONFLICT, seq, conflict_id=conflict_id, key=key,
                local_version=item.local_version,
                remote_version=norm["version"],
            )
        elif outcome.startswith("adopt"):
            adopted = _seal_item(
                SyncItem(
                    key=key,
                    value_digest=norm["value_digest"],
                    deleted=norm["deleted"],
                    base_version=max(
                        item.base_version if item is not None else 0, norm["version"]
                    ),
                    local_version=max(
                        item.local_version if item is not None else 0, norm["version"]
                    ),
                    updated_seq=seq,
                    prev_digest=self._chain_head,
                )
            )
            self._extend_chain(adopted.record_digest)
            self._items[key] = adopted
        return AppliedChange(
            remote_change_id=norm["change_id"],
            key=key,
            outcome=outcome,
            conflict_id=conflict_id,
            detail=detail,
        )

    @staticmethod
    def _classify(
        norm: Mapping[str, Any], item: SyncItem | None
    ) -> tuple[str, str | None, str]:
        """Decide the outcome for one remote change (data, never raised)."""
        if item is None:
            return "adopted-new", None, "key unknown locally; remote adopted"
        if norm["version"] <= item.base_version:
            return "ignored-stale", None, (
                f"remote version {norm['version']} at/below synced base "
                f"{item.base_version}"
            )
        local_advanced = item.local_version > item.base_version
        if not local_advanced:
            return "adopted-fast-forward", None, "local unchanged since sync"
        if norm["value_digest"] == item.value_digest and norm["deleted"] == item.deleted:
            return "adopted-identical", None, "both sides converged to identical content"
        return "conflict", None, "both sides advanced past synced base"

    def resolve(
        self,
        conflict_id: str,
        seq: int,
        strategy: str,
        merged_value: Any = _NO_MERGE,
    ) -> ResolutionRecord:
        """Terminally resolve one open conflict under a pinned strategy.

        ``merge`` requires ``merged_value`` (fail-closed when absent or
        unencodable). A merge always settles on a *live* record; to end
        with a tombstone use ``local-wins``/``remote-wins`` on the side
        that deleted.
        """
        with self._lock:
            self._next_seq(seq)
            if not isinstance(conflict_id, str) or not conflict_id:
                raise UnknownConflictError("conflict_id must be a non-empty str")
            conflict = self._conflicts.get(conflict_id)
            if conflict is None:
                raise UnknownConflictError(f"unknown conflict: {conflict_id!r}")
            if conflict.status != OPEN:
                raise ConflictStateError(
                    f"conflict {conflict_id} already resolved (terminal)"
                )
            if strategy not in _STRATEGIES:
                raise BadStrategyError(
                    f"unknown strategy {strategy!r}; pinned: {_STRATEGIES}"
                )
            item = self._items[conflict.key]
            if strategy == STRATEGY_LOCAL_WINS:
                resulting_digest = conflict.local_value_digest
                resulting_deleted = conflict.local_deleted
                resulting_version = max(conflict.local_version, conflict.remote_version)
            elif strategy == STRATEGY_REMOTE_WINS:
                resulting_digest = conflict.remote_value_digest
                resulting_deleted = conflict.remote_deleted
                resulting_version = max(conflict.local_version, conflict.remote_version)
            else:  # merge
                if merged_value is _NO_MERGE:
                    raise BadStrategyError("merge requires merged_value")
                resulting_digest = compute_value_digest(merged_value)
                resulting_deleted = False
                resulting_version = (
                    max(conflict.local_version, conflict.remote_version) + 1
                )
            self._resolution_counter += 1
            resolution = _seal_resolution(
                ResolutionRecord(
                    resolution_id=f"res-{self._resolution_counter}",
                    conflict_id=conflict_id,
                    key=conflict.key,
                    strategy=strategy,
                    resulting_value_digest=resulting_digest,
                    resulting_deleted=resulting_deleted,
                    resulting_version=resulting_version,
                    resolved_seq=seq,
                    prev_digest=self._chain_head,
                )
            )
            self._extend_chain(resolution.record_digest)
            settled = _seal_item(
                SyncItem(
                    key=conflict.key,
                    value_digest=resulting_digest,
                    deleted=resulting_deleted,
                    base_version=resulting_version,
                    local_version=resulting_version,
                    updated_seq=seq,
                    prev_digest=self._chain_head,
                )
            )
            self._extend_chain(settled.record_digest)
            self._items[conflict.key] = settled
            self._conflicts[conflict_id] = _seal_conflict(
                replace(conflict, status=RESOLVED)
            )
            self._resolutions[resolution.resolution_id] = resolution
            self._audit(
                KIND_RESOLVED, seq, conflict_id=conflict_id,
                strategy=strategy, resolution_id=resolution.resolution_id,
            )
            return resolution

    # -- views ---------------------------------------------------------

    def get(self, key: str) -> SyncItem | None:
        """Current per-key state, or None when the key is unknown."""
        _check_key(key)
        with self._lock:
            return self._items.get(key)

    def item_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._items)

    def open_conflicts(self) -> list[ConflictRecord]:
        with self._lock:
            return [
                c for c in self._conflicts.values() if c.status == OPEN
            ]

    def conflict(self, conflict_id: str) -> ConflictRecord:
        if not isinstance(conflict_id, str) or not conflict_id:
            raise UnknownConflictError("conflict_id must be a non-empty str")
        with self._lock:
            conflict = self._conflicts.get(conflict_id)
            if conflict is None:
                raise UnknownConflictError(f"unknown conflict: {conflict_id!r}")
            return conflict

    def resolution(self, resolution_id: str) -> ResolutionRecord:
        with self._lock:
            resolution = self._resolutions.get(resolution_id)
            if resolution is None:
                raise DataSyncError(f"unknown resolution: {resolution_id!r}")
            return resolution

    def staged_changes(self) -> list[ChangeRecord]:
        with self._lock:
            return list(self._staged)

    def audit(self, seq: int) -> Mapping[str, Any]:
        """Digest-pinned replica summary (consumes a seq)."""
        with self._lock:
            self._next_seq(seq)
            items = sorted(self._items.values(), key=lambda i: i.key)
            state_digest = _pin(
                b"data-sync.state",
                *(i.record_digest.encode() for i in items),
                str(len(self._conflicts)).encode(),
                str(len(self._staged)).encode(),
            )
            report = SyncStateReport(
                item_count=len(self._items),
                deleted_count=sum(1 for i in self._items.values() if i.deleted),
                open_conflict_count=sum(
                    1 for c in self._conflicts.values() if c.status == OPEN
                ),
                resolved_conflict_count=sum(
                    1 for c in self._conflicts.values() if c.status == RESOLVED
                ),
                staged_count=len(self._staged),
                pushed_count=self._batch_counter,
                state_digest=state_digest,
                at_seq=seq,
            )
            self._audit(KIND_AUDIT, seq, state_digest=state_digest)
            return {
                "schema": DATA_SYNC_SCHEMA,
                "module_version": DATA_SYNC_VERSION,
                "item_count": report.item_count,
                "deleted_count": report.deleted_count,
                "open_conflict_count": report.open_conflict_count,
                "resolved_conflict_count": report.resolved_conflict_count,
                "staged_count": report.staged_count,
                "pushed_count": report.pushed_count,
                "state_digest": report.state_digest,
                "at_seq": report.at_seq,
            }

    def audit_log(self) -> list[Mapping[str, Any]]:
        with self._lock:
            return list(self._audit_log)


def main() -> None:
    """Self-check: put, push, pull conflict, resolve, audit."""
    mgr = DataSync()
    chg = mgr.put("k", {"a": 1}, seq=1)
    assert chg.change_id == "chg-1" and chg.verify()
    mgr.put("k", {"a": 2}, seq=2)
    receipt = mgr.push(seq=3)
    assert receipt.change_count == 2 and receipt.verify()
    pull = mgr.pull(
        seq=4,
        remote_changes=[
            {
                "change_id": "r-1",
                "key": "k",
                "version": 3,
                "origin": "remote",
                "deleted": False,
                "value": {"a": 9},
            }
        ],
    )
    assert pull.conflict_ids and pull.verify()
    conflict_id = pull.conflict_ids[0]
    res = mgr.resolve(conflict_id, seq=5, strategy=STRATEGY_MERGE,
                      merged_value={"a": 10})
    assert res.verify() and not mgr.open_conflicts()
    mgr.audit(seq=6)
    print("data-sync OK: put, push, pull, conflict, resolve, audit")


if __name__ == "__main__":
    main()
