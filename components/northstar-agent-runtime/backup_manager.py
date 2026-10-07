"""Backup manager: snapshot/restore/schedule bookkeeping.

A ``BackupManager`` books host-reported backup decisions as a
deterministic single-host state machine:

- ``snapshot(backup_set, seq, kind="full", sources=())`` pins a
  point-in-time snapshot record: ``snap-N`` ids, per-source digest
  pins, a ``sha256:`` chain digest, and a parent link for incrementals.
- ``restore(snapshot_id, seq, target_map=())`` books a restore
  decision as data: ``rst-N`` ids bound to the snapshot digest.
  Restoring an unknown or pruned snapshot raises fail-closed.
- ``schedule(backup_set, cron_spec, seq)`` pins a schedule record
  (``sch-N``); the cron spec is validated fail-closed, and advancing
  to the next due window is an explicit caller-driven
  ``tick(backup_set, at_seq)`` — no wall-clock is read anywhere.
- ``prune(backup_set, keep_last, seq)`` expires all but the newest
  ``keep_last`` snapshots for a set (``pruned`` terminal); restores
  of pruned snapshots are refused.

House style: frozen dataclasses, caller-supplied strictly increasing
int seqs (bool/negative/rewind refused), RLock-guarded, fail-closed
taxonomy, stdlib-only plus the standard ``canonical_json``
try/except fallback, ``sha256:`` digest pins, ``audit.ndjson/1``
events, version pin ``backup-manager.v1``, schema pin
``northstar.backup-manager.v1``, ``main()`` self-check.

Honest scope: this module books *host-reported* backup events; it
cannot copy bytes, reach the filesystem, prove a restore works, or
verify offsite retention. A snapshot record pins *claimed* digests —
garbage claims in, garbage record out. Pair with the host's verified
restore drills for production confidence.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
BACKUP_MANAGER_VERSION = "backup-manager.v1"

#: Schema pin carried by records and audit events.
BACKUP_MANAGER_SCHEMA = "northstar.backup-manager.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

_GENESIS = "genesis"

_KINDS = (
    "snapshot-created",
    "restored",
    "schedule-defined",
    "schedule-ticked",
    "pruned",
    "rejected",
)

_SNAPSHOT_KINDS = ("full", "incremental", "differential")

_CRON_FIELD_RANGES = (0, 59), (0, 23), (1, 31), (1, 12), (0, 6)
_CRON_PART = re.compile(r"^(\*|\d+|\d+-\d+|\*/\d+|\d+-\d+/\d+|\d+(,\d+)+)$")


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class BackupManagerError(Exception):
    """Base error for the backup manager."""


class BadInputError(BackupManagerError):
    """A caller input was malformed."""


class DuplicateSnapshotError(BackupManagerError):
    """A snapshot id or duplicate backup-set window was already taken."""


class UnknownSnapshotError(BackupManagerError):
    """No snapshot with that id exists."""


class ExpiredSnapshotError(BackupManagerError):
    """The snapshot was pruned and can no longer be restored."""


class UnknownScheduleError(BackupManagerError):
    """No schedule for that backup set exists."""


class BadScheduleError(BackupManagerError):
    """The cron spec or schedule parameters were invalid."""


class DuplicateScheduleError(BackupManagerError):
    """A schedule for that backup set already exists."""


class SeqOrderError(BackupManagerError):
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
        raise BadInputError(f"{name} must be a non-empty string")
    return value.strip()


def _check_digest(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != len("sha256:") + 64
        or not all(c in "0123456789abcdef" for c in value[len("sha256:"):])
    ):
        raise BadInputError(f"{name} must be a sha256: + 64-hex digest pin")
    return value


def _check_cron(spec: Any) -> str:
    if not isinstance(spec, str):
        raise BadScheduleError("cron_spec must be a string")
    text = spec.strip()
    fields = text.split()
    if len(fields) != 5:
        raise BadScheduleError("cron_spec must have exactly 5 fields")
    for part, (lo, hi) in zip(fields, _CRON_FIELD_RANGES):
        if not _CRON_PART.match(part):
            raise BadScheduleError(f"bad cron field: {part!r}")
        # Validate numeric bounds for plain literals.
        for token in part.replace(",", " ").split():
            nums = re.findall(r"\d+", token)
            for n in nums:
                if not lo <= int(n) <= hi:
                    raise BadScheduleError(f"cron field out of range: {n!r}")
    return text


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([BACKUP_MANAGER_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


def _norm_sources(sources: Sequence[Sequence[str]]) -> Tuple[Tuple[str, str], ...]:
    """Normalize host-reported (path, digest) source pairs."""
    if not isinstance(sources, (list, tuple)):
        raise BadInputError("sources must be a sequence of (path, digest) pairs")
    seen: set = set()
    out: List[Tuple[str, str]] = []
    for item in sources:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise BadInputError("each source must be a (path, digest) pair")
        path = _check_nonempty_str(item[0], "source path")
        digest = _check_digest(item[1], "source digest")
        if path in seen:
            raise BadInputError(f"duplicate source path: {path!r}")
        seen.add(path)
        out.append((path, digest))
    return tuple(sorted(out))


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def backup_manager_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the backup manager."""
    if kind not in _KINDS:
        raise BackupManagerError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise BackupManagerError("detail must be a mapping")
    # Source contents and digests never cross the audit boundary; ids
    # and pins only.
    banned = {"sources", "contents", "target_map", "cron_spec"}
    if any(k in detail for k in banned):
        raise BackupManagerError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": BACKUP_MANAGER_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SnapshotRecord:
    """One pinned backup snapshot (frozen)."""

    snapshot_id: str
    backup_set: str
    kind: str
    seq: int
    sources: Tuple[Tuple[str, str], ...]
    parent_id: Optional[str]
    prev_digest: str
    digest: str

    def verify(self) -> None:
        """Re-derive the digest pin; raise on mismatch."""
        expected = _pin(
            "snapshot",
            self.snapshot_id,
            self.backup_set,
            self.kind,
            self.seq,
            [list(s) for s in self.sources],
            self.parent_id,
            self.prev_digest,
        )
        if self.digest != expected:
            raise BackupManagerError("snapshot digest mismatch")


@dataclass(frozen=True)
class RestoreRecord:
    """One booked restore decision (frozen)."""

    restore_id: str
    snapshot_id: str
    snapshot_digest: str
    seq: int
    target_count: int
    prev_digest: str
    digest: str

    def verify(self) -> None:
        """Re-derive the digest pin; raise on mismatch."""
        expected = _pin(
            "restore",
            self.restore_id,
            self.snapshot_id,
            self.snapshot_digest,
            self.seq,
            self.target_count,
            self.prev_digest,
        )
        if self.digest != expected:
            raise BackupManagerError("restore digest mismatch")


@dataclass(frozen=True)
class ScheduleRecord:
    """One pinned backup schedule (frozen)."""

    schedule_id: str
    backup_set: str
    cron_spec: str
    seq: int
    last_tick_seq: Optional[int]
    prev_digest: str
    digest: str

    def verify(self) -> None:
        """Re-derive the digest pin; raise on mismatch."""
        expected = _pin(
            "schedule",
            self.schedule_id,
            self.backup_set,
            self.cron_spec,
            self.seq,
            self.last_tick_seq,
            self.prev_digest,
        )
        if self.digest != expected:
            raise BackupManagerError("schedule digest mismatch")


@dataclass(frozen=True)
class PruneReport:
    """One retention-prune decision (frozen)."""

    backup_set: str
    seq: int
    keep_last: int
    expired_ids: Tuple[str, ...]
    retained_ids: Tuple[str, ...]
    digest: str


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class BackupManager:
    """Deterministic snapshot/restore/schedule bookkeeping ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._chain: List[str] = [_GENESIS]
        self._snapshots: Dict[str, SnapshotRecord] = {}
        self._restores: Dict[str, RestoreRecord] = {}
        self._schedules: Dict[str, ScheduleRecord] = {}
        self._pruned: set = set()
        self._set_seq: Dict[str, List[str]] = {}  # backup_set -> ordered snapshot ids
        self._audit: List[Dict[str, Any]] = []
        self._snap_n = 0
        self._restore_n = 0
        self._sched_n = 0

    # -- internals ------------------------------------------------------

    def _advance_seq(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last={self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, detail: Mapping[str, Any]) -> None:
        self._audit.append(
            backup_manager_audit_event(kind, detail, self._last_seq)
        )

    def _reject_locked(self, reason: str) -> None:
        self._emit("rejected", {"reason": reason})

    def _record(self, tag: str, *parts: Any) -> Tuple[str, str]:
        """Compute a record digest and advance the chain.

        Returns ``(record_digest, prev_digest)``.
        """
        prev_digest = self._chain[-1]
        digest = _pin(tag, *parts, prev_digest)
        self._chain.append(digest)
        return digest, prev_digest

    # -- snapshots ------------------------------------------------------

    def snapshot(
        self,
        backup_set: str,
        seq: int,
        kind: str = "full",
        sources: Sequence[Sequence[str]] = (),
        parent_id: Optional[str] = None,
    ) -> SnapshotRecord:
        """Pin a snapshot record for ``backup_set``."""
        with self._lock:
            self._advance_seq(seq)
            name = _check_nonempty_str(backup_set, "backup_set")
            if kind not in _SNAPSHOT_KINDS:
                self._reject_locked(f"unknown snapshot kind: {kind!r}")
                raise BadInputError(f"unknown snapshot kind: {kind!r}")
            srcs = _norm_sources(sources)
            if parent_id is not None:
                if parent_id not in self._snapshots:
                    self._reject_locked("unknown parent snapshot")
                    raise UnknownSnapshotError(f"unknown parent snapshot: {parent_id!r}")
                if parent_id in self._pruned:
                    self._reject_locked("parent snapshot pruned")
                    raise ExpiredSnapshotError(f"parent snapshot pruned: {parent_id!r}")
                if kind == "full":
                    self._reject_locked("full snapshot with parent")
                    raise BadInputError("full snapshots take no parent")
            else:
                if kind in ("incremental", "differential"):
                    self._reject_locked("non-full snapshot without parent")
                    raise BadInputError(
                        f"{kind} snapshots require a parent_id"
                    )
            self._snap_n += 1
            snapshot_id = f"snap-{self._snap_n}"
            digest, prev_digest = self._record(
                "snapshot",
                snapshot_id,
                name,
                kind,
                seq,
                [list(s) for s in srcs],
                parent_id,
            )
            record = SnapshotRecord(
                snapshot_id=snapshot_id,
                backup_set=name,
                kind=kind,
                seq=seq,
                sources=srcs,
                parent_id=parent_id,
                prev_digest=prev_digest,
                digest=digest,
            )
            self._snapshots[snapshot_id] = record
            self._set_seq.setdefault(name, []).append(snapshot_id)
            self._emit(
                "snapshot-created",
                {
                    "snapshot_id": snapshot_id,
                    "backup_set": name,
                    "kind": kind,
                    "digest": digest,
                },
            )
            return record

    def snapshot_record(self, snapshot_id: str) -> SnapshotRecord:
        """Read a snapshot record by id."""
        with self._lock:
            try:
                return self._snapshots[snapshot_id]
            except KeyError:
                raise UnknownSnapshotError(
                    f"unknown snapshot: {snapshot_id!r}"
                ) from None

    # -- restores -------------------------------------------------------

    def restore(
        self,
        snapshot_id: str,
        seq: int,
        target_map: Sequence[Sequence[str]] = (),
    ) -> RestoreRecord:
        """Book a restore decision bound to a snapshot's digest."""
        with self._lock:
            self._advance_seq(seq)
            record = self._snapshots.get(snapshot_id)
            if record is None:
                self._reject_locked("unknown snapshot")
                raise UnknownSnapshotError(f"unknown snapshot: {snapshot_id!r}")
            if snapshot_id in self._pruned:
                self._reject_locked("snapshot pruned")
                raise ExpiredSnapshotError(f"snapshot pruned: {snapshot_id!r}")
            if not isinstance(target_map, (list, tuple)):
                self._reject_locked("bad target_map")
                raise BadInputError("target_map must be a sequence of (src, dst) pairs")
            for item in target_map:
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    self._reject_locked("bad target_map entry")
                    raise BadInputError("each target must be a (src, dst) pair")
                _check_nonempty_str(item[0], "target src")
                _check_nonempty_str(item[1], "target dst")
            self._restore_n += 1
            restore_id = f"rst-{self._restore_n}"
            digest, prev_digest = self._record(
                "restore",
                restore_id,
                snapshot_id,
                record.digest,
                seq,
                len(target_map),
            )
            report = RestoreRecord(
                restore_id=restore_id,
                snapshot_id=snapshot_id,
                snapshot_digest=record.digest,
                seq=seq,
                target_count=len(target_map),
                prev_digest=prev_digest,
                digest=digest,
            )
            self._restores[restore_id] = report
            self._emit(
                "restored",
                {
                    "restore_id": restore_id,
                    "snapshot_id": snapshot_id,
                    "digest": digest,
                },
            )
            return report

    def restore_record(self, restore_id: str) -> RestoreRecord:
        """Read a restore record by id."""
        with self._lock:
            try:
                return self._restores[restore_id]
            except KeyError:
                raise BackupManagerError(
                    f"unknown restore: {restore_id!r}"
                ) from None

    # -- schedules ------------------------------------------------------

    def schedule(
        self, backup_set: str, cron_spec: str, seq: int
    ) -> ScheduleRecord:
        """Pin a schedule record for ``backup_set``."""
        with self._lock:
            self._advance_seq(seq)
            name = _check_nonempty_str(backup_set, "backup_set")
            spec = _check_cron(cron_spec)
            if name in self._schedules:
                self._reject_locked("duplicate schedule")
                raise DuplicateScheduleError(
                    f"schedule for {name!r} already exists"
                )
            self._sched_n += 1
            schedule_id = f"sch-{self._sched_n}"
            digest, prev_digest = self._record(
                "schedule", schedule_id, name, spec, seq, None
            )
            record = ScheduleRecord(
                schedule_id=schedule_id,
                backup_set=name,
                cron_spec=spec,
                seq=seq,
                last_tick_seq=None,
                prev_digest=prev_digest,
                digest=digest,
            )
            self._schedules[name] = record
            self._emit(
                "schedule-defined",
                {"schedule_id": schedule_id, "backup_set": name, "digest": digest},
            )
            return record

    def tick(self, backup_set: str, at_seq: int) -> ScheduleRecord:
        """Advance a schedule's due window to ``at_seq`` (caller-driven)."""
        with self._lock:
            self._advance_seq(at_seq)
            name = _check_nonempty_str(backup_set, "backup_set")
            record = self._schedules.get(name)
            if record is None:
                self._reject_locked("unknown schedule")
                raise UnknownScheduleError(f"no schedule for {name!r}")
            if record.last_tick_seq is not None and at_seq <= record.last_tick_seq:
                self._reject_locked("tick not after last tick")
                raise BadScheduleError("tick must advance beyond the last tick")
            digest, prev_digest = self._record(
                "schedule",
                record.schedule_id,
                name,
                record.cron_spec,
                record.seq,
                at_seq,
            )
            updated = ScheduleRecord(
                schedule_id=record.schedule_id,
                backup_set=name,
                cron_spec=record.cron_spec,
                seq=record.seq,
                last_tick_seq=at_seq,
                prev_digest=prev_digest,
                digest=digest,
            )
            self._schedules[name] = updated
            self._emit(
                "schedule-ticked",
                {
                    "schedule_id": record.schedule_id,
                    "backup_set": name,
                    "at_seq": at_seq,
                    "digest": digest,
                },
            )
            return updated

    def schedule_record(self, backup_set: str) -> ScheduleRecord:
        """Read a schedule record by backup-set name."""
        with self._lock:
            try:
                return self._schedules[backup_set]
            except KeyError:
                raise UnknownScheduleError(
                    f"no schedule for {backup_set!r}"
                ) from None

    # -- retention --------------------------------------------------------

    def prune(self, backup_set: str, keep_last: int, seq: int) -> PruneReport:
        """Expire all but the newest ``keep_last`` snapshots for a set."""
        with self._lock:
            self._advance_seq(seq)
            name = _check_nonempty_str(backup_set, "backup_set")
            if isinstance(keep_last, bool) or not isinstance(keep_last, int):
                self._reject_locked("bad keep_last")
                raise BadInputError("keep_last must be an int")
            if keep_last < 0:
                self._reject_locked("negative keep_last")
                raise BadInputError("keep_last must be non-negative")
            ids = self._set_seq.get(name, [])
            live = [i for i in ids if i not in self._pruned]
            if keep_last >= len(live):
                retained = tuple(live)
                expired: Tuple[str, ...] = ()
            else:
                retained = tuple(live[-keep_last:]) if keep_last else ()
                expired = tuple(live[: len(live) - keep_last])
            for sid in expired:
                self._pruned.add(sid)
            digest, _ = self._record(
                "prune", name, seq, keep_last, list(expired), list(retained)
            )
            report = PruneReport(
                backup_set=name,
                seq=seq,
                keep_last=keep_last,
                expired_ids=expired,
                retained_ids=retained,
                digest=digest,
            )
            self._emit(
                "pruned",
                {
                    "backup_set": name,
                    "keep_last": keep_last,
                    "expired": list(expired),
                    "retained": list(retained),
                    "digest": digest,
                },
            )
            return report

    # -- views ------------------------------------------------------------

    def snapshot_ids(self) -> Tuple[str, ...]:
        """All snapshot ids in insertion order."""
        with self._lock:
            return tuple(self._snapshots)

    def pruned_ids(self) -> Tuple[str, ...]:
        """Ids of pruned (expired) snapshots."""
        with self._lock:
            return tuple(sorted(self._pruned))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """The emitted audit event trail."""
        with self._lock:
            return tuple(self._audit)

    def as_dict(self) -> Dict[str, Any]:
        """Snapshot of ledger state (pins only, no source contents)."""
        with self._lock:
            return {
                "schema": BACKUP_MANAGER_SCHEMA,
                "module": BACKUP_MANAGER_VERSION,
                "snapshots": len(self._snapshots),
                "restores": len(self._restores),
                "schedules": len(self._schedules),
                "pruned": len(self._pruned),
                "chain_head": self._chain[-1],
                "last_seq": self._last_seq,
            }


def main() -> None:
    """Self-check: snapshot, schedule, restore, prune."""
    mgr = BackupManager()
    src = ("etc/app.conf", "sha256:" + "ab" * 32)
    snap = mgr.snapshot("app", 1, kind="full", sources=[src])
    snap.verify()
    sched = mgr.schedule("app", "0 2 * * *", 2)
    sched.verify()
    mgr.tick("app", 3)
    rst = mgr.restore(snap.snapshot_id, 4, target_map=[("/etc/app.conf", "/etc/app.conf")])
    rst.verify()
    report = mgr.prune("app", 1, 5)
    assert report.expired_ids == ()
    print("backup-manager OK: snapshot, schedule, restore, prune, pins")


if __name__ == "__main__":
    main()
