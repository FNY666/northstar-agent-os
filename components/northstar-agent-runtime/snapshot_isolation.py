"""Snapshot isolation: lock-free multi-version concurrency for agent state.

Each transaction reads from a *snapshot* -- the set of committed versions
visible at its start -- and stages its writes in a private workspace. On
commit, the first-committer-wins rule is enforced: if any key in the
transaction's write set was committed by a *different* transaction after
this transaction's snapshot was taken, the commit fails with
``SnapshotConflict`` and nothing is applied. Reads never block, writes
never block each other; only conflicting commits are refused.

Berenson et al. (1995) semantics, production-primitive half:

* ``SIDatabase`` -- the committed multi-version store. Versions are
  append-only per key; the store never rewrites history.
* ``SIDatabase.begin(txn_id)`` -- mints a ``SnapshotTxn`` whose
  ``start_seq`` is the store's last committed sequence number.
* ``SnapshotTxn.read(key)`` -- own writes first (read-your-own-writes),
  otherwise the latest committed version with ``commit_seq <= start_seq``.
* ``SnapshotTxn.write(key, value)`` / ``SnapshotTxn.delete(key)`` -- stage
  into the private workspace; invisible to everyone until commit.
* ``SnapshotTxn.commit(seq)`` -- caller-supplied commit seq, strictly
  greater than the store's last committed seq (monotonic ordering is the
  caller's responsibility; the store verifies it). Applies all staged
  writes atomically or raises ``SnapshotConflict`` naming the conflicting
  keys. ``SnapshotTxn.abort()`` discards the workspace.

House style: frozen dataclasses, no wall-clock (caller-supplied int seqs),
fail-closed validation (``TypeError``/``ValueError``/``SnapshotError`` on
malformed input or protocol violation), stdlib-only, deterministic,
version and schema pins, ``main()`` self-check.

Honest scope: this is *snapshot isolation*, not serializability. The
classic write-skew anomaly is real here: two transactions can each read
X and Y and then write the other, with no write-write conflict, so both
commit -- the invariant "not (X and Y)" can break. Hosts that need the
missing invariant must add predicate checks or use a stricter protocol.
A commit record pins write digests, never raw values beyond the store's
own copy; a ``SnapshotConflict`` means "another transaction won the key",
never "the data is corrupt".

Version pin: snapshot-isolation.v1
Schema pin: northstar.snapshot-isolation.v1
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

SNAPSHOT_ISOLATION_VERSION = "snapshot-isolation.v1"
SCHEMA_PIN = "northstar.snapshot-isolation.v1"

_GENESIS_SEQ = 0


class SnapshotError(Exception):
    """Base class for snapshot-isolation errors."""


class SnapshotConflict(SnapshotError):
    """Raised when a commit loses the first-committer-wins race.

    Carries the transaction id and the conflicting keys (sorted): keys the
    transaction wrote that another transaction committed after this
    transaction's snapshot was taken.
    """

    def __init__(self, txn_id: str, conflicting_keys: Tuple[str, ...]):
        self.txn_id = txn_id
        self.conflicting_keys = conflicting_keys
        super().__init__(
            f"snapshot conflict for txn {txn_id!r}: "
            f"keys concurrently committed: {', '.join(conflicting_keys)}"
        )


def _require_key(key: Any) -> str:
    if not isinstance(key, str):
        raise TypeError(f"key must be a str, got {type(key).__name__}")
    if not key:
        raise ValueError("key must be non-empty")
    return key


def _require_txn_id(txn_id: Any) -> str:
    if not isinstance(txn_id, str):
        raise TypeError(f"txn_id must be a str, got {type(txn_id).__name__}")
    if not txn_id:
        raise ValueError("txn_id must be non-empty")
    return txn_id


def _require_seq(seq: Any, name: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"{name} must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError(f"{name} must be non-negative")
    return seq


def _canonical(value: Any) -> bytes:
    """Canonical JSON bytes; rejects non-canonicalizable input fail-closed."""
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        raise ValueError("value must not be NaN or infinite")
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"value is not JSON-canonicalizable: {exc}") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True)
class VersionRecord:
    """One committed version of a key.

    ``deleted`` marks a tombstone: the key was removed at ``commit_seq``.
    """

    key: str
    value: Any
    deleted: bool
    commit_seq: int
    writer_txn_id: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "key": self.key,
            "value_digest": None if self.deleted else _digest(self.value),
            "deleted": self.deleted,
            "commit_seq": self.commit_seq,
            "writer_txn_id": self.writer_txn_id,
        }


@dataclass(frozen=True)
class CommitRecord:
    """Frozen proof of one committed transaction."""

    txn_id: str
    commit_seq: int
    write_keys: Tuple[str, ...]
    start_seq: int

    def digest(self) -> str:
        body = {
            "txn_id": self.txn_id,
            "commit_seq": self.commit_seq,
            "write_keys": list(self.write_keys),
            "start_seq": self.start_seq,
        }
        return "sha256:" + hashlib.sha256(_canonical(body)).hexdigest()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "txn_id": self.txn_id,
            "commit_seq": self.commit_seq,
            "write_keys": list(self.write_keys),
            "start_seq": self.start_seq,
            "digest": self.digest(),
        }


@dataclass(frozen=True)
class ReadResult:
    """Outcome of ``SnapshotTxn.read``: found flag plus the value (or None)."""

    key: str
    found: bool
    value: Any = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "key": self.key,
            "found": self.found,
            "value_digest": None if not self.found else _digest(self.value),
        }


class SIDatabase:
    """Multi-version committed store with snapshot-isolated transactions.

    ``_versions`` maps key -> list of ``VersionRecord`` in commit-seq order
    (append-only; history is never rewritten). ``_last_commit_seq`` is the
    store's own monotonic counter, advanced only by successful commits.
    RLock-guarded so a host may drive concurrent transactions from threads;
    isolation itself comes from the version protocol, not the lock.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._versions: Dict[str, List[VersionRecord]] = {}
        self._last_commit_seq: int = _GENESIS_SEQ

    def current_seq(self) -> int:
        """Last committed sequence number (the snapshot point for new txns)."""
        with self._lock:
            return self._last_commit_seq

    def begin(self, txn_id: Any) -> "SnapshotTxn":
        """Open a transaction; its snapshot is everything committed so far."""
        txn_id = _require_txn_id(txn_id)
        with self._lock:
            return SnapshotTxn(
                txn_id=txn_id,
                start_seq=self._last_commit_seq,
                _db=self,
            )

    # -- internal primitives (called by SnapshotTxn under the store lock) --

    def _latest_at(self, key: str, start_seq: int) -> Optional[VersionRecord]:
        """Latest committed version of ``key`` visible at ``start_seq``."""
        versions = self._versions.get(key)
        if not versions:
            return None
        best: Optional[VersionRecord] = None
        for record in versions:
            if record.commit_seq <= start_seq:
                best = record
            else:
                break
        return best

    def _latest_committed(self, key: str) -> Optional[VersionRecord]:
        versions = self._versions.get(key)
        return versions[-1] if versions else None


class SnapshotTxn:
    """One snapshot-isolated transaction (stateful handle, not frozen).

    Reads see the snapshot; writes stage in ``_writes`` as
    ``key -> (value, deleted)`` and are invisible until ``commit``.
    After ``commit`` or ``abort`` the handle is closed and every further
    operation raises ``SnapshotError``.
    """

    def __init__(self, txn_id: str, start_seq: int, _db: SIDatabase):
        self._txn_id = txn_id
        self._start_seq = start_seq
        self._db = _db
        self._writes: Dict[str, Tuple[Any, bool]] = {}
        self._closed = False

    @property
    def txn_id(self) -> str:
        return self._txn_id

    @property
    def start_seq(self) -> int:
        return self._start_seq

    @property
    def is_closed(self) -> bool:
        return self._closed

    def _ensure_open(self) -> None:
        if self._closed:
            raise SnapshotError(f"transaction {self._txn_id!r} is closed")

    def read(self, key: Any) -> ReadResult:
        """Read ``key`` from the snapshot (own writes first)."""
        key = _require_key(key)
        self._ensure_open()
        with self._db._lock:
            if key in self._writes:
                value, deleted = self._writes[key]
                if deleted:
                    return ReadResult(key=key, found=False)
                return ReadResult(key=key, found=True, value=value)
            record = self._db._latest_at(key, self._start_seq)
            if record is None or record.deleted:
                return ReadResult(key=key, found=False)
            return ReadResult(key=key, found=True, value=record.value)

    def write(self, key: Any, value: Any) -> None:
        """Stage ``key = value`` in the private workspace."""
        key = _require_key(key)
        _canonical(value)  # fail-closed: value must be digest-pinnable
        self._ensure_open()
        self._writes[key] = (value, False)

    def delete(self, key: Any) -> None:
        """Stage a tombstone for ``key`` in the private workspace."""
        key = _require_key(key)
        self._ensure_open()
        self._writes[key] = (None, True)

    def commit(self, seq: Any) -> CommitRecord:
        """Commit atomically, or raise ``SnapshotConflict``.

        ``seq`` is the caller-supplied commit sequence number; it must be
        strictly greater than the store's last committed seq (the store
        verifies monotonicity -- timestamps must order, or replay breaks).
        First-committer-wins: for every key in the write set, the latest
        committed version must predate this transaction's snapshot; a newer
        committed write means another transaction won the key.
        """
        seq = _require_seq(seq, "seq")
        self._ensure_open()
        with self._db._lock:
            if seq <= self._db._last_commit_seq:
                raise SnapshotError(
                    f"commit seq {seq} must exceed last committed seq "
                    f"{self._db._last_commit_seq}"
                )
            conflicts: List[str] = []
            for key in self._writes:
                latest = self._db._latest_committed(key)
                if latest is not None and latest.commit_seq > self._start_seq:
                    conflicts.append(key)
            if conflicts:
                raise SnapshotConflict(self._txn_id, tuple(sorted(conflicts)))
            for key, (value, deleted) in self._writes.items():
                record = VersionRecord(
                    key=key,
                    value=value,
                    deleted=deleted,
                    commit_seq=seq,
                    writer_txn_id=self._txn_id,
                )
                self._db._versions.setdefault(key, []).append(record)
            self._db._last_commit_seq = seq
            self._closed = True
            return CommitRecord(
                txn_id=self._txn_id,
                commit_seq=seq,
                write_keys=tuple(sorted(self._writes)),
                start_seq=self._start_seq,
            )

    def abort(self) -> None:
        """Discard the workspace; the handle is closed."""
        self._ensure_open()
        self._writes.clear()
        self._closed = True

    def pending_keys(self) -> Tuple[str, ...]:
        """Keys staged in the workspace (sorted), for inspection only."""
        self._ensure_open()
        return tuple(sorted(self._writes))


_AUDIT_KINDS = ("begun", "committed", "aborted", "conflict")


def snapshot_audit_event(
    kind: str, txn_id: Any, seq: Any, detail: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a snapshot event."""
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {_AUDIT_KINDS}, got {kind!r}")
    txn_id = _require_txn_id(txn_id)
    seq = _require_seq(seq, "seq")
    if detail is not None:
        _canonical(detail)
        payload: Dict[str, Any] = dict(detail)
    else:
        payload = {}
    return {
        "schema": "audit.ndjson/1",
        "kind": f"snapshot-isolation.{kind}",
        "txn_id": txn_id,
        "audit_seq": seq,
        "module": SCHEMA_PIN,
        **payload,
    }


def main() -> None:
    db = SIDatabase()
    t1 = db.begin("t1")
    t1.write("balance", 100)
    rec = t1.commit(1)
    assert rec.commit_seq == 1 and rec.write_keys == ("balance",)
    t2 = db.begin("t2")
    got = t2.read("balance")
    assert got.found and got.value == 100
    t2.abort()
    print("snapshot-isolation OK: snapshot read, atomic commit, abort")


if __name__ == "__main__":
    main()
