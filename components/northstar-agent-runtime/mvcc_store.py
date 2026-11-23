"""MVCC store: snapshot-isolated multi-version key-value storage.

Multi-version concurrency control (Bernstein & Goodman 1983): readers never
block writers. A transaction observes a *snapshot* of the committed state as
of its begin point; concurrent writers are serialized at commit time with
first-committer-wins write-write conflict detection.

* **Snapshot isolation** -- ``begin(txn_id)`` captures ``snapshot_point``
  (the current commit counter). ``read`` sees the latest committed version
  with ``commit_seq <= snapshot_point``; a transaction also sees its own
  uncommitted writes (read-your-writes).
* **First-committer-wins** -- ``commit`` fails closed with
  ``WriteConflictError`` when another transaction committed a write to the
  same key after this transaction's snapshot point. Blind writes that do
  not overlap commit fine.
* **No wall-clock** -- ordering comes from an internal monotonic commit
  counter (a logical clock, deterministic under a deterministic call
  sequence), never from time. Audit events additionally carry
  caller-supplied int seqs.

House style: frozen dataclasses, fail-closed validation
(``TypeError``/``ValueError``/``WriteConflictError`` on malformed or
conflicting input), stdlib-only, deterministic, version and schema pins,
``main()`` self-check.

Honest scope: this is the *state machine* of snapshot isolation, not a
database engine -- values are pinned by ``sha256:`` digests of canonical
JSON; values that are not JSON-canonicalizable (NaN/inf, non-str dict keys,
arbitrary objects) are rejected fail-closed rather than hashed ambiguously.
There is no persistence, no deadlock detection (MVCC has no read-write
locks to deadlock), and no protection against a host that mutates the
store outside the API. A commit record means "this transaction's writes
are now the latest", never "no serialization anomaly is possible"
(snapshot isolation permits write-skew by design; predicate constraints
are the host's job).

Version pin: mvcc-store.v1
Schema pin: northstar.mvcc-store.v1
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

#: Module version.
MVCC_VERSION = "mvcc-store.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.mvcc-store.v1"


class MVCCError(Exception):
    """Base class for MVCC store errors."""


class WriteConflictError(MVCCError):
    """Raised when a commit loses first-committer-wins conflict detection.

    Carries the txn_id and the conflicting keys.
    """

    def __init__(self, txn_id: str, keys: Tuple[str, ...], commit_seq: int):
        self.txn_id = txn_id
        self.conflicting_keys = keys
        super().__init__(
            f"txn {txn_id!r} aborted: write-write conflict on "
            f"{', '.join(keys)} at commit seq {commit_seq}"
        )


def _canonical(value: Any) -> str:
    """Canonical JSON for digest pinning (sorted keys, compact separators)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _check_value(value: Any) -> None:
    """Reject values that are not JSON-canonicalizable, fail-closed."""
    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, float):
            raise TypeError("NaN/inf floats are not canonicalizable")
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise TypeError("NaN/inf floats are not canonicalizable")
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _check_value(item)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError("dict keys must be str for canonical digest")
            _check_value(v)
        return
    raise TypeError(f"value of type {type(value).__name__} is not canonicalizable")


def _check_txn_id(txn_id: Any) -> str:
    if not isinstance(txn_id, str):
        raise TypeError("txn_id must be str")
    if not txn_id:
        raise ValueError("txn_id must be non-empty")
    return txn_id


def _check_key(key: Any) -> str:
    if not isinstance(key, str):
        raise TypeError("key must be str")
    if not key:
        raise ValueError("key must be non-empty")
    return key


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Version:
    """One committed version of a key."""

    key: str
    value: Any
    value_digest: str
    commit_seq: int
    txn_id: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "value_digest": self.value_digest,
            "commit_seq": self.commit_seq,
            "txn_id": self.txn_id,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class CommitRecord:
    """Result of a successful commit."""

    txn_id: str
    commit_seq: int
    keys: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "txn_id": self.txn_id,
            "commit_seq": self.commit_seq,
            "keys": list(self.keys),
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class ReadResult:
    """Result of a read: value plus the version it came from."""

    value: Any
    found: bool
    commit_seq: Optional[int]
    txn_id: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "found": self.found,
            "commit_seq": self.commit_seq,
            "txn_id": self.txn_id,
            "schema": SCHEMA_PIN,
        }


class _ActiveTxn:
    """Mutable per-transaction state (internal only)."""

    __slots__ = ("txn_id", "snapshot_point", "write_set")

    def __init__(self, txn_id: str, snapshot_point: int):
        self.txn_id = txn_id
        self.snapshot_point = snapshot_point
        self.write_set: Dict[str, Any] = {}


class MVCCStore:
    """Snapshot-isolated multi-version key-value store."""

    def __init__(self) -> None:
        # key -> tuple of Version, newest last (append-only).
        self._versions: Dict[str, Tuple[Version, ...]] = {}
        self._active: Dict[str, _ActiveTxn] = {}
        # Logical commit clock: incremented once per successful commit.
        self._commit_seq: int = 0

    # -- transaction lifecycle ----------------------------------------

    def begin(self, txn_id: str) -> int:
        """Start a transaction; returns its snapshot point."""
        txn_id = _check_txn_id(txn_id)
        if txn_id in self._active:
            raise MVCCError(f"transaction {txn_id!r} already active")
        self._active[txn_id] = _ActiveTxn(txn_id, self._commit_seq)
        return self._commit_seq

    def commit(self, txn_id: str) -> CommitRecord:
        """Commit a transaction (first-committer-wins conflict detection)."""
        txn_id = _check_txn_id(txn_id)
        txn = self._active.get(txn_id)
        if txn is None:
            raise MVCCError(f"no active transaction {txn_id!r}")
        conflicting = tuple(
            sorted(
                key
                for key in txn.write_set
                if any(
                    v.commit_seq > txn.snapshot_point
                    for v in self._versions.get(key, ())
                )
            )
        )
        if conflicting:
            del self._active[txn_id]
            raise WriteConflictError(txn_id, conflicting, self._commit_seq + 1)
        self._commit_seq += 1
        seq = self._commit_seq
        keys = tuple(sorted(txn.write_set))
        for key in keys:
            value = txn.write_set[key]
            version = Version(
                key=key,
                value=value,
                value_digest=_digest(value),
                commit_seq=seq,
                txn_id=txn_id,
            )
            self._versions[key] = self._versions.get(key, ()) + (version,)
        del self._active[txn_id]
        return CommitRecord(txn_id=txn_id, commit_seq=seq, keys=keys)

    def abort(self, txn_id: str) -> None:
        """Abort a transaction, discarding its write set."""
        txn_id = _check_txn_id(txn_id)
        if txn_id not in self._active:
            raise MVCCError(f"no active transaction {txn_id!r}")
        del self._active[txn_id]

    # -- data access ---------------------------------------------------

    def write(self, key: str, value: Any, txn_id: str) -> None:
        """Buffer a write in the transaction's write set (not yet visible)."""
        key = _check_key(key)
        _check_value(value)
        txn_id = _check_txn_id(txn_id)
        txn = self._active.get(txn_id)
        if txn is None:
            raise MVCCError(f"no active transaction {txn_id!r}")
        txn.write_set[key] = value

    def read(self, key: str, txn_id: str) -> ReadResult:
        """Read under snapshot isolation (read-your-writes included)."""
        key = _check_key(key)
        txn_id = _check_txn_id(txn_id)
        txn = self._active.get(txn_id)
        if txn is None:
            raise MVCCError(f"no active transaction {txn_id!r}")
        if key in txn.write_set:
            return ReadResult(
                value=txn.write_set[key],
                found=True,
                commit_seq=None,
                txn_id=txn_id,
            )
        latest: Optional[Version] = None
        for version in self._versions.get(key, ()):
            if version.commit_seq <= txn.snapshot_point:
                latest = version
        if latest is None:
            return ReadResult(value=None, found=False, commit_seq=None, txn_id=None)
        return ReadResult(
            value=latest.value,
            found=True,
            commit_seq=latest.commit_seq,
            txn_id=latest.txn_id,
        )

    # -- views --------------------------------------------------------

    def active_txns(self) -> Tuple[str, ...]:
        return tuple(sorted(self._active))

    def commit_seq(self) -> int:
        return self._commit_seq

    def versions(self, key: str) -> Tuple[Version, ...]:
        return self._versions.get(_check_key(key), ())


def mvcc_audit_event(
    kind: str, record: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an audit.ndjson/1-style record for an MVCC event."""
    valid = {"begin", "write", "commit", "abort", "conflict"}
    if kind not in valid:
        raise ValueError(f"unknown audit kind {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    if not isinstance(record, Mapping):
        raise TypeError("record must be a mapping")
    return {
        "event": "audit.ndjson/1",
        "kind": f"mvcc-{kind}",
        "record": dict(record),
        "audit_seq": seq,
        "schema": SCHEMA_PIN,
        "module_version": MVCC_VERSION,
    }


def main() -> None:
    store = MVCCStore()
    store.begin("t1")
    store.write("k", {"n": 1}, "t1")
    rec = store.commit("t1")
    assert rec.commit_seq == 1 and rec.keys == ("k",)
    store.begin("t2")
    got = store.read("k", "t2")
    assert got.found and got.value == {"n": 1}
    # Snapshot isolation: t3 begins, t4 writes+commits, t3 still sees old.
    store.begin("t3")
    store.begin("t4")
    store.write("k", {"n": 2}, "t4")
    store.commit("t4")
    assert store.read("k", "t3").value == {"n": 1}
    # First-committer-wins: t3 also wrote k -> conflict.
    store.write("k", {"n": 3}, "t3")
    try:
        store.commit("t3")
        raise AssertionError("expected WriteConflictError")
    except WriteConflictError as exc:
        assert exc.conflicting_keys == ("k",)
    print("mvcc-store OK: snapshot isolation, read-your-writes, first-committer-wins")


if __name__ == "__main__":
    main()
