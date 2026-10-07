"""Raft log: persistent-state log replication bookkeeping for Raft.

Research motivation: Raft (Ongaro & Ousterhout 2014) replicates a log
of state-machine commands: a leader appends entries with its term,
replicates them to followers, and commits an entry once a majority has
it. The leader commits entries *in log order*, and safety (section
5.4.2) pins that a leader may only advance the commit index through an
entry from its *current* term -- older-term entries piggyback on newer
ones.

Public API:

- ``RaftLog(node_id)`` -- per-node log bookkeeping. Simulated: no
  transport, no timers, no elections -- the host drives everything.
- ``append(term, payload_digest, seq)`` -> frozen ``AppendRecord``.
  Appends one entry with index ``last_log_index + 1``. The entry term
  must be ``>= current_term`` (a node never appends older-term
  entries). Payloads are pinned by ``sha256:`` digest only -- raw values
  never enter a record.
- ``set_term(term, seq)`` -> frozen ``TermRecord``. Advances the
  current term; term regression is refused fail-closed.
- ``truncate_after(index, seq)`` -> frozen ``TruncateRecord``. Leader
  force: drops all entries with index > ``index`` (log-consistency
  repair). Committed/applied entries are never dropped -- truncation
  at or below the commit index is refused.
- ``commit(index, seq)`` -> frozen ``CommitRecord``. Advances the
  commit index to ``index``. Rules: ``index`` must be an existing
  entry, must be strictly greater than the current commit index
  (commit index never moves backward), and the entry at ``index``
  must carry the *current* term -- the Raft section 5.4.2 safety rule.
- ``apply(index, seq)`` -> frozen ``ApplyRecord``. Applies one
  committed entry to the state machine, in exact index order:
  ``index`` must equal ``last_applied + 1`` and must be ``<=
  commit_index``.
- ``snapshot(index, state_digest, seq)`` -> frozen ``SnapshotRecord``.
  Log compaction: drops all log entries with index ``<= index``
  (``index`` must be committed), and pins ``last_included_index``
  / ``last_included_term`` for InstallSnapshot-style metadata.
- Read views (seq validated, never consumed, no audit rows):
  ``entry(index, seq)``, ``entries(seq)``, ``last_log_index(seq)``,
  ``last_log_term(seq)``, ``commit_index(seq)``, ``last_applied(seq)``,
  ``snapshot_info(seq)``, ``stats(seq)``, ``audit_log()``.
- ``raft_log_audit_event(kind, seq, **detail)`` -- ``audit.ndjson/1``
  shaped record.

All mutations require a caller-supplied strictly increasing ``seq``
(logical clock; no wall-clock is read anywhere). Failed mutations
consume their seq (ledger position stays total).

Honest scope:

- This is single-node *log bookkeeping*, not a distributed Raft
  implementation. There is no election timer, no RPC transport, no
  quorum counting, and no partition detection. A ``CommitRecord``
  means "this node recorded the host's commitment decision", never
  "the fleet agreed" -- the host's transport and the voters' honesty
  decide that.
- ``commit`` enforces the leader-side safety rule (section 5.4.2):
  only current-term entries may advance the commit index. A host
  emulating a *follower* records the leader's commit position with
  ``follower_commit`` instead, which pins ``leader_commit`` without
  the term rule.
- ``truncate_after`` models leader force (AppendEntries consistency
  repair). Dropping uncommitted conflicting entries is the protocol;
  the module only refuses truncation that would touch committed
  entries.
- Log entries never see raw payloads: ``payload_digest`` must be a
  ``sha256:`` pin of the canonical JSON encoding of the value,
  computed by the host. Digests are opaque to this module.
- Snapshots book the *decision* to compact; they do not prove the
  state machine state behind ``state_digest``.
- Canonical JSON note: values serialize with sorted keys and compact
  separators. Like every JSON canonicalizer (RFC 8785 included),
  integers outside +/-2**53 serialize as IEEE 754 doubles and lose
  precision -- hosts needing exact large-integer pins must encode
  them as strings.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover
    _cj = None  # type: ignore

#: Module version pin.
RAFT_LOG_VERSION = "raft-log.v1"

#: Schema pin carried by records and audit events.
RAFT_LOG_SCHEMA = "northstar.raft-log.v1"

#: Audit schema.
AUDIT_SCHEMA = "audit.ndjson/1"


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class RaftLogError(Exception):
    """Base class for all raft-log errors."""


class BadNodeError(RaftLogError):
    """Node id is not a non-empty string."""


class BadTermError(RaftLogError):
    """Term is not a non-negative int, or entry term < current term."""


class TermRegressionError(RaftLogError):
    """Attempted to move the current term backward."""


class BadIndexError(RaftLogError):
    """Index is not a positive int."""


class IndexOutOfRangeError(RaftLogError):
    """Index refers to an entry this log does not hold."""


class NoCommitAdvanceError(RaftLogError):
    """Commit index did not advance (it never moves backward)."""


class TermMismatchError(RaftLogError):
    """Entry at the commit target is not from the current term (5.4.2)."""


class BadDigestError(RaftLogError):
    """Digest is not a ``sha256:`` + 64 hex pin."""


class AlreadyAppliedError(RaftLogError):
    """Entry was already applied to the state machine."""


class ApplyOrderError(RaftLogError):
    """Apply target is not the next unapplied committed index."""


class UncommittedApplyError(RaftLogError):
    """Apply target is beyond the commit index."""


class UncommittedSnapshotError(RaftLogError):
    """Snapshot target is not committed yet."""


class CommittedTruncateError(RaftLogError):
    """Truncation would drop committed entries."""


class SeqOrderError(RaftLogError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Canonicalization / pinning
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        _canonical([RAFT_LOG_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise SeqOrderError(f"{name} must be a positive int")
    return value


def _check_node_id(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadNodeError("node_id must be a non-empty string")
    return value.strip()


def _check_term(value: Any, name: str = "term") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadTermError(f"{name} must be an int")
    if value < 0:
        raise BadTermError(f"{name} must be non-negative")
    return value


def _check_index(value: Any, name: str = "index") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadIndexError(f"{name} must be an int")
    if value < 1:
        raise BadIndexError(f"{name} must be >= 1")
    return value


def _check_digest(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise BadDigestError("digest must be a sha256: pin")
    body = value[len("sha256:") :]
    if len(body) != 64 or any(c not in "0123456789abcdef" for c in body):
        raise BadDigestError("digest must be sha256: + 64 lowercase hex")
    return value


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LogEntry:
    """One log entry (frozen). Indexes are 1-based; index 0 is reserved."""

    term: int
    index: int
    payload_digest: str


@dataclass(frozen=True)
class AppendRecord:
    """One appended entry (frozen)."""

    term: int
    index: int
    payload_digest: str
    seq: int
    digest: str
    schema: str = RAFT_LOG_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "append", self.term, self.index, self.payload_digest, self.seq
        )


@dataclass(frozen=True)
class TermRecord:
    """One term advancement (frozen)."""

    term: int
    seq: int
    digest: str
    schema: str = RAFT_LOG_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("set-term", self.term, self.seq)


@dataclass(frozen=True)
class TruncateRecord:
    """One leader-force truncation (frozen)."""

    from_index: int  # entries with index > from_index were dropped
    dropped: int
    seq: int
    digest: str
    schema: str = RAFT_LOG_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "truncate", self.from_index, self.dropped, self.seq
        )


@dataclass(frozen=True)
class CommitRecord:
    """One commit-index advancement (frozen)."""

    index: int
    term: int  # term of the entry at index (pinned current at commit time)
    seq: int
    digest: str
    schema: str = RAFT_LOG_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "commit", self.index, self.term, self.seq
        )


@dataclass(frozen=True)
class FollowerCommitRecord:
    """One leader_commit pin on a follower (frozen)."""

    leader_commit: int
    seq: int
    digest: str
    schema: str = RAFT_LOG_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("follower-commit", self.leader_commit,
                                   self.seq)


@dataclass(frozen=True)
class ApplyRecord:
    """One state-machine application (frozen)."""

    index: int
    term: int
    payload_digest: str
    seq: int
    digest: str
    schema: str = RAFT_LOG_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "apply", self.index, self.term, self.payload_digest, self.seq
        )


@dataclass(frozen=True)
class SnapshotRecord:
    """One log-compaction snapshot (frozen)."""

    last_included_index: int
    last_included_term: int
    state_digest: str
    compacted: int  # entries dropped
    seq: int
    digest: str
    schema: str = RAFT_LOG_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "snapshot", self.last_included_index,
            self.last_included_term, self.state_digest,
            self.compacted, self.seq,
        )


@dataclass(frozen=True)
class SnapshotInfo:
    """Snapshot metadata view (frozen, pure read)."""

    last_included_index: int
    last_included_term: int


@dataclass(frozen=True)
class LogStats:
    """Log statistics view (frozen, pure read)."""

    node_id: str
    current_term: int
    last_log_index: int
    last_log_term: int
    commit_index: int
    last_applied: int
    snapshot_index: int
    pending_entries: int  # entries with index > commit_index


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_APPENDED = "raft.appended"
KIND_TERM_SET = "raft.term-set"
KIND_TRUNCATED = "raft.truncated"
KIND_COMMITTED = "raft.committed"
KIND_FOLLOWER_COMMIT = "raft.follower-commit"
KIND_APPLIED = "raft.applied"
KIND_SNAPSHOT = "raft.snapshot-taken"
KIND_REJECTED = "raft.rejected"
_KINDS = frozenset(
    {
        KIND_APPENDED,
        KIND_TERM_SET,
        KIND_TRUNCATED,
        KIND_COMMITTED,
        KIND_FOLLOWER_COMMIT,
        KIND_APPLIED,
        KIND_SNAPSHOT,
        KIND_REJECTED,
    }
)


def raft_log_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the raft log."""
    if kind not in _KINDS:
        raise RaftLogError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    # Digests are pins; raw payloads must never cross the audit boundary.
    banned = {"payload", "value", "data", "command", "entry"}
    if any(k in detail for k in banned):
        raise RaftLogError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "raft_log",
        "module_version": RAFT_LOG_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# The log
# ---------------------------------------------------------------------------


class RaftLog:
    """Deterministic Raft log bookkeeping for one node.

    Books append / term / truncate / commit / apply / snapshot as frozen
    records. Simulated: no transport, no timers, no elections -- the host
    drives everything.

    All state mutations take a caller-supplied strictly increasing
    ``seq`` (monotonic logical time); no wall-clock is read anywhere.
    Failed mutations consume their seq (fail-closed ledger position).
    Read views validate the seq shape but do not consume it and write
    no audit rows.
    """

    def __init__(self, node_id: str) -> None:
        self._node_id = _check_node_id(node_id)
        self._lock = threading.RLock()
        self._seq = 0
        self._current_term = 0
        self._entries: Dict[int, LogEntry] = {}
        self._commit_index = 0
        self._last_applied = 0
        self._snapshot_index = 0
        self._snapshot_term = 0
        self._audit: List[Mapping[str, Any]] = []

    # -- internals ----------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._seq}, got={seq})"
            )
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(raft_log_audit_event(kind, seq, **detail))

    def _reject_locked(self, seq: int, reason: str) -> None:
        self._emit(KIND_REJECTED, seq, reason=reason)

    def _last_log_index(self) -> int:
        return max(self._entries) if self._entries else self._snapshot_index

    def _last_log_term(self) -> int:
        idx = self._last_log_index()
        if idx == 0:
            return 0
        if idx == self._snapshot_index and not self._entries:
            return self._snapshot_term
        return self._entries[idx].term

    # -- mutations -----------------------------------------------------------

    def set_term(self, term: int, seq: int) -> TermRecord:
        """Advance the current term. Regression is refused fail-closed."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                term = _check_term(term)
                if term < self._current_term:
                    raise TermRegressionError(
                        f"term {term} < current {self._current_term}"
                    )
            except RaftLogError as exc:
                self._seq = seq
                self._reject_locked(seq, str(exc))
                raise
            self._current_term = term
            self._seq = seq
            record = TermRecord(
                term=term, seq=seq, digest=_pin("set-term", term, seq)
            )
            self._emit(KIND_TERM_SET, seq, term=term)
            return record

    def append(self, term: int, payload_digest: str, seq: int) -> AppendRecord:
        """Append one entry at ``last_log_index + 1``.

        The entry term must be ``>= current_term`` -- a node never
        appends older-term entries.
        """
        with self._lock:
            seq = self._next_seq(seq)
            try:
                term = _check_term(term)
                digest = _check_digest(payload_digest)
                if term < self._current_term:
                    raise BadTermError(
                        f"entry term {term} < current term "
                        f"{self._current_term}"
                    )
            except RaftLogError as exc:
                self._seq = seq
                self._reject_locked(seq, str(exc))
                raise
            index = self._last_log_index() + 1
            self._entries[index] = LogEntry(
                term=term, index=index, payload_digest=digest
            )
            self._seq = seq
            record = AppendRecord(
                term=term,
                index=index,
                payload_digest=digest,
                seq=seq,
                digest=_pin("append", term, index, digest, seq),
            )
            self._emit(
                KIND_APPENDED, seq, term=term, index=index,
                payload_digest=digest,
            )
            return record

    def truncate_after(self, index: int, seq: int) -> TruncateRecord:
        """Leader force: drop all entries with ``index`` > ``index``.

        Truncation at or below the commit index is refused -- committed
        entries are never dropped. ``index`` below the snapshot index
        is refused as well.
        """
        with self._lock:
            seq = self._next_seq(seq)
            try:
                index = _check_index(index)
                if index <= self._commit_index:
                    raise CommittedTruncateError(
                        f"truncate at {index} would touch commit index "
                        f"{self._commit_index}"
                    )
                if index < self._snapshot_index:
                    raise CommittedTruncateError(
                        f"truncate at {index} below snapshot index "
                        f"{self._snapshot_index}"
                    )
            except RaftLogError as exc:
                self._seq = seq
                self._reject_locked(seq, str(exc))
                raise
            dropped = sum(1 for i in self._entries if i > index)
            for i in [i for i in self._entries if i > index]:
                del self._entries[i]
            self._seq = seq
            record = TruncateRecord(
                from_index=index,
                dropped=dropped,
                seq=seq,
                digest=_pin("truncate", index, dropped, seq),
            )
            self._emit(
                KIND_TRUNCATED, seq, from_index=index, dropped=dropped
            )
            return record

    def commit(self, index: int, seq: int) -> CommitRecord:
        """Advance the commit index to ``index`` (leader-side rule).

        Rules: ``index`` must be an existing entry; it must be strictly
        greater than the current commit index (commit index never moves
        backward); and the entry at ``index`` must carry the *current*
        term -- the Raft section 5.4.2 safety rule: a leader may only
        commit entries from its own term.
        """
        with self._lock:
            seq = self._next_seq(seq)
            try:
                index = _check_index(index)
                if index <= self._snapshot_index or index not in self._entries:
                    raise IndexOutOfRangeError(
                        f"index {index} not held by this log"
                    )
                if index <= self._commit_index:
                    raise NoCommitAdvanceError(
                        f"index {index} <= commit index {self._commit_index}"
                    )
                entry = self._entries[index]
                if entry.term != self._current_term:
                    raise TermMismatchError(
                        f"entry at {index} has term {entry.term}, current "
                        f"term is {self._current_term} (raft 5.4.2)"
                    )
            except RaftLogError as exc:
                self._seq = seq
                self._reject_locked(seq, str(exc))
                raise
            self._commit_index = index
            self._seq = seq
            record = CommitRecord(
                index=index,
                term=self._current_term,
                seq=seq,
                digest=_pin("commit", index, self._current_term, seq),
            )
            self._emit(
                KIND_COMMITTED, seq, index=index, term=self._current_term
            )
            return record

    def follower_commit(self, leader_commit: int, seq: int) -> FollowerCommitRecord:
        """Pin a follower's commit index from the leader's ``leader_commit``.

        Follower-side rule: advance to ``min(leader_commit,
        last_log_index)`` when that advances the commit index. No term
        rule applies -- the leader already ran 5.4.2.
        """
        with self._lock:
            seq = self._next_seq(seq)
            try:
                leader_commit = _check_index(leader_commit)
            except RaftLogError as exc:
                self._seq = seq
                self._reject_locked(seq, str(exc))
                raise
            target = min(leader_commit, self._last_log_index())
            if target > self._commit_index:
                self._commit_index = target
            self._seq = seq
            record = FollowerCommitRecord(
                leader_commit=self._commit_index,
                seq=seq,
                digest=_pin("follower-commit", self._commit_index, seq),
            )
            self._emit(
                KIND_FOLLOWER_COMMIT, seq,
                leader_commit=self._commit_index,
            )
            return record

    def apply(self, index: int, seq: int) -> ApplyRecord:
        """Apply one committed entry to the state machine.

        Exact index order: ``index`` must equal ``last_applied + 1``
        and must be ``<= commit_index``.
        """
        with self._lock:
            seq = self._next_seq(seq)
            try:
                index = _check_index(index)
                if index <= self._last_applied:
                    raise AlreadyAppliedError(
                        f"index {index} already applied "
                        f"(last_applied={self._last_applied})"
                    )
                if index != self._last_applied + 1:
                    raise ApplyOrderError(
                        f"expected index {self._last_applied + 1}, "
                        f"got {index}"
                    )
                if index > self._commit_index:
                    raise UncommittedApplyError(
                        f"index {index} beyond commit index "
                        f"{self._commit_index}"
                    )
                entry = self._entries.get(index)
                if entry is None:
                    # Entry compacted by a snapshot: replay is impossible.
                    raise IndexOutOfRangeError(
                        f"index {index} not held by this log (compacted?)"
                    )
            except RaftLogError as exc:
                self._seq = seq
                self._reject_locked(seq, str(exc))
                raise
            self._last_applied = index
            self._seq = seq
            record = ApplyRecord(
                index=index,
                term=entry.term,
                payload_digest=entry.payload_digest,
                seq=seq,
                digest=_pin(
                    "apply", index, entry.term, entry.payload_digest, seq
                ),
            )
            self._emit(
                KIND_APPLIED, seq, index=index, term=entry.term,
                payload_digest=entry.payload_digest,
            )
            return record

    def snapshot(self, index: int, state_digest: str, seq: int) -> SnapshotRecord:
        """Compact the log: drop all entries with ``index`` <= ``index``.

        ``index`` must be committed (``<= commit_index``). The
        ``last_included_index``/``last_included_term`` pair is pinned
        for InstallSnapshot-style metadata.
        """
        with self._lock:
            seq = self._next_seq(seq)
            try:
                index = _check_index(index)
                digest = _check_digest(state_digest)
                if index > self._commit_index:
                    raise UncommittedSnapshotError(
                        f"index {index} beyond commit index "
                        f"{self._commit_index}"
                    )
                if index <= self._snapshot_index:
                    raise UncommittedSnapshotError(
                        f"index {index} <= snapshot index "
                        f"{self._snapshot_index}"
                    )
            except RaftLogError as exc:
                self._seq = seq
                self._reject_locked(seq, str(exc))
                raise
            term = self._entries[index].term
            compacted = sum(1 for i in self._entries if i <= index)
            for i in [i for i in self._entries if i <= index]:
                del self._entries[i]
            self._snapshot_index = index
            self._snapshot_term = term
            if self._last_applied < index:
                self._last_applied = index
            self._seq = seq
            record = SnapshotRecord(
                last_included_index=index,
                last_included_term=term,
                state_digest=digest,
                compacted=compacted,
                seq=seq,
                digest=_pin(
                    "snapshot", index, term, digest, compacted, seq
                ),
            )
            self._emit(
                KIND_SNAPSHOT, seq, last_included_index=index,
                last_included_term=term, state_digest=digest,
                compacted=compacted,
            )
            return record

    # -- read views (seq validated, never consumed, no audit rows) ------------

    def entry(self, index: int, seq: int) -> Optional[LogEntry]:
        """Return the entry at ``index``, or ``None`` if compacted/missing."""
        with self._lock:
            _check_seq(seq)
            _check_index(index)
            return self._entries.get(index)

    def entries(self, seq: int) -> Tuple[LogEntry, ...]:
        """Return all held entries in index order (read view)."""
        with self._lock:
            _check_seq(seq)
            return tuple(
                self._entries[i] for i in sorted(self._entries)
            )

    def last_log_index(self, seq: int) -> int:
        """Return the highest log index (read view)."""
        with self._lock:
            _check_seq(seq)
            return self._last_log_index()

    def last_log_term(self, seq: int) -> int:
        """Return the term of the highest log index (read view)."""
        with self._lock:
            _check_seq(seq)
            return self._last_log_term()

    def current_term(self, seq: int) -> int:
        """Return the current term (read view)."""
        with self._lock:
            _check_seq(seq)
            return self._current_term

    def commit_index(self, seq: int) -> int:
        """Return the commit index (read view)."""
        with self._lock:
            _check_seq(seq)
            return self._commit_index

    def last_applied(self, seq: int) -> int:
        """Return the last applied index (read view)."""
        with self._lock:
            _check_seq(seq)
            return self._last_applied

    def snapshot_info(self, seq: int) -> SnapshotInfo:
        """Return the snapshot metadata (read view)."""
        with self._lock:
            _check_seq(seq)
            return SnapshotInfo(
                last_included_index=self._snapshot_index,
                last_included_term=self._snapshot_term,
            )

    def stats(self, seq: int) -> LogStats:
        """Return log statistics (read view)."""
        with self._lock:
            _check_seq(seq)
            pending = sum(
                1 for i in self._entries if i > self._commit_index
            )
            return LogStats(
                node_id=self._node_id,
                current_term=self._current_term,
                last_log_index=self._last_log_index(),
                last_log_term=self._last_log_term(),
                commit_index=self._commit_index,
                last_applied=self._last_applied,
                snapshot_index=self._snapshot_index,
                pending_entries=pending,
            )

    def audit_log(self) -> Tuple[Mapping[str, Any], ...]:
        """Return the audit rows booked so far (oldest first)."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check: append, term, commit, apply, snapshot, audit."""
    log = RaftLog("n1")
    log.set_term(1, 1)
    a1 = log.append(1, "sha256:" + "aa" * 32, 2)
    assert a1.verify()
    a2 = log.append(1, "sha256:" + "bb" * 32, 3)
    assert a2.index == 2
    c = log.commit(2, 4)
    assert c.verify()
    p1 = log.apply(1, 5)
    assert p1.verify()
    p2 = log.apply(2, 6)
    assert p2.verify()
    s = log.snapshot(2, "sha256:" + "cc" * 32, 7)
    assert s.verify()
    st = log.stats(8)
    assert st.last_log_index == 2
    assert st.commit_index == 2
    assert st.last_applied == 2
    assert st.snapshot_index == 2
    kinds = [e["kind"] for e in log.audit_log()]
    assert kinds == [
        "raft.term-set", "raft.appended", "raft.appended",
        "raft.committed", "raft.applied", "raft.applied",
        "raft.snapshot-taken",
    ], kinds
    print("raft-log OK: append, term, commit, apply, snapshot, audit")


if __name__ == "__main__":
    main()
