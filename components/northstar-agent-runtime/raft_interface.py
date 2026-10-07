"""Raft interface: single-node RPC bookkeeping for the Raft consensus protocol.

Research motivation (Ongaro & Ousterhout 2014): Raft elects a leader by
majority vote and replicates a log to followers, replacing Paxos with a
more understandable protocol. This module pins the *mechanical* half of
Raft that does not require a network: term bookkeeping, vote rules,
log-consistency checks, and the two RPC handlers a host calls when a
request arrives over its own transport.

Public API:

- ``State`` -- node role: ``FOLLOWER`` / ``CANDIDATE`` / ``LEADER``.
- ``LogEntry`` -- frozen: ``term``, ``index`` (1-based), ``payload_digest``
  (``sha256:`` pin -- the node never sees raw values).
- ``VoteRequest`` / ``VoteResponse`` -- frozen vote RPC records.
- ``AppendEntriesRequest`` / ``AppendEntriesResponse`` -- frozen replication
  RPC records (heartbeat is the empty-entries case).
- ``RaftNode`` -- stateful per-node bookkeeping:
  ``request_vote(...)`` / ``append_entries(...)`` apply the Raft rules and
  return frozen responses; ``start_election(seq)`` moves the node to
  CANDIDATE, bumps the term, and votes for itself; ``become_leader(seq)``
  records a self-declared quorum win; ``step_down(seq)`` returns to
  FOLLOWER.
- ``raft_audit_event(...)`` -- ``audit.ndjson/1``-shaped record.

Honest scope:

- This is single-node RPC *bookkeeping*, not a distributed Raft
  implementation. There is no election timer, no network transport, no
  commit-index advancement beyond ``leader_commit`` pinning, and no
  partition detection. A host drives the protocol: it detects timeouts,
  sends RPCs over its transport, counts votes, and calls these methods
  when responses arrive.
- A vote granted here is one host's vote, not a quorum. Becoming LEADER is
  recorded only when the *host* has counted a majority and calls
  ``become_leader`` -- this module cannot count votes it never saw.
- Terms are caller-supplied monotonic ints. The node *observes* terms from
  RPCs and steps down / updates when it sees a higher one, but never
  invents a term except through ``start_election``.
- Log consistency checks the entries the caller presents; it cannot see
  entries the leader withheld or a partitioned log.
- As in ``secure_aggregation``, integer digests pin through fixed-width
  hex so JCS ``>2**53`` float serialization cannot silently collide pins.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping, Sequence

#: Module version.
RAFT_INTERFACE_VERSION = "raft-interface.v1"

#: Schema pin carried by records and audit events.
RAFT_INTERFACE_SCHEMA = "northstar.raft-interface.v1"

# ---------------------------------------------------------------------------
# Audit event kinds.
# ---------------------------------------------------------------------------

EVENT_VOTE_GRANTED = "vote-granted"
EVENT_VOTE_DENIED = "vote-denied"
EVENT_ELECTION_STARTED = "election-started"
EVENT_BECAME_LEADER = "became-leader"
EVENT_STEPPED_DOWN = "stepped-down"
EVENT_ENTRIES_APPENDED = "entries-appended"
EVENT_ENTRIES_REJECTED = "entries-rejected"
EVENT_TERM_ADVANCED = "term-advanced"

_EVENT_TYPES = frozenset(
    {
        EVENT_VOTE_GRANTED,
        EVENT_VOTE_DENIED,
        EVENT_ELECTION_STARTED,
        EVENT_BECAME_LEADER,
        EVENT_STEPPED_DOWN,
        EVENT_ENTRIES_APPENDED,
        EVENT_ENTRIES_REJECTED,
        EVENT_TERM_ADVANCED,
    }
)

_HEX_DIGITS = frozenset("0123456789abcdef")


# ---------------------------------------------------------------------------
# Validation helpers.
# ---------------------------------------------------------------------------


def _check_node_id(value: object, name: str = "node_id") -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    node_id = value.strip()
    if not node_id:
        raise ValueError(f"{name} must be non-empty")
    return node_id


def _check_term(value: object, name: str = "term") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _check_seq(value: object, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _check_index(value: object, name: str = "index") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 1:
        raise ValueError(f"{name} must be >= 1 (1-based log index)")
    return value


def _check_digest(value: object, name: str = "digest") -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    if not value.startswith("sha256:"):
        raise ValueError(f"{name} must be a 'sha256:' digest pin")
    body = value[len("sha256:") :]
    if len(body) != 64 or any(c not in _HEX_DIGITS for c in body):
        raise ValueError(f"{name} must be 'sha256:' + 64 lowercase hex chars")
    return value


def _payload_digest(payload: Mapping[str, object]) -> str:
    """Pin a payload without seeing raw semantics: sorted key-value digest.

    Fixed-width encoding only; maps must be flat string-keyed.
    """
    if not isinstance(payload, Mapping):
        raise TypeError(f"payload must be a mapping, got {type(payload).__name__}")
    parts: list[str] = []
    for key in sorted(payload.keys()):
        if not isinstance(key, str):
            raise TypeError("payload keys must be strings")
        val = payload[key]
        if isinstance(val, bool):
            parts.append(f"{key}:bool:{val!r}")
        elif isinstance(val, int):
            # Fixed-width hex: immune to JCS >2**53 float loss.
            parts.append(f"{key}:int:{val & 0xFFFFFFFFFFFFFFFF:016x}")
        elif isinstance(val, float):
            if val != val or val in (float("inf"), float("-inf")):
                raise ValueError("payload floats must be finite")
            parts.append(f"{key}:float:{val!r}")
        elif isinstance(val, str):
            parts.append(f"{key}:str:{val}")
        else:
            raise TypeError(f"payload values must be bool/int/float/str, got {type(val).__name__}")
    body = "\x00".join(parts)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Records.
# ---------------------------------------------------------------------------


class State(str, Enum):
    """Raft node role."""

    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    LEADER = "leader"


@dataclass(frozen=True)
class LogEntry:
    """One replicated log entry: 1-based index, term, payload pin."""

    term: int
    index: int
    payload_digest: str
    schema: str = RAFT_INTERFACE_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "term", _check_term(self.term))
        object.__setattr__(self, "index", _check_index(self.index))
        object.__setattr__(self, "payload_digest", _check_digest(self.payload_digest, "payload_digest"))
        if self.schema != RAFT_INTERFACE_SCHEMA:
            raise ValueError(f"schema must be {RAFT_INTERFACE_SCHEMA!r}")

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "term": self.term,
            "index": self.index,
            "payload_digest": self.payload_digest,
        }


@dataclass(frozen=True)
class VoteRequest:
    """RequestVote RPC arguments."""

    candidate_id: str
    term: int
    last_log_index: int
    last_log_term: int
    seq: int
    schema: str = RAFT_INTERFACE_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_id", _check_node_id(self.candidate_id, "candidate_id"))
        object.__setattr__(self, "term", _check_term(self.term))
        object.__setattr__(self, "last_log_index", _check_index_or_zero(self.last_log_index))
        object.__setattr__(self, "last_log_term", _check_term(self.last_log_term))
        object.__setattr__(self, "seq", _check_seq(self.seq))
        if self.schema != RAFT_INTERFACE_SCHEMA:
            raise ValueError(f"schema must be {RAFT_INTERFACE_SCHEMA!r}")

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "candidate_id": self.candidate_id,
            "term": self.term,
            "last_log_index": self.last_log_index,
            "last_log_term": self.last_log_term,
            "seq": self.seq,
        }


def _check_index_or_zero(value: object, name: str = "last_log_index") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0 (0 = empty log)")
    return value


@dataclass(frozen=True)
class VoteResponse:
    """RequestVote RPC reply."""

    term: int
    vote_granted: bool
    voter_id: str
    seq: int
    schema: str = RAFT_INTERFACE_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "term", _check_term(self.term))
        if not isinstance(self.vote_granted, bool):
            raise TypeError("vote_granted must be a bool")
        object.__setattr__(self, "voter_id", _check_node_id(self.voter_id, "voter_id"))
        object.__setattr__(self, "seq", _check_seq(self.seq))
        if self.schema != RAFT_INTERFACE_SCHEMA:
            raise ValueError(f"schema must be {RAFT_INTERFACE_SCHEMA!r}")

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "term": self.term,
            "vote_granted": self.vote_granted,
            "voter_id": self.voter_id,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class AppendEntriesRequest:
    """AppendEntries RPC arguments. Empty ``entries`` = heartbeat."""

    leader_id: str
    term: int
    prev_log_index: int
    prev_log_term: int
    entries: tuple
    leader_commit: int
    seq: int
    schema: str = RAFT_INTERFACE_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "leader_id", _check_node_id(self.leader_id, "leader_id"))
        object.__setattr__(self, "term", _check_term(self.term))
        object.__setattr__(self, "prev_log_index", _check_index_or_zero(self.prev_log_index, "prev_log_index"))
        object.__setattr__(self, "prev_log_term", _check_term(self.prev_log_term, "prev_log_term"))
        entries = tuple(self.entries)
        for e in entries:
            if not isinstance(e, LogEntry):
                raise TypeError(f"entries must be LogEntry, got {type(e).__name__}")
        object.__setattr__(self, "entries", entries)
        object.__setattr__(self, "leader_commit", _check_index_or_zero(self.leader_commit, "leader_commit"))
        object.__setattr__(self, "seq", _check_seq(self.seq))
        if self.schema != RAFT_INTERFACE_SCHEMA:
            raise ValueError(f"schema must be {RAFT_INTERFACE_SCHEMA!r}")

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "leader_id": self.leader_id,
            "term": self.term,
            "prev_log_index": self.prev_log_index,
            "prev_log_term": self.prev_log_term,
            "entries": [e.as_dict() for e in self.entries],
            "leader_commit": self.leader_commit,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class AppendEntriesResponse:
    """AppendEntries RPC reply."""

    term: int
    success: bool
    node_id: str
    match_index: int
    seq: int
    schema: str = RAFT_INTERFACE_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "term", _check_term(self.term))
        if not isinstance(self.success, bool):
            raise TypeError("success must be a bool")
        object.__setattr__(self, "node_id", _check_node_id(self.node_id))
        object.__setattr__(self, "match_index", _check_index_or_zero(self.match_index, "match_index"))
        object.__setattr__(self, "seq", _check_seq(self.seq))
        if self.schema != RAFT_INTERFACE_SCHEMA:
            raise ValueError(f"schema must be {RAFT_INTERFACE_SCHEMA!r}")

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "term": self.term,
            "success": self.success,
            "node_id": self.node_id,
            "match_index": self.match_index,
            "seq": self.seq,
        }


# ---------------------------------------------------------------------------
# Node.
# ---------------------------------------------------------------------------


class RaftError(Exception):
    """Base for Raft bookkeeping errors."""


@dataclass(frozen=True)
class RaftAuditRecord:
    """Frozen audit record for state transitions."""

    kind: str
    node_id: str
    term: int
    state: str
    detail: str
    seq: int
    schema: str = RAFT_INTERFACE_SCHEMA

    def __post_init__(self) -> None:
        if self.kind not in _EVENT_TYPES:
            raise ValueError(f"kind must be one of {sorted(_EVENT_TYPES)}")
        object.__setattr__(self, "node_id", _check_node_id(self.node_id))
        object.__setattr__(self, "term", _check_term(self.term))
        if self.state not in {s.value for s in State}:
            raise ValueError(f"state must be one of {[s.value for s in State]}")
        if not isinstance(self.detail, str):
            raise TypeError("detail must be a string")
        object.__setattr__(self, "seq", _check_seq(self.seq))
        if self.schema != RAFT_INTERFACE_SCHEMA:
            raise ValueError(f"schema must be {RAFT_INTERFACE_SCHEMA!r}")

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "kind": self.kind,
            "node_id": self.node_id,
            "term": self.term,
            "state": self.state,
            "detail": self.detail,
            "seq": self.seq,
        }


class RaftNode:
    """Per-node Raft state machine bookkeeping (host-driven RPC handlers).

    The host owns the transport, the election timer, and vote counting. This
    object answers "what should this node do when this RPC arrives" and
    records the answer.
    """

    def __init__(self, node_id: str, cluster_size: int) -> None:
        self._node_id = _check_node_id(node_id)
        if isinstance(cluster_size, bool) or not isinstance(cluster_size, int):
            raise TypeError("cluster_size must be an int")
        if cluster_size < 1:
            raise ValueError("cluster_size must be >= 1")
        self._cluster_size = cluster_size
        self._term = 0
        self._voted_for: str | None = None
        self._state = State.FOLLOWER
        self._log: list[LogEntry] = []
        self._commit_index = 0
        self._audit: list[RaftAuditRecord] = []

    # -- views ------------------------------------------------------------

    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def state(self) -> State:
        return self._state

    @property
    def current_term(self) -> int:
        return self._term

    @property
    def voted_for(self) -> str | None:
        return self._voted_for

    @property
    def commit_index(self) -> int:
        return self._commit_index

    def last_log_index(self) -> int:
        return len(self._log)

    def last_log_term(self) -> int:
        return self._log[-1].term if self._log else 0

    def log(self) -> tuple:
        return tuple(self._log)

    def audit(self) -> tuple:
        return tuple(self._audit)

    @property
    def quorum(self) -> int:
        return self._cluster_size // 2 + 1

    # -- internal ----------------------------------------------------------

    def _record(self, kind: str, detail: str, seq: int) -> None:
        self._audit.append(
            RaftAuditRecord(
                kind=kind,
                node_id=self._node_id,
                term=self._term,
                state=self._state.value,
                detail=detail,
                seq=seq,
            )
        )

    def _advance_term(self, term: int, seq: int) -> bool:
        """Move to a higher term; step down and clear vote. Returns True if moved."""
        if term > self._term:
            self._term = term
            self._voted_for = None
            self._state = State.FOLLOWER
            self._record(EVENT_TERM_ADVANCED, f"advanced to term {term}", seq)
            return True
        return False

    def _log_up_to_date(self, last_log_index: int, last_log_term: int) -> bool:
        mine_term = self.last_log_term()
        mine_index = self.last_log_index()
        return (last_log_term > mine_term) or (
            last_log_term == mine_term and last_log_index >= mine_index
        )

    # -- RPC handlers -------------------------------------------------------

    def request_vote(self, req: VoteRequest) -> VoteResponse:
        """Apply Raft's vote rules to an incoming RequestVote."""
        if not isinstance(req, VoteRequest):
            raise TypeError(f"req must be VoteRequest, got {type(req).__name__}")
        granted = False
        if req.term < self._term:
            reason = f"stale term {req.term} < {self._term}"
        elif req.term > self._term:
            self._advance_term(req.term, req.seq)
            reason = ""
        else:
            reason = ""
        if req.term >= self._term:
            if self._voted_for not in (None, req.candidate_id):
                reason = f"already voted for {self._voted_for}"
            elif not self._log_up_to_date(req.last_log_index, req.last_log_term):
                reason = "candidate log not up-to-date"
            else:
                self._voted_for = req.candidate_id
                granted = True
                reason = f"voted for {req.candidate_id}"
        self._record(
            EVENT_VOTE_GRANTED if granted else EVENT_VOTE_DENIED,
            reason,
            req.seq,
        )
        return VoteResponse(
            term=self._term,
            vote_granted=granted,
            voter_id=self._node_id,
            seq=req.seq,
        )

    def append_entries(self, req: AppendEntriesRequest) -> AppendEntriesResponse:
        """Apply Raft's AppendEntries rules to an incoming RPC (incl. heartbeat)."""
        if not isinstance(req, AppendEntriesRequest):
            raise TypeError(f"req must be AppendEntriesRequest, got {type(req).__name__}")
        if req.term < self._term:
            self._record(EVENT_ENTRIES_REJECTED, f"stale term {req.term} < {self._term}", req.seq)
            return AppendEntriesResponse(
                term=self._term, success=False, node_id=self._node_id,
                match_index=self.last_log_index(), seq=req.seq,
            )
        if req.term > self._term:
            self._advance_term(req.term, req.seq)
        elif self._state != State.FOLLOWER:
            self._state = State.FOLLOWER
            self._record(EVENT_STEPPED_DOWN, f"recognized leader {req.leader_id}", req.seq)

        # Log consistency: prev entry must exist and match term.
        if req.prev_log_index > 0:
            if req.prev_log_index > self.last_log_index():
                self._record(EVENT_ENTRIES_REJECTED, "prev_log_index beyond local log", req.seq)
                return AppendEntriesResponse(
                    term=self._term, success=False, node_id=self._node_id,
                    match_index=self.last_log_index(), seq=req.seq,
                )
            if self._log[req.prev_log_index - 1].term != req.prev_log_term:
                # Delete the conflicting entry and everything after it.
                self._log = self._log[: req.prev_log_index - 1]
                self._record(EVENT_ENTRIES_REJECTED, "prev_log_term mismatch; truncated", req.seq)
                return AppendEntriesResponse(
                    term=self._term, success=False, node_id=self._node_id,
                    match_index=self.last_log_index(), seq=req.seq,
                )

        # Append new entries (skip ones already present with matching term).
        for entry in req.entries:
            if entry.index <= self.last_log_index():
                existing = self._log[entry.index - 1]
                if existing.term == entry.term and existing.payload_digest == entry.payload_digest:
                    continue
                # Conflict: truncate and append from here.
                self._log = self._log[: entry.index - 1]
            if entry.index != self.last_log_index() + 1:
                self._record(
                    EVENT_ENTRIES_REJECTED,
                    f"non-contiguous entry index {entry.index}",
                    req.seq,
                )
                return AppendEntriesResponse(
                    term=self._term, success=False, node_id=self._node_id,
                    match_index=self.last_log_index(), seq=req.seq,
                )
            self._log.append(entry)

        if req.leader_commit > self._commit_index:
            self._commit_index = min(req.leader_commit, self.last_log_index())

        detail = "heartbeat" if not req.entries else f"appended {len(req.entries)} entries"
        self._record(EVENT_ENTRIES_APPENDED, detail, req.seq)
        return AppendEntriesResponse(
            term=self._term, success=True, node_id=self._node_id,
            match_index=self.last_log_index(), seq=req.seq,
        )

    # -- host-driven transitions --------------------------------------------

    def start_election(self, seq: int) -> VoteRequest:
        """Become CANDIDATE for a new term and vote for self. Returns the VoteRequest to broadcast."""
        _check_seq(seq)
        self._term += 1
        self._voted_for = self._node_id
        self._state = State.CANDIDATE
        self._record(EVENT_ELECTION_STARTED, f"term {self._term}", seq)
        return VoteRequest(
            candidate_id=self._node_id,
            term=self._term,
            last_log_index=self.last_log_index(),
            last_log_term=self.last_log_term(),
            seq=seq,
        )

    def become_leader(self, seq: int, votes: int) -> None:
        """Record a self-declared quorum win. The host counted the votes."""
        _check_seq(seq)
        if self._state != State.CANDIDATE:
            raise RaftError(f"only a candidate can become leader (state={self._state.value})")
        if isinstance(votes, bool) or not isinstance(votes, int):
            raise TypeError("votes must be an int")
        if votes < self.quorum:
            raise RaftError(f"need {self.quorum} votes for quorum, got {votes}")
        self._state = State.LEADER
        self._record(EVENT_BECAME_LEADER, f"{votes} votes at term {self._term}", seq)

    def step_down(self, seq: int) -> None:
        """Return to FOLLOWER (host detected a higher term or a valid leader)."""
        _check_seq(seq)
        self._state = State.FOLLOWER
        self._record(EVENT_STEPPED_DOWN, "host-directed step down", seq)

    def append_local(self, payload: Mapping[str, object], seq: int) -> LogEntry:
        """Leader-side helper: mint the next log entry for this node's log."""
        _check_seq(seq)
        if self._state != State.LEADER:
            raise RaftError(f"only a leader appends locally (state={self._state.value})")
        entry = LogEntry(
            term=self._term,
            index=self.last_log_index() + 1,
            payload_digest=_payload_digest(payload),
        )
        self._log.append(entry)
        return entry


def raft_audit_event(record: RaftAuditRecord, audit_seq: int) -> dict:
    """Shape a ``RaftAuditRecord`` as an ``audit.ndjson/1`` event."""
    if not isinstance(record, RaftAuditRecord):
        raise TypeError(f"record must be RaftAuditRecord, got {type(record).__name__}")
    _check_seq(audit_seq, "audit_seq")
    event = record.as_dict()
    event["audit_seq"] = audit_seq
    return event


def main() -> None:
    node = RaftNode("n1", 3)
    assert node.state == State.FOLLOWER
    assert node.quorum == 2
    req = node.start_election(seq=1)
    assert node.state == State.CANDIDATE and req.term == 1
    node.become_leader(seq=2, votes=2)
    assert node.state == State.LEADER
    entry = node.append_local({"op": "set", "k": "x"}, seq=3)
    assert entry.index == 1 and entry.term == 1
    follower = RaftNode("n2", 3)
    vr = follower.request_vote(
        VoteRequest(candidate_id="n1", term=1, last_log_index=1, last_log_term=1, seq=4)
    )
    assert vr.vote_granted and vr.term == 1
    ae = AppendEntriesRequest(
        leader_id="n1", term=1, prev_log_index=0, prev_log_term=0,
        entries=(entry,), leader_commit=1, seq=5,
    )
    ar = follower.append_entries(ae)
    assert ar.success and ar.match_index == 1 and follower.commit_index == 1
    print("raft-interface OK: election, vote, append, commit")


if __name__ == "__main__":
    main()
