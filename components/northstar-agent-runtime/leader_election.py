"""Leader election: deterministic rule + lease bookkeeping for coordination.

Research motivation: a fleet of hosts must agree on *one* coordinator for
tasks that cannot run concurrently (fleet-wide kill trigger, global budget
release, audit-head anchoring). This module pins the two mechanical halves
of leader election that do not require a network:

- ``elect(candidates)`` -- pure deterministic rule: the highest ``priority``
  wins; ties break on the lexicographically smallest ``node_id`` so every
  host that sees the same candidate set picks the same leader.
- ``LeaderLease`` -- a frozen claim record: who leads, at which ``term``,
  and until which caller-supplied ``expiry_seq``. Leases expire
  fail-closed: an expired lease is *not* a leader.

Public API:

- ``Candidate`` -- frozen record: ``node_id`` (non-empty str),
  ``priority`` (non-negative int; bool rejected).
- ``elect(candidates)`` -- pure election; raises on empty set or duplicate
  node ids; ties broken deterministically by ``node_id``.
- ``LeaderLease`` -- frozen record: ``leader_id``, ``term`` (monotonic
  caller-supplied int), ``expiry_seq``; ``is_expired(current_seq)``.
- ``LeaderElector`` -- stateful coordinator over a fixed candidate set:
  ``elect_new_term(...)`` advances the term and mints a lease,
  ``renew_lease(...)`` extends the expiry of an unexpired lease whose
  leader is still registered, ``current_lease()`` view.
- ``leader_election_audit_event(...)`` -- ``audit.ndjson/1``-shaped record.

Honest scope:

- This is the deterministic election rule and lease bookkeeping, *not* a
  distributed consensus protocol. There is no Raft/Paxos here, no vote
  quorum, no partition detection. Two hosts that see *different* candidate
  sets (network partition) will elect different leaders -- that is
  split-brain, and detecting/healing it is the host's transport-layer job.
- A ``LeaderLease`` is a *claim* recorded by the electing host, not proof
  that the rest of the fleet agreed. ``is_leader()`` answers "does this
  lease name you and is it unexpired", never "the fleet accepts you".
- Terms are caller-supplied monotonic ints (epoch counters, ballot
  numbers); this module never invents them and never orders them across
  hosts. Reusing a term is a caller bug -- the elector rejects a term that
  is not strictly greater than the current one.
- Leases use caller-supplied int seqs, not wall-clock: expiry is a logical
  statement ("valid through seq N"), immune to NTP jumps.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

#: Version pin for this module's record shape.
LEADER_ELECTION_VERSION = "leader-election.v1"

#: Schema pin carried by records and audit events.
LEADER_ELECTION_SCHEMA = "northstar.leader-election.v1"

#: Audit event types.
EVENT_ELECTED = "leader-elected"
EVENT_RENEWED = "lease-renewed"
EVENT_EXPIRED = "lease-expired"
EVENT_RESIGNED = "leader-resigned"

_EVENT_TYPES = frozenset({EVENT_ELECTED, EVENT_RENEWED, EVENT_EXPIRED, EVENT_RESIGNED})


def _check_node_id(value: object, name: str = "node_id") -> str:
    """Validate a node id: non-empty string, whitespace-stripped."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    node_id = value.strip()
    if not node_id:
        raise ValueError(f"{name} must be non-empty")
    return node_id


def _check_priority(value: object, name: str = "priority") -> int:
    """Validate a priority: non-negative int, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


def _check_seq(value: object, name: str) -> int:
    """Validate a caller-supplied int seq: non-negative int, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


def _check_term(value: object, name: str = "term") -> int:
    """Validate a term: strictly positive int, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value <= 0:
        raise ValueError(f"{name} must be strictly positive, got {value}")
    return value


@dataclass(frozen=True)
class Candidate:
    """A node eligible for leadership."""

    node_id: str
    priority: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", _check_node_id(self.node_id))
        object.__setattr__(self, "priority", _check_priority(self.priority))

    def as_dict(self) -> dict:
        """JSON-safe shape of this candidate."""
        return {
            "schema": LEADER_ELECTION_SCHEMA,
            "version": LEADER_ELECTION_VERSION,
            "node_id": self.node_id,
            "priority": self.priority,
        }


def elect(candidates: Sequence[Candidate] | Iterable[Candidate]) -> Candidate:
    """Run the deterministic election rule over the candidate set.

    The highest ``priority`` wins; ties break on the lexicographically
    smallest ``node_id`` so every host that sees the same set picks the
    same leader. Pure function -- no state, no wall-clock.

    Raises:
        TypeError: if ``candidates`` is not an iterable of ``Candidate``.
        ValueError: if the set is empty or two candidates share a node id.
    """
    if isinstance(candidates, (str, bytes, Mapping)) or not isinstance(candidates, Iterable):
        raise TypeError(
            f"candidates must be an iterable of Candidate, got {type(candidates).__name__}"
        )
    pool = list(candidates)
    if not pool:
        raise ValueError("cannot elect from an empty candidate set")
    for c in pool:
        if not isinstance(c, Candidate):
            raise TypeError(f"candidates must be Candidate records, got {type(c).__name__}")
    seen: dict[str, Candidate] = {}
    for c in pool:
        if c.node_id in seen:
            raise ValueError(f"duplicate node_id in candidate set: {c.node_id!r}")
        seen[c.node_id] = c
    # Highest priority wins; lowest node_id breaks ties (deterministic).
    return min(pool, key=lambda c: (-c.priority, c.node_id))


@dataclass(frozen=True)
class LeaderLease:
    """A frozen claim that ``leader_id`` leads during ``term`` through
    ``expiry_seq`` (inclusive)."""

    leader_id: str
    term: int
    expiry_seq: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "leader_id", _check_node_id(self.leader_id))
        object.__setattr__(self, "term", _check_term(self.term))
        object.__setattr__(self, "expiry_seq", _check_seq(self.expiry_seq, "expiry_seq"))

    def is_expired(self, current_seq: int) -> bool:
        """True when ``current_seq`` has passed the lease expiry.

        Fail-closed on malformed seq (raises -- a caller that cannot count
        cannot trust a lease).
        """
        seq = _check_seq(current_seq, "current_seq")
        return seq > self.expiry_seq

    def as_dict(self) -> dict:
        """JSON-safe shape of this lease."""
        return {
            "schema": LEADER_ELECTION_SCHEMA,
            "version": LEADER_ELECTION_VERSION,
            "leader_id": self.leader_id,
            "term": self.term,
            "expiry_seq": self.expiry_seq,
        }


class LeaderElector:
    """Stateful election coordinator over a registered candidate set.

    Owns the monotonic term counter and the current lease. Terms are
    *advanced* here (never reused): ``elect_new_term`` requires a term
    strictly greater than the current one, so a crash that replays an old
    term cannot resurrect a stale leadership claim.
    """

    def __init__(self, candidates: Sequence[Candidate] | Iterable[Candidate]) -> None:
        pool = list(candidates)
        if not pool:
            raise ValueError("elector requires a non-empty candidate set")
        for c in pool:
            if not isinstance(c, Candidate):
                raise TypeError(f"candidates must be Candidate records, got {type(c).__name__}")
        ids = [c.node_id for c in pool]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate node_id in candidate set")
        self._candidates: tuple[Candidate, ...] = tuple(pool)
        self._term: int = 0
        self._lease: LeaderLease | None = None

    @property
    def term(self) -> int:
        """Current term (0 before the first election)."""
        return self._term

    def candidate_ids(self) -> tuple[str, ...]:
        """Registered node ids, in registration order."""
        return tuple(c.node_id for c in self._candidates)

    def add_candidate(self, candidate: Candidate) -> None:
        """Register a new candidate. Duplicates fail closed."""
        if not isinstance(candidate, Candidate):
            raise TypeError(f"candidate must be a Candidate, got {type(candidate).__name__}")
        if candidate.node_id in self.candidate_ids():
            raise ValueError(f"node_id already registered: {candidate.node_id!r}")
        self._candidates = self._candidates + (candidate,)

    def remove_candidate(self, node_id: str) -> None:
        """Deregister a candidate. If it holds the current lease, the lease
        is resigned (a removed node cannot lead)."""
        node = _check_node_id(node_id)
        remaining = tuple(c for c in self._candidates if c.node_id != node)
        if len(remaining) == len(self._candidates):
            raise KeyError(f"unknown node_id: {node!r}")
        self._candidates = remaining
        if self._lease is not None and self._lease.leader_id == node:
            self._lease = None

    def current_lease(self) -> LeaderLease | None:
        """The current lease record, or None if no live leader."""
        return self._lease

    def elect_new_term(
        self, term: int, lease_duration_seqs: int, current_seq: int
    ) -> LeaderLease:
        """Run an election at ``term`` and mint the winner's lease.

        ``term`` must be strictly greater than the current term (monotonic
        advance). The lease covers ``[current_seq, current_seq +
        lease_duration_seqs]``; duration 0 means the lease expires at the
        current seq (leader for exactly this seq).
        """
        new_term = _check_term(term)
        if new_term <= self._term:
            raise ValueError(
                f"term must advance past current term {self._term}, got {new_term}"
            )
        duration = _check_seq(lease_duration_seqs, "lease_duration_seqs")
        seq = _check_seq(current_seq, "current_seq")
        winner = elect(self._candidates)
        lease = LeaderLease(
            leader_id=winner.node_id,
            term=new_term,
            expiry_seq=seq + duration,
        )
        self._term = new_term
        self._lease = lease
        return lease

    def renew_lease(self, lease_duration_seqs: int, current_seq: int) -> LeaderLease:
        """Extend the current lease without a new election.

        Fail-closed: raises ``LookupError`` when there is no live lease,
        when the lease already expired (a new term is required), or when
        the lease's leader is no longer registered. The term is unchanged
        -- renewal is continuity, not a new election.
        """
        duration = _check_seq(lease_duration_seqs, "lease_duration_seqs")
        seq = _check_seq(current_seq, "current_seq")
        lease = self._lease
        if lease is None:
            raise LookupError("no live lease to renew")
        if lease.is_expired(seq):
            raise LookupError("lease expired; a new term election is required")
        if lease.leader_id not in self.candidate_ids():
            raise LookupError(f"lease holder {lease.leader_id!r} is not registered")
        renewed = LeaderLease(
            leader_id=lease.leader_id,
            term=lease.term,
            expiry_seq=seq + duration,
        )
        self._lease = renewed
        return renewed

    def is_leader(self, node_id: str, current_seq: int) -> bool:
        """True iff ``node_id`` holds a live, unexpired lease.

        Never raises on policy: unknown nodes and expired leases simply
        report False.
        """
        try:
            node = _check_node_id(node_id)
            seq = _check_seq(current_seq, "current_seq")
        except (TypeError, ValueError):
            return False
        lease = self._lease
        return (
            lease is not None
            and lease.leader_id == node
            and not lease.is_expired(seq)
        )


def leader_election_audit_event(
    event_type: str,
    lease: LeaderLease | None,
    seq: int,
    detail: str = "",
) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for an election event.

    ``lease`` may be None for resignation events (no live lease exists).
    """
    if event_type not in _EVENT_TYPES:
        raise ValueError(f"unknown event_type: {event_type!r}")
    if lease is not None and not isinstance(lease, LeaderLease):
        raise TypeError(f"lease must be a LeaderLease or None, got {type(lease).__name__}")
    audit_seq = _check_seq(seq, "seq")
    if not isinstance(detail, str):
        raise TypeError(f"detail must be a string, got {type(detail).__name__}")
    return {
        "audit_seq": audit_seq,
        "event": event_type,
        "module": LEADER_ELECTION_VERSION,
        "lease": lease.as_dict() if lease is not None else None,
        "detail": detail,
    }


def main() -> None:
    """Self-check: elect, lease, expire, renew, resign."""
    elector = LeaderElector(
        [Candidate(node_id="a", priority=1), Candidate(node_id="b", priority=5)]
    )
    lease = elector.elect_new_term(term=1, lease_duration_seqs=10, current_seq=0)
    assert lease.leader_id == "b", "highest priority should win"
    assert elector.is_leader("b", current_seq=5)
    assert not elector.is_leader("a", current_seq=5)
    assert lease.is_expired(11)
    assert not elector.is_leader("b", current_seq=11)
    renewed = elector.renew_lease(lease_duration_seqs=10, current_seq=5)
    assert renewed.term == 1 and renewed.expiry_seq == 15
    # Tie breaks on lowest node_id.
    tie = elect([Candidate(node_id="z", priority=3), Candidate(node_id="a", priority=3)])
    assert tie.node_id == "a"
    # Term reuse is refused.
    try:
        elector.elect_new_term(term=1, lease_duration_seqs=10, current_seq=16)
    except ValueError:
        pass
    else:
        raise AssertionError("term reuse must fail")
    print("leader-election OK: elect, lease, expire, renew, term advance")


if __name__ == "__main__":
    main()
