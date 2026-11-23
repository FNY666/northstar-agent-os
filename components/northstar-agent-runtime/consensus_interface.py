"""Consensus protocol interface: propose/accept/commit bookkeeping.

Research motivation: Raft (Ongaro & Ousterhout 2014) and Paxos (Lamport
1998) are how distributed agent fleets agree on one value (a fleet kill
decision, a global budget release, the audit-head anchor) despite
failures. This module pins the mechanical bookkeeping of the
propose/accept/commit pipeline that does *not* require a network:

- ``propose(value, ballot, seq)`` -- a proposer pins a value (by digest)
  under a caller-supplied ballot number and records its own acceptance.
- ``receive_acceptance(acceptance)`` -- the host feeds acceptances that
  arrived over the fleet's transport; each is validated (known proposal,
  matching ballot, known acceptor, no duplicates).
- ``commit(proposal_id, seq)`` -- once a quorum of *distinct known*
  acceptors has accepted the same proposal, mints a frozen ``CommitRecord``;
  otherwise returns ``None`` (nothing committed yet).
- ``propose_commit(...)`` -- convenience full local pipeline: propose,
  record own acceptance, fold in host-supplied peer acceptances, attempt
  commit. Returns the ``CommitRecord`` or ``None``.

Paxos safety invariants enforced locally:

- Ballot monotonicity (the prepare/promise phase): a node that has
  prepared (promised) ballot ``N`` refuses to accept any proposal with
  ballot ``< N``. ``accept`` returns ``None`` on refusal; it never raises
  on policy.
- Value binding: the proposal pins ``value_digest`` at propose time.
  Acceptances reference the proposal id only, so a vote can never smuggle
  a different value in.
- Quorum: only acceptances from *distinct known* acceptors count; the
  quorum is ``floor(n/2) + 1`` of the known acceptor set unless the host
  sets an explicit one. One acceptor's vote counts once per proposal.

Honest scope:

- This is a single node's *interface bookkeeping*, not a distributed
  protocol. There is no leader election here (see ``leader_election``),
  no log replication, no network round-trips, no partition detection.
  A ``CommitRecord`` means "this node recorded a quorum of acceptances",
  never "the fleet agreed" -- the host's transport and the acceptors'
  honesty decide that.
- The node never sees raw values: ``propose`` pins
  ``sha256:`` over canonical JSON and keeps only the digest. It cannot
  become a second exfiltration channel.
- Canonical JSON note: values are serialized with ``json.dumps`` sorted
  keys and compact separators. Like every JSON canonicalizer (RFC 8785
  included), integers outside +/-2**53 are serialized as IEEE 754 doubles
  and lose precision there -- values carrying such integers digest
  identically. Hosts needing exact large-integer pins must encode them as
  strings or fixed-width hex (the ``secure_aggregation`` module's
  ``_hexint`` shows the pattern).
- ``commit`` returning ``None`` is a policy outcome ("quorum not yet
  reached"), never an error. Malformed inputs raise ``TypeError`` /
  ``ValueError`` / ``ConsensusError`` fail-closed.
- All seqs are caller-supplied ints (logical clock); no wall-clock is read
  anywhere in this module.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

#: Module version pin.
CONSENSUS_INTERFACE_VERSION = "consensus-interface.v1"

#: Schema pin carried by records and audit events.
CONSENSUS_INTERFACE_SCHEMA = "northstar.consensus-interface.v1"

#: Audit event kinds.
EVENT_PROPOSED = "consensus-proposed"
EVENT_ACCEPTED = "consensus-accepted"
EVENT_COMMITTED = "consensus-committed"
EVENT_COMMIT_REFUSED = "consensus-commit-refused"

_EVENT_KINDS = frozenset(
    {EVENT_PROPOSED, EVENT_ACCEPTED, EVENT_COMMITTED, EVENT_COMMIT_REFUSED}
)

#: Digest prefix for pinned values.
_DIGEST_PREFIX = "sha256:"


class ConsensusError(Exception):
    """Base error for consensus bookkeeping (fail-closed)."""


class BallotConflictError(ConsensusError):
    """Raised when a ballot number is reused by the same proposer."""


def quorum_size(n_acceptors: int) -> int:
    """Return the majority quorum for ``n_acceptors`` acceptors.

    ``floor(n/2) + 1``. Fail-closed on malformed input.
    """
    if isinstance(n_acceptors, bool) or not isinstance(n_acceptors, int):
        raise TypeError(
            f"n_acceptors must be an int, got {type(n_acceptors).__name__}"
        )
    if n_acceptors < 1:
        raise ValueError("n_acceptors must be >= 1")
    return n_acceptors // 2 + 1


def _check_node_id(value: object, name: str = "node_id") -> str:
    """Validate a node id: non-empty string, whitespace-stripped."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    node_id = value.strip()
    if not node_id:
        raise ValueError(f"{name} must be non-empty")
    return node_id


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied logical seq: non-negative int, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _check_ballot(value: object, name: str = "ballot") -> int:
    """Validate a ballot number: positive int, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 1:
        raise ValueError(f"{name} must be >= 1")
    return value


def _check_digest(value: object, name: str = "digest") -> str:
    """Validate a ``sha256:`` + 64-hex digest pin."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    if not value.startswith(_DIGEST_PREFIX) or len(value) != len(
        _DIGEST_PREFIX
    ) + 64:
        raise ValueError(f"{name} must look like 'sha256:' + 64 hex chars")
    hexpart = value[len(_DIGEST_PREFIX) :]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise ValueError(f"{name} hex part must be lowercase hex")
    return value


def _canonical(value: Any) -> bytes:
    """Serialize a JSON-canonicalizable value deterministically.

    Sorted keys, compact separators, ASCII. Fail-closed: raises TypeError
    on anything that is not JSON-canonicalizable (None/bool/int/float/
    str/list/tuple/str-keyed dict only; NaN/inf rejected).
    """
    if value is None or isinstance(value, (bool, int, str)):
        pass
    elif isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise TypeError("NaN/inf are not canonicalizable")
    elif isinstance(value, (list, tuple)):
        for item in value:
            _canonical(item)
    elif isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError("dict keys must be str for canonicalization")
            _canonical(value[key])
    else:
        raise TypeError(
            f"value of type {type(value).__name__} is not JSON-canonicalizable"
        )
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def pin_value(value: Any) -> str:
    """Pin a JSON-canonicalizable value: ``sha256:`` + hex digest."""
    return _DIGEST_PREFIX + hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True)
class Proposal:
    """A proposer's pinned intent: value digest under a ballot number."""

    proposal_id: str
    proposer_id: str
    ballot: int
    value_digest: str
    proposed_seq: int

    def __post_init__(self) -> None:
        _check_node_id(self.proposal_id, "proposal_id")
        _check_node_id(self.proposer_id, "proposer_id")
        _check_ballot(self.ballot)
        _check_digest(self.value_digest)
        _check_seq(self.proposed_seq)

    def as_dict(self) -> dict:
        return {
            "schema": CONSENSUS_INTERFACE_SCHEMA,
            "proposal_id": self.proposal_id,
            "proposer_id": self.proposer_id,
            "ballot": self.ballot,
            "value_digest": self.value_digest,
            "proposed_seq": self.proposed_seq,
        }


@dataclass(frozen=True)
class Acceptance:
    """One acceptor's vote for a proposal (ballot-bound)."""

    proposal_id: str
    acceptor_id: str
    ballot: int
    accepted_seq: int

    def __post_init__(self) -> None:
        _check_node_id(self.proposal_id, "proposal_id")
        _check_node_id(self.acceptor_id, "acceptor_id")
        _check_ballot(self.ballot)
        _check_seq(self.accepted_seq)

    def as_dict(self) -> dict:
        return {
            "schema": CONSENSUS_INTERFACE_SCHEMA,
            "proposal_id": self.proposal_id,
            "acceptor_id": self.acceptor_id,
            "ballot": self.ballot,
            "accepted_seq": self.accepted_seq,
        }


@dataclass(frozen=True)
class CommitRecord:
    """Quorum-accepted proposal: frozen commit evidence."""

    proposal_id: str
    value_digest: str
    ballot: int
    acceptors: tuple
    quorum: int
    committed_seq: int

    def __post_init__(self) -> None:
        _check_node_id(self.proposal_id, "proposal_id")
        _check_digest(self.value_digest)
        _check_ballot(self.ballot)
        if not isinstance(self.acceptors, tuple) or not self.acceptors:
            raise TypeError("acceptors must be a non-empty tuple")
        for acceptor in self.acceptors:
            _check_node_id(acceptor, "acceptor")
        if len(set(self.acceptors)) != len(self.acceptors):
            raise ValueError("acceptors must be distinct")
        _check_seq(self.committed_seq)

    def as_dict(self) -> dict:
        return {
            "schema": CONSENSUS_INTERFACE_SCHEMA,
            "proposal_id": self.proposal_id,
            "value_digest": self.value_digest,
            "ballot": self.ballot,
            "acceptors": list(self.acceptors),
            "quorum": self.quorum,
            "committed_seq": self.committed_seq,
        }


class ConsensusNode:
    """Single-node propose/accept/commit bookkeeping for one acceptor set.

    The host wires transport: peer acceptances arrive via
    ``receive_acceptance``; this node only records and validates.
    """

    def __init__(
        self,
        node_id: str,
        acceptors: Sequence[str],
        quorum: int | None = None,
    ) -> None:
        self._node_id = _check_node_id(node_id)
        if not isinstance(acceptors, (list, tuple)) or not acceptors:
            raise TypeError("acceptors must be a non-empty list/tuple")
        cleaned = tuple(_check_node_id(a, "acceptor") for a in acceptors)
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("acceptors must be distinct")
        if self._node_id not in cleaned:
            raise ValueError("node_id must be in the acceptor set")
        self._acceptors = cleaned
        if quorum is None:
            self._quorum = quorum_size(len(cleaned))
        else:
            if isinstance(quorum, bool) or not isinstance(quorum, int):
                raise TypeError(
                    f"quorum must be an int, got {type(quorum).__name__}"
                )
            if not 1 <= quorum <= len(cleaned):
                raise ValueError("quorum must be in [1, len(acceptors)]")
            self._quorum = quorum
        # proposal_id -> Proposal
        self._proposals: dict[str, Proposal] = {}
        # proposal_id -> {acceptor_id: Acceptance}
        self._acceptances: dict[str, dict[str, Acceptance]] = {}
        # proposal_id -> CommitRecord
        self._commits: dict[str, CommitRecord] = {}
        # Paxos promise: highest ballot this node has prepared for.
        self._promised_ballot = 0
        # Ballots this node has already used to propose.
        self._used_ballots: set[int] = set()
        # Monotonic proposal counter for deterministic ids.
        self._proposal_count = 0

    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def acceptors(self) -> tuple:
        return self._acceptors

    @property
    def quorum(self) -> int:
        return self._quorum

    def propose(self, value: Any, ballot: int, seq: int) -> Proposal:
        """Propose ``value`` under ``ballot``: pin, record, self-accept.

        Returns the frozen ``Proposal``. The node's own acceptance is
        recorded automatically (it is an acceptor). Raises
        ``BallotConflictError`` if this node already proposed under
        ``ballot`` (caller bug -- ballots must be fresh).
        """
        ballot = _check_ballot(ballot)
        seq = _check_seq(seq, "seq")
        if ballot in self._used_ballots:
            raise BallotConflictError(
                f"ballot {ballot} already used by {self._node_id}"
            )
        digest = pin_value(value)
        self._proposal_count += 1
        proposal_id = f"prop-{self._node_id}-{self._proposal_count}"
        proposal = Proposal(
            proposal_id=proposal_id,
            proposer_id=self._node_id,
            ballot=ballot,
            value_digest=digest,
            proposed_seq=seq,
        )
        self._proposals[proposal_id] = proposal
        self._acceptances[proposal_id] = {}
        self._used_ballots.add(ballot)
        # Prepare (promise) and self-accept.
        self._promised_ballot = max(self._promised_ballot, ballot)
        own = Acceptance(
            proposal_id=proposal_id,
            acceptor_id=self._node_id,
            ballot=ballot,
            accepted_seq=seq,
        )
        self._acceptances[proposal_id][self._node_id] = own
        return proposal

    def prepare(self, proposal: Proposal) -> bool:
        """Promise not to accept any ballot lower than ``proposal.ballot``.

        The Paxos prepare phase is about ballot numbers: an acceptor that
        has promised ballot ``N`` refuses proposals with ballot ``< N``.
        Returns True when the promise is recorded (the proposal is
        registered as seen); False when the node already promised a
        higher ballot -- the proposal is refused, never raised on
        (policy, fail closed).
        """
        if not isinstance(proposal, Proposal):
            raise TypeError(
                f"proposal must be a Proposal, got {type(proposal).__name__}"
            )
        if proposal.ballot < self._promised_ballot:
            return False
        self._promised_ballot = max(self._promised_ballot, proposal.ballot)
        if proposal.proposal_id not in self._proposals:
            self._proposals[proposal.proposal_id] = proposal
            self._acceptances[proposal.proposal_id] = {}
        return True

    def receive_acceptance(self, acceptance: Acceptance) -> None:
        """Record a peer acceptor's vote (arrived over host transport).

        Fail-closed validation: unknown proposal, ballot mismatch,
        unknown acceptor, or duplicate vote all raise ``ConsensusError``.
        """
        if not isinstance(acceptance, Acceptance):
            raise TypeError(
                f"acceptance must be an Acceptance, got {type(acceptance).__name__}"
            )
        proposal = self._proposals.get(acceptance.proposal_id)
        if proposal is None:
            raise ConsensusError(
                f"acceptance for unknown proposal {acceptance.proposal_id}"
            )
        if acceptance.ballot != proposal.ballot:
            raise ConsensusError(
                f"ballot mismatch: acceptance {acceptance.ballot} "
                f"vs proposal {proposal.ballot}"
            )
        if acceptance.acceptor_id not in self._acceptors:
            raise ConsensusError(
                f"unknown acceptor {acceptance.acceptor_id}"
            )
        votes = self._acceptances[acceptance.proposal_id]
        if acceptance.acceptor_id in votes:
            raise ConsensusError(
                f"duplicate vote from {acceptance.acceptor_id} "
                f"for {acceptance.proposal_id}"
            )
        votes[acceptance.acceptor_id] = acceptance

    def commit(self, proposal_id: str, seq: int) -> CommitRecord | None:
        """Commit a proposal once a quorum of acceptances is recorded.

        Returns the frozen ``CommitRecord`` on quorum, ``None`` when the
        quorum is not yet reached (policy outcome, never an error).
        Committing is idempotent: an already-committed proposal returns
        the same record. ``ValueError`` on unknown proposal id.
        """
        _check_node_id(proposal_id, "proposal_id")
        seq = _check_seq(seq, "seq")
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise ValueError(f"unknown proposal {proposal_id}")
        if proposal_id in self._commits:
            return self._commits[proposal_id]
        votes = self._acceptances[proposal_id]
        if len(votes) < self._quorum:
            return None
        acceptors = tuple(sorted(votes))
        record = CommitRecord(
            proposal_id=proposal_id,
            value_digest=proposal.value_digest,
            ballot=proposal.ballot,
            acceptors=acceptors,
            quorum=self.quorum,
            committed_seq=seq,
        )
        self._commits[proposal_id] = record
        return record

    def commit_status(self, proposal_id: str) -> CommitRecord | None:
        """Return the commit record for a proposal, or None if uncommitted."""
        _check_node_id(proposal_id, "proposal_id")
        return self._commits.get(proposal_id)

    def propose_commit(
        self,
        value: Any,
        ballot: int,
        peer_acceptances: Iterable[Acceptance],
        seq: int,
    ) -> CommitRecord | None:
        """Full local pipeline: propose + peer acceptances + commit.

        ``peer_acceptances`` are the host-supplied votes from other
        acceptors (the node's own vote is recorded by ``propose``).
        Returns the ``CommitRecord`` on quorum, ``None`` otherwise.
        """
        proposal = self.propose(value, ballot, seq)
        for acceptance in peer_acceptances:
            self.receive_acceptance(acceptance)
        return self.commit(proposal.proposal_id, seq)

    def acceptance_count(self, proposal_id: str) -> int:
        """Number of distinct acceptances recorded for a proposal."""
        _check_node_id(proposal_id, "proposal_id")
        votes = self._acceptances.get(proposal_id)
        if votes is None:
            raise ValueError(f"unknown proposal {proposal_id}")
        return len(votes)


def consensus_audit_event(
    kind: str, record: Proposal | Acceptance | CommitRecord, seq: int
) -> dict:
    """Shape an ``audit.ndjson/1`` record for a consensus event."""
    if kind not in _EVENT_KINDS:
        raise ValueError(f"unknown event kind {kind!r}")
    if not isinstance(record, (Proposal, Acceptance, CommitRecord)):
        raise TypeError(
            f"record must be a consensus record, got {type(record).__name__}"
        )
    _check_seq(seq, "seq")
    return {
        "schema": "northstar.audit.ndjson/1",
        "event": kind,
        "module": CONSENSUS_INTERFACE_VERSION,
        "record": record.as_dict(),
        "audit_seq": seq,
    }


def main() -> None:
    """Self-check: propose, gather quorum, commit; low-ballot refused."""
    node = ConsensusNode("n1", ("n1", "n2", "n3"))
    proposal = node.propose({"fleet-kill": True}, ballot=2, seq=0)
    node.receive_acceptance(
        Acceptance(
            proposal_id=proposal.proposal_id,
            acceptor_id="n2",
            ballot=2,
            accepted_seq=1,
        )
    )
    record = node.commit(proposal.proposal_id, seq=2)
    assert record is not None, "quorum of 2 should commit"
    assert record.acceptors == ("n1", "n2")
    # A ballot lower than the promised one is refused by the promise.
    late = Proposal(
        proposal_id="prop-n9-1",
        proposer_id="n9",
        ballot=1,
        value_digest=pin_value("x"),
        proposed_seq=0,
    )
    assert node.prepare(late) is False, "lower ballot must be refused"
    print("consensus-interface OK: propose, quorum commit, ballot refused")


if __name__ == "__main__":
    main()
