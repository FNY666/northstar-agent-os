"""Distributed consensus round coordinator: propose/vote/commit bookkeeping.

Research motivation: Paxos (Lamport 1998) and Raft (Ongaro & Ousterhout
2014) describe how a fleet of agents agrees on one value despite failures.
This module pins the *round coordinator* half of that problem: multiple
concurrent proposal rounds, host-reported votes, quorum tallies, terminal
commit/reject/withdraw transitions, and a read-only ``view()`` report --
all without a network.

Public API:

- ``DistributedConsensus(quorum=1, voters=(), protocol="simulated")`` --
  the coordinator. ``quorum`` is the number of accept-votes that commits
  a round (must be >= 1, and <= ``len(voters)`` when a voter set is
  declared). ``voters`` is an optional allowlist of voter ids; when
  non-empty, votes from unknown voters are refused. ``protocol`` is an
  informational pin (``simulated`` / ``paxos`` / ``raft``) recording which
  protocol family the host claims to drive underneath.
- ``propose(proposal_id, value_digest, seq)`` -> frozen ``ProposalRecord``.
  Values are pinned by ``sha256:`` digest only -- raw values never enter a
  record or the audit boundary.
- ``vote(proposal_id, voter, decision, seq)`` -> frozen ``VoteRecord``.
  ``decision`` is ``accept`` or ``reject``; verdicts are booked as data.
  One vote per ``(proposal, voter)`` pair -- a second vote raises
  ``DuplicateVoteError`` (votes are final, as in Paxos).
- ``commit(proposal_id, seq)`` -> frozen ``CommitRecord`` once
  accept-votes reach quorum. Before quorum: ``QuorumNotReachedError``.
  When reject-votes reach quorum first, the round is terminally
  ``RejectedProposalError`` and a ``RejectionRecord`` is booked.
- ``withdraw(proposal_id, seq, reason="")`` -> frozen
  ``WithdrawalRecord``; terminally cancels an *open* round.
- ``view(seq)`` -> frozen ``ViewReport``: pure read view (seq validated,
  not consumed, no audit row) listing committed / rejected / withdrawn /
  open rounds plus per-round tallies.
- ``distributed_consensus_audit_event(kind, seq, **detail)`` --
  ``audit.ndjson/1``-shaped record. Kinds: ``consensus.proposed``,
  ``consensus.vote-recorded``, ``consensus.committed``,
  ``consensus.round-rejected``, ``consensus.withdrawn``,
  ``consensus.rejected`` (failed mutation).

All mutations require a caller-supplied strictly increasing ``seq``
(logical clock; no wall-clock is read anywhere). Failed mutations consume
their seq (ledger position stays total).

Honest scope:

- This is single-node *interface bookkeeping*, not a distributed
  protocol. There are no election timers, no RPCs, no retransmission, no
  partition detection. A ``CommitRecord`` means "this node recorded a
  quorum of host-reported accept votes", never "the fleet agreed" -- the
  host's transport and the voters' honesty decide that.
- The ``protocol`` pin is a host declaration. Nothing here runs Paxos or
  Raft; see ``paxos_interface`` / ``raft_interface`` for their
  message-level bookkeeping. A host that actually runs Raft underneath
  would translate its replication successes into ``vote`` calls here.
- The node never sees raw values: ``value_digest`` must be a ``sha256:``
  pin of the canonical JSON encoding of the value, computed by the host.
  Digests are opaque to this module (no collision analysis performed).
- Canonical JSON note: values serialize with sorted keys and compact
  separators. Like every JSON canonicalizer (RFC 8785 included), integers
  outside +/-2**53 serialize as IEEE 754 doubles and lose precision --
  hosts needing exact large-integer pins must encode them as strings.
- ``commit`` raising ``QuorumNotReachedError`` is a policy outcome
  ("quorum not yet reached"), not a system failure.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover
    _cj = None  # type: ignore

#: Module version pin.
DISTRIBUTED_CONSENSUS_VERSION = "distributed-consensus.v1"

#: Schema pin carried by records and audit events.
DISTRIBUTED_CONSENSUS_SCHEMA = "northstar.distributed-consensus.v1"

#: Audit schema.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned protocol vocabulary (informational: which family the host claims).
PROTOCOLS = ("simulated", "paxos", "raft")

#: Pinned vote-decision vocabulary.
DECISIONS = ("accept", "reject")

#: Pinned round-state vocabulary.
STATES = ("open", "committed", "rejected", "withdrawn")


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class DistributedConsensusError(Exception):
    """Base class for all distributed-consensus errors."""


class BadQuorumError(DistributedConsensusError):
    """Quorum is not a positive int, or exceeds the declared voter set."""


class BadProtocolError(DistributedConsensusError):
    """Protocol pin is outside the pinned vocabulary."""


class BadVoterError(DistributedConsensusError):
    """Voter id is not a non-empty string."""


class UnknownVoterError(DistributedConsensusError):
    """Voter is not in the declared voter set."""


class BadProposalError(DistributedConsensusError):
    """Proposal id is not a non-empty string."""


class DuplicateProposalError(DistributedConsensusError):
    """Proposal id already exists (ids are never recycled)."""


class UnknownProposalError(DistributedConsensusError):
    """No such proposal id."""


class BadDigestError(DistributedConsensusError):
    """Value digest is not a ``sha256:`` + 64 hex pin."""


class BadDecisionError(DistributedConsensusError):
    """Vote decision is outside the pinned vocabulary."""


class DuplicateVoteError(DistributedConsensusError):
    """Voter already voted in this round (votes are final)."""


class QuorumNotReachedError(DistributedConsensusError):
    """Neither accept-quorum nor reject-quorum reached yet."""


class RejectedProposalError(DistributedConsensusError):
    """Round terminally rejected: reject-votes reached quorum."""


class TerminalProposalError(DistributedConsensusError):
    """Round is no longer open (committed / rejected / withdrawn)."""


class BadWithdrawError(DistributedConsensusError):
    """Withdraw reason is not a string."""


class SeqOrderError(DistributedConsensusError):
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
        _canonical([DISTRIBUTED_CONSENSUS_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise SeqOrderError(f"{name} must be a positive int")
    return value


def _check_id(value: Any, name: str, exc: type) -> str:
    if not isinstance(value, str) or not value.strip():
        raise exc(f"{name} must be a non-empty string")
    return value.strip()


def _check_digest(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise BadDigestError("value_digest must be a sha256: pin")
    body = value[len("sha256:") :]
    if len(body) != 64 or any(c not in "0123456789abcdef" for c in body):
        raise BadDigestError("value_digest must be sha256: + 64 lowercase hex")
    return value


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProposalRecord:
    """One proposed round (frozen)."""

    proposal_id: str
    value_digest: str
    protocol: str
    seq: int
    digest: str
    schema: str = DISTRIBUTED_CONSENSUS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "propose", self.proposal_id, self.value_digest, self.protocol,
            self.seq,
        )


@dataclass(frozen=True)
class VoteRecord:
    """One recorded vote (frozen). The verdict is data."""

    proposal_id: str
    voter: str
    decision: str  # "accept" | "reject"
    seq: int
    digest: str
    schema: str = DISTRIBUTED_CONSENSUS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "vote", self.proposal_id, self.voter, self.decision, self.seq
        )


@dataclass(frozen=True)
class CommitRecord:
    """One committed round (frozen, terminal)."""

    proposal_id: str
    value_digest: str
    accepts: int
    quorum: int
    seq: int
    digest: str
    schema: str = DISTRIBUTED_CONSENSUS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "commit", self.proposal_id, self.value_digest, self.accepts,
            self.quorum, self.seq,
        )


@dataclass(frozen=True)
class RejectionRecord:
    """One quorum-rejected round (frozen, terminal)."""

    proposal_id: str
    value_digest: str
    rejects: int
    quorum: int
    seq: int
    digest: str
    schema: str = DISTRIBUTED_CONSENSUS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "round-reject", self.proposal_id, self.value_digest, self.rejects,
            self.quorum, self.seq,
        )


@dataclass(frozen=True)
class WithdrawalRecord:
    """One withdrawn round (frozen, terminal)."""

    proposal_id: str
    reason: str
    seq: int
    digest: str
    schema: str = DISTRIBUTED_CONSENSUS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "withdraw", self.proposal_id, self.reason, self.seq
        )


@dataclass(frozen=True)
class RoundTally:
    """Per-round vote tally for the read view (frozen)."""

    proposal_id: str
    state: str
    accepts: int
    rejects: int
    quorum: int


@dataclass(frozen=True)
class ViewReport:
    """Cluster view of all rounds (frozen, pure read)."""

    quorum: int
    protocol: str
    committed: Tuple[str, ...]
    rejected: Tuple[str, ...]
    withdrawn: Tuple[str, ...]
    open: Tuple[str, ...]
    tallies: Tuple[RoundTally, ...]
    seq: int
    digest: str
    schema: str = DISTRIBUTED_CONSENSUS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "view", self.quorum, self.protocol, self.committed,
            self.rejected, self.withdrawn, self.open,
            [(t.proposal_id, t.state, t.accepts, t.rejects)
             for t in self.tallies],
            self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_PROPOSED = "consensus.proposed"
KIND_VOTE_RECORDED = "consensus.vote-recorded"
KIND_COMMITTED = "consensus.committed"
KIND_ROUND_REJECTED = "consensus.round-rejected"
KIND_WITHDRAWN = "consensus.withdrawn"
KIND_REJECTED = "consensus.rejected"
_KINDS = frozenset(
    {
        KIND_PROPOSED,
        KIND_VOTE_RECORDED,
        KIND_COMMITTED,
        KIND_ROUND_REJECTED,
        KIND_WITHDRAWN,
        KIND_REJECTED,
    }
)


def distributed_consensus_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for distributed consensus."""
    if kind not in _KINDS:
        raise DistributedConsensusError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    # Value digests are pins; raw values must never cross the audit boundary.
    banned = {"value", "payload", "data", "votes"}
    if any(k in detail for k in banned):
        raise DistributedConsensusError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "distributed_consensus",
        "module_version": DISTRIBUTED_CONSENSUS_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# The coordinator
# ---------------------------------------------------------------------------


class DistributedConsensus:
    """Deterministic consensus-round coordinator (Paxos/Raft-shaped).

    Books proposal rounds, host-reported votes, quorum tallies, and the
    terminal commit / reject / withdraw transitions as frozen records.
    Simulated: there is no transport, no timer, no election -- the host
    drives everything through ``vote()`` calls.

    All state mutations take a caller-supplied strictly increasing ``seq``
    (monotonic logical time); no wall-clock is read anywhere. Failed
    mutations consume their seq (fail-closed ledger position). Read views
    (``view``, ``proposal``, ``votes_for``, ...) validate the seq shape
    but do not consume it and write no audit rows.
    """

    def __init__(
        self,
        quorum: int = 1,
        voters: Tuple[str, ...] = (),
        protocol: str = "simulated",
    ) -> None:
        if isinstance(quorum, bool) or not isinstance(quorum, int) \
                or quorum < 1:
            raise BadQuorumError("quorum must be a positive int")
        if protocol not in PROTOCOLS:
            raise BadProtocolError(
                f"protocol must be one of {PROTOCOLS}, got {protocol!r}"
            )
        known: List[str] = []
        for v in voters:
            v = _check_id(v, "voter", BadVoterError)
            if v in known:
                raise BadVoterError(f"duplicate voter: {v!r}")
            known.append(v)
        if known and quorum > len(known):
            raise BadQuorumError(
                "quorum exceeds the declared voter set"
            )
        self._quorum = quorum
        self._voters: FrozenSet[str] = frozenset(known)
        self._protocol = protocol
        self._lock = threading.RLock()
        self._seq = 0
        # proposal_id -> {"record": ProposalRecord, "votes": {voter: VoteRecord},
        #                 "state": str, "terminal": record|None}
        self._rounds: Dict[str, Dict[str, Any]] = {}
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
        self._audit.append(
            distributed_consensus_audit_event(kind, seq, **detail)
        )

    def _reject_locked(self, seq: int, reason: str) -> None:
        self._emit(KIND_REJECTED, seq, reason=reason)

    def _get_round(self, proposal_id: str) -> Dict[str, Any]:
        try:
            return self._rounds[proposal_id]
        except KeyError:
            raise UnknownProposalError(f"unknown proposal: {proposal_id!r}")

    def _check_open(self, rnd: Dict[str, Any], proposal_id: str) -> None:
        if rnd["state"] != "open":
            raise TerminalProposalError(
                f"round {proposal_id!r} is {rnd['state']}, no longer open"
            )

    # -- mutations -----------------------------------------------------------

    def propose(self, proposal_id: str, value_digest: str, seq: int) -> ProposalRecord:
        """Open a new consensus round for a digest-pinned value."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                pid = _check_id(proposal_id, "proposal_id", BadProposalError)
                digest = _check_digest(value_digest)
                if pid in self._rounds:
                    raise DuplicateProposalError(
                        f"duplicate proposal: {pid!r}"
                    )
            except DistributedConsensusError as exc:
                self._seq = seq
                self._reject_locked(seq, str(exc))
                raise
            record = ProposalRecord(
                proposal_id=pid,
                value_digest=digest,
                protocol=self._protocol,
                seq=seq,
                digest=_pin("propose", pid, digest, self._protocol, seq),
            )
            self._rounds[pid] = {
                "record": record,
                "votes": {},
                "state": "open",
                "terminal": None,
            }
            self._seq = seq
            self._emit(
                KIND_PROPOSED, seq, proposal_id=pid,
                value_digest=digest, protocol=self._protocol,
            )
            return record

    def vote(
        self, proposal_id: str, voter: str, decision: str, seq: int
    ) -> VoteRecord:
        """Record one host-reported vote. Votes are final."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                pid = _check_id(proposal_id, "proposal_id", BadProposalError)
                who = _check_id(voter, "voter", BadVoterError)
                if self._voters and who not in self._voters:
                    raise UnknownVoterError(f"unknown voter: {who!r}")
                if decision not in DECISIONS:
                    raise BadDecisionError(
                        f"decision must be one of {DECISIONS}, "
                        f"got {decision!r}"
                    )
                rnd = self._get_round(pid)
                self._check_open(rnd, pid)
                if who in rnd["votes"]:
                    raise DuplicateVoteError(
                        f"voter {who!r} already voted in round {pid!r}"
                    )
            except DistributedConsensusError as exc:
                self._seq = seq
                self._reject_locked(seq, str(exc))
                raise
            record = VoteRecord(
                proposal_id=pid,
                voter=who,
                decision=decision,
                seq=seq,
                digest=_pin("vote", pid, who, decision, seq),
            )
            rnd["votes"][who] = record
            self._seq = seq
            self._emit(
                KIND_VOTE_RECORDED, seq, proposal_id=pid, voter=who,
                decision=decision,
            )
            return record

    def commit(self, proposal_id: str, seq: int) -> CommitRecord:
        """Commit an open round once accept-votes reach quorum.

        Terminal: a committed round can never change state again. When
        reject-votes reach quorum first, books a ``RejectionRecord`` and
        raises ``RejectedProposalError``.
        """
        with self._lock:
            seq = self._next_seq(seq)
            try:
                pid = _check_id(proposal_id, "proposal_id", BadProposalError)
                rnd = self._get_round(pid)
                self._check_open(rnd, pid)
                votes: Dict[str, VoteRecord] = rnd["votes"]
                accepts = sum(
                    1 for v in votes.values() if v.decision == "accept"
                )
                rejects = sum(
                    1 for v in votes.values() if v.decision == "reject"
                )
                if rejects >= self._quorum:
                    record = rnd["record"]
                    rejection = RejectionRecord(
                        proposal_id=pid,
                        value_digest=record.value_digest,
                        rejects=rejects,
                        quorum=self._quorum,
                        seq=seq,
                        digest=_pin(
                            "round-reject", pid, record.value_digest,
                            rejects, self._quorum, seq,
                        ),
                    )
                    rnd["state"] = "rejected"
                    rnd["terminal"] = rejection
                    self._seq = seq
                    self._emit(
                        KIND_ROUND_REJECTED, seq, proposal_id=pid,
                        rejects=rejects, quorum=self._quorum,
                    )
                    raise RejectedProposalError(
                        f"round {pid!r} rejected: {rejects} reject-votes "
                        f"reached quorum {self._quorum}"
                    )
                if accepts < self._quorum:
                    raise QuorumNotReachedError(
                        f"round {pid!r}: {accepts} accepts < quorum "
                        f"{self._quorum}"
                    )
            except DistributedConsensusError as exc:
                if not isinstance(exc, RejectedProposalError):
                    # RejectedProposalError already advanced the ledger above.
                    self._seq = seq
                    self._reject_locked(seq, str(exc))
                raise
            record = rnd["record"]
            commit_rec = CommitRecord(
                proposal_id=pid,
                value_digest=record.value_digest,
                accepts=accepts,
                quorum=self._quorum,
                seq=seq,
                digest=_pin(
                    "commit", pid, record.value_digest, accepts,
                    self._quorum, seq,
                ),
            )
            rnd["state"] = "committed"
            rnd["terminal"] = commit_rec
            self._seq = seq
            self._emit(
                KIND_COMMITTED, seq, proposal_id=pid, accepts=accepts,
                quorum=self._quorum,
            )
            return commit_rec

    def withdraw(self, proposal_id: str, seq: int, reason: str = "") -> WithdrawalRecord:
        """Terminally cancel an *open* round (host-declared, e.g. superseded)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                pid = _check_id(proposal_id, "proposal_id", BadProposalError)
                if not isinstance(reason, str):
                    raise BadWithdrawError("reason must be a string")
                rnd = self._get_round(pid)
                self._check_open(rnd, pid)
            except DistributedConsensusError as exc:
                self._seq = seq
                self._reject_locked(seq, str(exc))
                raise
            record = WithdrawalRecord(
                proposal_id=pid,
                reason=reason,
                seq=seq,
                digest=_pin("withdraw", pid, reason, seq),
            )
            rnd["state"] = "withdrawn"
            rnd["terminal"] = record
            self._seq = seq
            self._emit(KIND_WITHDRAWN, seq, proposal_id=pid, reason=reason)
            return record

    # -- read views (seq validated, never consumed, no audit rows) ------------

    def view(self, seq: int) -> ViewReport:
        """Cluster-wide read view of all rounds."""
        with self._lock:
            _check_seq(seq)
            committed, rejected, withdrawn, open_ids = [], [], [], []
            tallies: List[RoundTally] = []
            for pid in sorted(self._rounds):
                rnd = self._rounds[pid]
                votes: Dict[str, VoteRecord] = rnd["votes"]
                accepts = sum(
                    1 for v in votes.values() if v.decision == "accept"
                )
                rejects = sum(
                    1 for v in votes.values() if v.decision == "reject"
                )
                state: str = rnd["state"]
                tallies.append(
                    RoundTally(
                        proposal_id=pid, state=state, accepts=accepts,
                        rejects=rejects, quorum=self._quorum,
                    )
                )
                if state == "committed":
                    committed.append(pid)
                elif state == "rejected":
                    rejected.append(pid)
                elif state == "withdrawn":
                    withdrawn.append(pid)
                else:
                    open_ids.append(pid)
            return ViewReport(
                quorum=self._quorum,
                protocol=self._protocol,
                committed=tuple(committed),
                rejected=tuple(rejected),
                withdrawn=tuple(withdrawn),
                open=tuple(open_ids),
                tallies=tuple(tallies),
                seq=seq,
                digest=_pin(
                    "view", self._quorum, self._protocol,
                    committed, rejected, withdrawn, open_ids,
                    [(t.proposal_id, t.state, t.accepts, t.rejects)
                     for t in tallies],
                    seq,
                ),
            )

    def proposal(self, proposal_id: str, seq: int) -> ProposalRecord:
        """Return the frozen proposal record (read view)."""
        with self._lock:
            _check_seq(seq)
            return self._get_round(
                _check_id(proposal_id, "proposal_id", BadProposalError)
            )["record"]

    def round_state(self, proposal_id: str, seq: int) -> str:
        """Return a round's state: open / committed / rejected / withdrawn."""
        with self._lock:
            _check_seq(seq)
            return self._get_round(
                _check_id(proposal_id, "proposal_id", BadProposalError)
            )["state"]

    def votes_for(self, proposal_id: str, seq: int) -> Tuple[VoteRecord, ...]:
        """Return a round's recorded votes, sorted by voter (read view)."""
        with self._lock:
            _check_seq(seq)
            rnd = self._get_round(
                _check_id(proposal_id, "proposal_id", BadProposalError)
            )
            return tuple(
                rnd["votes"][v] for v in sorted(rnd["votes"])
            )

    def proposal_ids(self, seq: int) -> Tuple[str, ...]:
        """Return all proposal ids, sorted (read view)."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._rounds))

    def audit_log(self) -> Tuple[Mapping[str, Any], ...]:
        """Return the audit rows booked so far (oldest first)."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check: propose, vote, commit, view, audit."""
    dc = DistributedConsensus(quorum=2, voters=("n1", "n2", "n3"),
                              protocol="simulated")
    p = dc.propose("p1", "sha256:" + "ab" * 32, 1)
    assert p.verify()
    dc.vote("p1", "n1", "accept", 2)
    dc.vote("p1", "n2", "accept", 3)
    c = dc.commit("p1", 4)
    assert c.verify()
    v = dc.view(5)
    assert v.verify()
    assert v.committed == ("p1",)
    kinds = [e["kind"] for e in dc.audit_log()]
    assert kinds == [
        "consensus.proposed", "consensus.vote-recorded",
        "consensus.vote-recorded", "consensus.committed",
    ], kinds
    print("distributed-consensus OK: propose, vote, commit, view, audit")


if __name__ == "__main__":
    main()
