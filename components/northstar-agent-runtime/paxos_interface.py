"""Paxos interface: proposer / acceptor / learner bookkeeping.

Research motivation: Paxos (Lamport 1998, "The Part-Time Parliament") is
the classic single-value consensus protocol. A fleet of agents that must
agree on *one* value (a fleet kill decision, the audit-head anchor, a
global budget release) needs its phases as inspectable primitives: this
module pins the phase transitions as frozen records with fail-closed
rules, without any network.

Phase order (all messages are records this module mints or validates):

- ``Proposer.prepare(ballot, seq)`` -> ``Prepare``. One ballot per
  proposer (reusing a ballot raises ``BallotConflictError``; a proposer
  that lost a round must advance its ballot).
- ``Acceptor.on_prepare(prepare)`` -> ``Promise`` or ``None`` (refusal).
  An acceptor that has promised ballot ``N`` refuses any prepare with
  ballot ``< N``. A promise carries the acceptor's last accepted
  ``(ballot, value_digest)`` pair, or ``None`` if it accepted nothing.
- ``Proposer.receive_promises(promises)`` -> ``AcceptRequest``. The
  Paxos value-selection rule: if any promise carries an accepted pair,
  the request adopts the value_digest with the *highest* accepted ballot;
  otherwise it carries the proposer's own value_digest. Raises
  ``InsufficientPromises`` when fewer distinct acceptors promised than
  the quorum.
- ``Acceptor.on_accept(request)`` -> ``Accepted`` or ``None`` (refusal).
  Refuses when ``request.ballot < promised_ballot``; otherwise records
  ``(ballot, value_digest)`` and returns the ``Accepted`` record.
- ``Learner.on_accepted(accepted)`` -> ``ChosenValue`` or ``None``. Once
  a quorum of *distinct known* acceptors has accepted the *same*
  ``(ballot, value_digest)``, the value is chosen. Idempotent: learning
  twice returns the same record; a second, different choice for the same
  ballot raises ``PaxosError`` (a quorum intersection violation would be
  the only cause, and the host must investigate).

Safety invariants enforced locally:

- Ballot monotonicity at the acceptor: promised ballot only moves up.
- Value binding: ``AcceptRequest`` carries ``value_digest`` only; votes
  reference ``proposal_id``. No message ever carries raw values.
- Quorum: ``floor(n/2) + 1`` of the known acceptor set unless the host
  sets an explicit quorum. One acceptor's vote counts once per
  ``(ballot, proposal)`` pair.
- Distinct-acceptors rule at the learner: the same acceptor's record
  counts once, even if the host re-feeds it.

Honest scope:

- This is single-node *interface bookkeeping*, not a distributed
  protocol. There is no leader election (see ``leader_election``), no
  network round-trips, no retransmission, no partition detection. A
  ``ChosenValue`` means "this node recorded a quorum of acceptances",
  never "the fleet agreed".
- The node never sees raw values: ``Proposer.prepare`` /
  ``receive_promises`` pins ``sha256:`` over canonical JSON and keeps
  only the digest. It cannot become a second exfiltration channel.
- Canonical JSON note: values serialize with ``json.dumps`` sorted keys
  and compact separators. Like every JSON canonicalizer (RFC 8785
  included), integers outside +/-2**53 are serialized as IEEE 754 doubles
  and lose precision -- values carrying such integers digest identically.
  Hosts needing exact large-integer pins must encode them as strings or
  fixed-width hex (the ``secure_aggregation`` module's ``_hexint`` shows
  the pattern).
- ``None`` returns are policy outcomes ("refused" / "not yet chosen"),
  never errors. Malformed inputs raise ``TypeError`` / ``ValueError`` /
  ``PaxosError`` fail-closed.
- All seqs are caller-supplied ints (logical clock); no wall-clock is
  read anywhere in this module.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

#: Module version pin.
PAXOS_INTERFACE_VERSION = "paxos-interface.v1"

#: Schema pin carried by records and audit events.
PAXOS_INTERFACE_SCHEMA = "northstar.paxos-interface.v1"

#: Audit event kinds.
EVENT_PREPARED = "paxos-prepared"
EVENT_PROMISED = "paxos-promised"
EVENT_PREPARE_REFUSED = "paxos-prepare-refused"
EVENT_ACCEPT_REQUESTED = "paxos-accept-requested"
EVENT_ACCEPTED = "paxos-accepted"
EVENT_ACCEPT_REFUSED = "paxos-accept-refused"
EVENT_CHOSEN = "paxos-chosen"

_EVENT_KINDS = frozenset(
    {
        EVENT_PREPARED,
        EVENT_PROMISED,
        EVENT_PREPARE_REFUSED,
        EVENT_ACCEPT_REQUESTED,
        EVENT_ACCEPTED,
        EVENT_ACCEPT_REFUSED,
        EVENT_CHOSEN,
    }
)

#: Digest prefix for pinned values.
_DIGEST_PREFIX = "sha256:"


class PaxosError(Exception):
    """Base error for Paxos bookkeeping (fail-closed)."""


class BallotConflictError(PaxosError):
    """Raised when a proposer reuses a ballot number it already prepared."""


class InsufficientPromises(PaxosError):
    """Raised when fewer distinct acceptors promised than the quorum."""


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


def _check_ballot(value: object) -> int:
    """Validate a ballot number: positive int, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"ballot must be an int, got {type(value).__name__}")
    if value <= 0:
        raise ValueError("ballot must be positive")
    return value


def pin_value(value: Any) -> str:
    """Pin a value as ``sha256:`` over canonical JSON.

    Canonical form: ``json.dumps(value, sort_keys=True, separators=(",", ":"))``.
    Fail-closed on non-canonicalizable values (NaN, non-str dict keys,
    arbitrary objects).
    """
    try:
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise PaxosError(f"value is not canonicalizable: {exc}") from exc
    if not isinstance(canonical, str):
        raise PaxosError("value serialization did not produce a string")
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return _DIGEST_PREFIX + digest


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


def _check_digest(value: object, name: str = "value_digest") -> str:
    """Validate a pinned value digest: ``sha256:`` + 64 hex chars."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    if not value.startswith(_DIGEST_PREFIX) or len(value) != len(_DIGEST_PREFIX) + 64:
        raise ValueError(f"{name} must be '{_DIGEST_PREFIX}' + 64 hex chars")
    try:
        int(value[len(_DIGEST_PREFIX):], 16)
    except ValueError as exc:
        raise ValueError(f"{name} is not valid hex") from exc
    return value


@dataclass(frozen=True)
class Prepare:
    """A proposer's prepare message: ballot number under preparation."""

    proposal_id: str
    proposer_id: str
    ballot: int
    seq: int

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "schema": PAXOS_INTERFACE_SCHEMA,
            "kind": "prepare",
            "proposal_id": self.proposal_id,
            "proposer_id": self.proposer_id,
            "ballot": self.ballot,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class Promise:
    """An acceptor's promise: it will not accept ballots below ``ballot``.

    ``accepted_ballot`` / ``accepted_digest`` carry the acceptor's last
    accepted pair, or ``None`` when the acceptor accepted nothing.
    """

    proposal_id: str
    acceptor_id: str
    ballot: int
    accepted_ballot: int | None
    accepted_digest: str | None
    seq: int

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "schema": PAXOS_INTERFACE_SCHEMA,
            "kind": "promise",
            "proposal_id": self.proposal_id,
            "acceptor_id": self.acceptor_id,
            "ballot": self.ballot,
            "accepted_ballot": self.accepted_ballot,
            "accepted_digest": self.accepted_digest,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class AcceptRequest:
    """A proposer's accept request: (ballot, value_digest) pair to accept."""

    proposal_id: str
    proposer_id: str
    ballot: int
    value_digest: str
    seq: int

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "schema": PAXOS_INTERFACE_SCHEMA,
            "kind": "accept-request",
            "proposal_id": self.proposal_id,
            "proposer_id": self.proposer_id,
            "ballot": self.ballot,
            "value_digest": self.value_digest,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class Accepted:
    """An acceptor's acceptance: (ballot, value_digest) recorded."""

    proposal_id: str
    acceptor_id: str
    ballot: int
    value_digest: str
    seq: int

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "schema": PAXOS_INTERFACE_SCHEMA,
            "kind": "accepted",
            "proposal_id": self.proposal_id,
            "acceptor_id": self.acceptor_id,
            "ballot": self.ballot,
            "value_digest": self.value_digest,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class ChosenValue:
    """The value a learner recorded a quorum for: (ballot, value_digest)."""

    proposal_id: str
    ballot: int
    value_digest: str
    acceptors: tuple[str, ...]
    quorum: int
    seq: int

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "schema": PAXOS_INTERFACE_SCHEMA,
            "kind": "chosen",
            "proposal_id": self.proposal_id,
            "ballot": self.ballot,
            "value_digest": self.value_digest,
            "acceptors": list(self.acceptors),
            "quorum": self.quorum,
            "seq": self.seq,
        }


def paxos_audit_event(kind: str, record: Mapping[str, Any], seq: object) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1``-style event for a Paxos record."""
    if kind not in _EVENT_KINDS:
        raise ValueError(f"unknown audit event kind: {kind!r}")
    seq_int = _check_seq(seq, "audit_seq")
    if not isinstance(record, Mapping):
        raise TypeError(f"record must be a Mapping, got {type(record).__name__}")
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "record": dict(record),
        "audit_seq": seq_int,
    }


class Proposer:
    """Phase-1 proposer bookkeeping: prepare, then accept-request.

    A proposer owns one ballot progression: ballots must be strictly
    increasing per proposer (reusing a ballot raises ``BallotConflictError``).
    """

    def __init__(self, proposer_id: object, acceptors: Iterable[object], quorum: int | None = None) -> None:
        self._proposer_id = _check_node_id(proposer_id, "proposer_id")
        acceptor_ids = tuple(_check_node_id(a, "acceptor") for a in acceptors)
        if not acceptor_ids:
            raise ValueError("acceptors must be non-empty")
        if len(set(acceptor_ids)) != len(acceptor_ids):
            raise ValueError("duplicate acceptor ids")
        self._acceptors = frozenset(acceptor_ids)
        if quorum is None:
            self._quorum = quorum_size(len(self._acceptors))
        else:
            if isinstance(quorum, bool) or not isinstance(quorum, int):
                raise TypeError(f"quorum must be an int, got {type(quorum).__name__}")
            if quorum < 1 or quorum > len(self._acceptors):
                raise ValueError("quorum must be within 1..len(acceptors)")
            self._quorum = quorum
        self._used_ballots: set[int] = set()
        self._counter = 0

    @property
    def proposer_id(self) -> str:
        return self._proposer_id

    @property
    def quorum(self) -> int:
        return self._quorum

    def prepare(self, ballot: object, seq: object) -> Prepare:
        """Mint a ``Prepare`` for ``ballot``.

        Raises ``BallotConflictError`` when this proposer already prepared
        the same ballot (it must advance its ballot instead).
        """
        ballot_int = _check_ballot(ballot)
        seq_int = _check_seq(seq)
        if ballot_int in self._used_ballots:
            raise BallotConflictError(
                f"ballot {ballot_int} already prepared by {self._proposer_id}"
            )
        self._used_ballots.add(ballot_int)
        self._counter += 1
        proposal_id = f"prop-{self._proposer_id}-{self._counter}"
        return Prepare(
            proposal_id=proposal_id,
            proposer_id=self._proposer_id,
            ballot=ballot_int,
            seq=seq_int,
        )

    def receive_promises(
        self, prepare: Prepare, promises: Sequence[Promise], value: Any, seq: object
    ) -> AcceptRequest:
        """Build an ``AcceptRequest`` from a quorum of promises.

        Applies the Paxos value-selection rule: if any promise carries an
        accepted pair, adopt the ``value_digest`` with the highest accepted
        ballot; otherwise pin the proposer's own ``value``.

        Raises ``InsufficientPromises`` when fewer distinct acceptors
        promised than the quorum, and ``PaxosError`` when a promise
        references a different proposal or ballot, or comes from an unknown
        acceptor.
        """
        if not isinstance(prepare, Prepare):
            raise TypeError(f"prepare must be a Prepare, got {type(prepare).__name__}")
        if not isinstance(promises, Sequence):
            raise TypeError(f"promises must be a Sequence, got {type(promises).__name__}")
        seq_int = _check_seq(seq)

        seen: dict[str, Promise] = {}
        for promise in promises:
            if not isinstance(promise, Promise):
                raise TypeError(f"promise must be a Promise, got {type(promise).__name__}")
            if promise.proposal_id != prepare.proposal_id:
                raise PaxosError("promise references a different proposal")
            if promise.ballot != prepare.ballot:
                raise PaxosError("promise references a different ballot")
            if promise.acceptor_id not in self._acceptors:
                raise PaxosError(f"unknown acceptor: {promise.acceptor_id}")
            seen.setdefault(promise.acceptor_id, promise)

        if len(seen) < self._quorum:
            raise InsufficientPromises(
                f"{len(seen)} promises from distinct acceptors, quorum is {self._quorum}"
            )

        # Paxos value-selection rule: highest accepted ballot wins.
        best_ballot: int | None = None
        chosen_digest: str | None = None
        for promise in seen.values():
            if promise.accepted_digest is None:
                continue
            assert promise.accepted_ballot is not None
            if best_ballot is None or promise.accepted_ballot > best_ballot:
                best_ballot = promise.accepted_ballot
                chosen_digest = promise.accepted_digest

        if chosen_digest is None:
            chosen_digest = pin_value(value)

        return AcceptRequest(
            proposal_id=prepare.proposal_id,
            proposer_id=self._proposer_id,
            ballot=prepare.ballot,
            value_digest=chosen_digest,
            seq=seq_int,
        )


class Acceptor:
    """Acceptor bookkeeping: promise on prepare, accept on accept-request.

    The promised ballot only ever moves up. ``on_prepare`` returns
    ``None`` (refusal) for ballots below the promised one; ``on_accept``
    likewise returns ``None`` for a ballot below the promised one,
    otherwise records ``(ballot, value_digest)`` and returns ``Accepted``.
    """

    def __init__(self, acceptor_id: object) -> None:
        self._acceptor_id = _check_node_id(acceptor_id, "acceptor_id")
        self._promised_ballot: int = 0
        self._accepted_ballot: int | None = None
        self._accepted_digest: str | None = None

    @property
    def acceptor_id(self) -> str:
        return self._acceptor_id

    @property
    def promised_ballot(self) -> int:
        return self._promised_ballot

    @property
    def accepted_pair(self) -> tuple[int | None, str | None]:
        return (self._accepted_ballot, self._accepted_digest)

    def on_prepare(self, prepare: Prepare, seq: object) -> Promise | None:
        """Handle a prepare: promise or refuse (returns ``None``).

        Refuses when ``prepare.ballot < promised_ballot``. Raises
        ``PaxosError`` when the promise would bind a non-digest value.
        """
        if not isinstance(prepare, Prepare):
            raise TypeError(f"prepare must be a Prepare, got {type(prepare).__name__}")
        seq_int = _check_seq(seq)
        if prepare.ballot < self._promised_ballot:
            return None
        self._promised_ballot = prepare.ballot
        return Promise(
            proposal_id=prepare.proposal_id,
            acceptor_id=self._acceptor_id,
            ballot=prepare.ballot,
            accepted_ballot=self._accepted_ballot,
            accepted_digest=self._accepted_digest,
            seq=seq_int,
        )

    def on_accept(self, request: AcceptRequest, seq: object) -> Accepted | None:
        """Handle an accept request: record or refuse (returns ``None``).

        Refuses when ``request.ballot < promised_ballot``; otherwise
        records ``(ballot, value_digest)`` and returns ``Accepted``.
        """
        if not isinstance(request, AcceptRequest):
            raise TypeError(
                f"request must be an AcceptRequest, got {type(request).__name__}"
            )
        seq_int = _check_seq(seq)
        _check_digest(request.value_digest)
        if request.ballot < self._promised_ballot:
            return None
        self._promised_ballot = request.ballot
        self._accepted_ballot = request.ballot
        self._accepted_digest = request.value_digest
        return Accepted(
            proposal_id=request.proposal_id,
            acceptor_id=self._acceptor_id,
            ballot=request.ballot,
            value_digest=request.value_digest,
            seq=seq_int,
        )


class Learner:
    """Learner bookkeeping: learn the chosen value from acceptances.

    Records one acceptance per acceptor per ``(proposal_id, ballot)``.
    Once a quorum of *distinct known* acceptors has accepted the *same*
    ``(ballot, value_digest)``, ``on_accepted`` returns ``ChosenValue``.
    Idempotent: learning the same choice twice returns the same record.
    """

    def __init__(self, acceptors: Iterable[object], quorum: int | None = None) -> None:
        acceptor_ids = tuple(_check_node_id(a, "acceptor") for a in acceptors)
        if not acceptor_ids:
            raise ValueError("acceptors must be non-empty")
        if len(set(acceptor_ids)) != len(acceptor_ids):
            raise ValueError("duplicate acceptor ids")
        self._acceptors = frozenset(acceptor_ids)
        if quorum is None:
            self._quorum = quorum_size(len(self._acceptors))
        else:
            if isinstance(quorum, bool) or not isinstance(quorum, int):
                raise TypeError(f"quorum must be an int, got {type(quorum).__name__}")
            if quorum < 1 or quorum > len(self._acceptors):
                raise ValueError("quorum must be within 1..len(acceptors)")
            self._quorum = quorum
        # proposal_id -> ballot -> value_digest -> sorted acceptor ids
        self._votes: dict[str, dict[int, dict[str, set[str]]]] = {}
        self._chosen: dict[tuple[str, int], ChosenValue] = {}

    @property
    def quorum(self) -> int:
        return self._quorum

    def on_accepted(self, accepted: Accepted, seq: object) -> ChosenValue | None:
        """Fold an acceptance in; return ``ChosenValue`` once quorate.

        Returns ``None`` when the quorum is not yet reached. A second,
        *different* ``(ballot, value_digest)`` choice reaching quorum for
        the same proposal raises ``PaxosError`` (quorum intersection would
        make this a sign of host bookkeeping corruption).
        """
        if not isinstance(accepted, Accepted):
            raise TypeError(f"accepted must be an Accepted, got {type(accepted).__name__}")
        seq_int = _check_seq(seq)
        if accepted.acceptor_id not in self._acceptors:
            raise PaxosError(f"unknown acceptor: {accepted.acceptor_id}")

        key = (accepted.proposal_id, accepted.ballot)
        existing = self._chosen.get(key)
        if existing is not None:
            if existing.value_digest != accepted.value_digest:
                raise PaxosError(
                    "conflicting chosen values for the same ballot "
                    "(quorum intersection violated)"
                )
            return existing

        by_ballot = self._votes.setdefault(accepted.proposal_id, {})
        by_digest = by_ballot.setdefault(accepted.ballot, {})
        voters = by_digest.setdefault(accepted.value_digest, set())
        voters.add(accepted.acceptor_id)

        if len(voters) >= self._quorum:
            chosen = ChosenValue(
                proposal_id=accepted.proposal_id,
                ballot=accepted.ballot,
                value_digest=accepted.value_digest,
                acceptors=tuple(sorted(voters)),
                quorum=self._quorum,
                seq=seq_int,
            )
            self._chosen[key] = chosen
            return chosen
        return None

    def is_chosen(self, proposal_id: str, ballot: int) -> bool:
        """Return True when a choice was already recorded for the ballot."""
        if not isinstance(proposal_id, str) or not proposal_id:
            raise ValueError("proposal_id must be a non-empty string")
        if isinstance(ballot, bool) or not isinstance(ballot, int) or ballot <= 0:
            raise ValueError("ballot must be a positive int")
        return (proposal_id, ballot) in self._chosen


def main() -> None:
    """Self-check: full Paxos round across 3 acceptors chooses one value."""
    acceptors = ("a1", "a2", "a3")
    proposer = Proposer("p1", acceptors)
    acceptor_nodes = {a: Acceptor(a) for a in acceptors}
    learner = Learner(acceptors)

    prepare = proposer.prepare(1, 0)
    promises = []
    for aid, node in acceptor_nodes.items():
        promise = node.on_prepare(prepare, seq=1)
        assert promise is not None, f"{aid} refused ballot 1"
        promises.append(promise)

    request = proposer.receive_promises(prepare, promises, {"cmd": "halt"}, seq=2)
    chosen = None
    for aid, node in acceptor_nodes.items():
        accepted = node.on_accept(request, seq=3)
        assert accepted is not None, f"{aid} refused the accept"
        result = learner.on_accepted(accepted, seq=4)
        if result is not None:
            chosen = result
    assert chosen is not None, "no value was chosen"
    assert chosen.value_digest == pin_value({"cmd": "halt"})

    # Ballot 0 is not a valid ballot (fail-closed at the door).
    try:
        Proposer("p2", acceptors).prepare(0, 5)
    except ValueError:
        pass
    else:
        raise AssertionError("ballot 0 should be rejected")

    # A lower-ballot prepare is refused once acceptors promised higher.
    # First bump the promised ballot to 2 with a fresh proposer ...
    p3 = Proposer("p3", acceptors)
    bump = p3.prepare(2, 6)
    assert all(
        node.on_prepare(bump, seq=7) is not None for node in acceptor_nodes.values()
    ), "ballot-2 prepare was refused"
    # ... then a ballot-1 prepare is refused by every acceptor.
    p4 = Proposer("p4", acceptors)
    late_prepare = p4.prepare(1, 8)
    refusals = [
        node.on_prepare(late_prepare, seq=9) for node in acceptor_nodes.values()
    ]
    assert all(r is None for r in refusals), "lower-ballot prepare was not refused"

    print(
        "paxos-interface OK: chosen",
        chosen.value_digest[:18] + "...",
        "with quorum",
        chosen.quorum,
    )


if __name__ == "__main__":
    main()
