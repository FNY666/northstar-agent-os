"""Two-phase commit (2PC): atomic commit across a participant cohort.

Research note: two-phase commit (Gray, 1978; Bernstein, Hadzilacos &
Goodman) is the classic atomic-commitment protocol for distributed
transactions. A *coordinator* runs two phases: in **prepare** it asks every
participant whether it can commit; in **commit/abort** it broadcasts the
final decision. Commit requires *unanimous* yes votes — one no (or one
crashed voter) aborts the whole transaction.

* **Phase 1 (prepare)** — every participant's vote function is invoked and
  recorded as a frozen ``VoteRecord`` in registration order. A voter that
  raises is recorded as ``NO`` (fail-closed: a crash can never be read as
  consent); the exception type is kept in the record's ``note``.
* **Phase 2 (commit/abort)** — the decision is unanimous-yes → commit,
  anything else → abort. Every participant is notified of the outcome in
  registration order; a crashing notification is recorded and the remaining
  participants are still notified (best-effort, like the saga's
  compensation path — abandoning half the cohort is worse).
* **Sticky decisions** — the decision log is append-only and keyed by
  transaction id. Re-running ``execute`` on an already-decided transaction
  returns the recorded outcome *without re-voting*: the decision survives
  the coordinator, which is the whole point of the protocol (crash between
  the phases → ``decision_for`` recovers the recorded decision).
* **No wall-clock** — all ordering uses caller-supplied int ``seq`` values,
  so the module is deterministic and replayable.
* **Fail-closed** — committing without a successful all-yes prepare raises;
  committing an abort-decided prepare raises; re-preparing a decided
  transaction raises; malformed participants/transactions/seqs raise at
  construction/call time, never silently.

Honest scope: this is the *protocol state machine*, not a distributed
system — there is no network, no timeout, no participant recovery
protocol, and a participant that lies (votes yes, then does something
else) is invisible to it. The coordinator pins only ``sha256:`` digests of
payloads, never raw payloads, so it cannot become an exfiltration channel.
``committed`` means "every participant voted yes and was told to commit",
never "every participant actually committed" — durable execution is the
host's job. The decision log is in-memory; cross-restart durability is the
host's job. A blocking coordinator (a voter that hangs forever) blocks the
protocol by design — pair with ``timeout_manager`` if that is a concern.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, Mapping, Optional, Tuple

#: Module version.
TWO_PHASE_COMMIT_VERSION = "two-phase-commit.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.two-phase-commit.v1"

#: Digest prefix used for payload pins.
_DIGEST_PREFIX = "sha256:"


class TwoPhaseCommitError(Exception):
    """Protocol violation or malformed input (programming error)."""


class Vote(str, Enum):
    """A participant's prepare-phase vote."""

    YES = "yes"
    NO = "no"


def _check_id(value: object, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise TwoPhaseCommitError(f"{what} must be a non-empty str")
    return value


def _check_seq(seq: object, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise TwoPhaseCommitError(f"{what} must be a non-negative int")
    return seq


def _check_digest(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(_DIGEST_PREFIX)
        or len(value) != len(_DIGEST_PREFIX) + 64
    ):
        raise TwoPhaseCommitError(
            "payload_digest must be a 'sha256:' + 64 lowercase-hex-char pin"
        )
    hexpart = value[len(_DIGEST_PREFIX):]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise TwoPhaseCommitError(
            "payload_digest must be a 'sha256:' + 64 lowercase-hex-char pin"
        )
    return value


@dataclass(frozen=True)
class Transaction:
    """A transaction proposed to the cohort.

    The coordinator only ever sees ``payload_digest`` — a ``sha256:`` pin
    over the payload computed by the host — so it cannot observe or leak
    the payload contents.
    """

    transaction_id: str
    payload_digest: str

    def __post_init__(self) -> None:
        _check_id(self.transaction_id, "transaction_id")
        _check_digest(self.payload_digest)


@dataclass(frozen=True)
class Participant:
    """A registered cohort member.

    ``decide`` is the host-supplied vote function (must be deterministic
    for replayability); ``on_commit`` / ``on_abort`` are the host-supplied
    outcome notifications. All three are invoked synchronously by the
    coordinator.
    """

    participant_id: str
    decide: Callable[[Transaction], Vote]
    on_commit: Callable[[Transaction], None]
    on_abort: Callable[[Transaction], None]

    def __post_init__(self) -> None:
        _check_id(self.participant_id, "participant_id")
        for name in ("decide", "on_commit", "on_abort"):
            if not callable(getattr(self, name)):
                raise TwoPhaseCommitError(f"{name} must be callable")


@dataclass(frozen=True)
class VoteRecord:
    """One participant's recorded prepare-phase vote."""

    participant_id: str
    vote: Vote
    seq: int
    note: str = ""

    def __post_init__(self) -> None:
        _check_id(self.participant_id, "participant_id")
        if not isinstance(self.vote, Vote):
            raise TwoPhaseCommitError("vote must be a Vote")
        _check_seq(self.seq)
        if not isinstance(self.note, str):
            raise TwoPhaseCommitError("note must be a str")


@dataclass(frozen=True)
class PrepareResult:
    """Outcome of phase 1: all votes plus the phase-2 decision."""

    transaction_id: str
    votes: Tuple[VoteRecord, ...]
    decision: str  # "commit" or "abort"
    seq: int

    def __post_init__(self) -> None:
        _check_id(self.transaction_id, "transaction_id")
        if self.decision not in ("commit", "abort"):
            raise TwoPhaseCommitError("decision must be 'commit' or 'abort'")
        _check_seq(self.seq)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "transaction_id": self.transaction_id,
            "votes": [
                {
                    "participant_id": v.participant_id,
                    "vote": v.vote.value,
                    "seq": v.seq,
                    "note": v.note,
                }
                for v in self.votes
            ],
            "decision": self.decision,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class TxnOutcome:
    """Final outcome of a two-phase commit run."""

    transaction_id: str
    decision: str  # "commit" or "abort"
    votes: Tuple[VoteRecord, ...]
    notified: Tuple[str, ...]  # participant ids notified, registration order
    seq: int

    def __post_init__(self) -> None:
        _check_id(self.transaction_id, "transaction_id")
        if self.decision not in ("commit", "abort"):
            raise TwoPhaseCommitError("decision must be 'commit' or 'abort'")
        _check_seq(self.seq)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "transaction_id": self.transaction_id,
            "decision": self.decision,
            "votes": [
                {
                    "participant_id": v.participant_id,
                    "vote": v.vote.value,
                    "seq": v.seq,
                    "note": v.note,
                }
                for v in self.votes
            ],
            "notified": list(self.notified),
            "seq": self.seq,
        }


class Coordinator:
    """Phase primitives: prepare / commit / abort.

    The coordinator owns the participant registry and runs the phases.
    It does not keep a decision log — that is the orchestrator's job
    (see :class:`TwoPhaseCommit`).
    """

    def __init__(self, coordinator_id: str, participants: Tuple[Participant, ...]) -> None:
        self._coordinator_id = _check_id(coordinator_id, "coordinator_id")
        if not isinstance(participants, tuple):
            raise TwoPhaseCommitError("participants must be a tuple")
        if not participants:
            raise TwoPhaseCommitError("participants must not be empty")
        seen = set()
        for p in participants:
            if not isinstance(p, Participant):
                raise TwoPhaseCommitError("participants must be Participant records")
            if p.participant_id in seen:
                raise TwoPhaseCommitError(
                    f"duplicate participant_id: {p.participant_id!r}"
                )
            seen.add(p.participant_id)
        self._participants = participants

    @property
    def coordinator_id(self) -> str:
        return self._coordinator_id

    @property
    def participant_ids(self) -> Tuple[str, ...]:
        return tuple(p.participant_id for p in self._participants)

    def prepare(self, transaction: Transaction, seq: int) -> PrepareResult:
        """Phase 1: collect every participant's vote."""
        if not isinstance(transaction, Transaction):
            raise TwoPhaseCommitError("transaction must be a Transaction")
        seq = _check_seq(seq)
        records: list[VoteRecord] = []
        for participant in self._participants:
            vote = self._vote_of(participant, transaction)
            records.append(
                VoteRecord(
                    participant_id=participant.participant_id,
                    vote=vote[0],
                    seq=seq,
                    note=vote[1],
                )
            )
        decision = (
            "commit" if all(r.vote is Vote.YES for r in records) else "abort"
        )
        return PrepareResult(
            transaction_id=transaction.transaction_id,
            votes=tuple(records),
            decision=decision,
            seq=seq,
        )

    @staticmethod
    def _vote_of(participant: Participant, transaction: Transaction) -> Tuple[Vote, str]:
        """Invoke a voter's decide function; a crash is a NO (fail-closed)."""
        try:
            vote = participant.decide(transaction)
        except Exception as exc:  # noqa: BLE001 - crash is a vote, recorded
            return Vote.NO, f"voter-raised:{type(exc).__name__}"
        if vote is Vote.YES:
            return Vote.YES, ""
        if vote is Vote.NO:
            return Vote.NO, ""
        # A non-Vote return is a programming error at the voter: fail closed.
        return Vote.NO, f"voter-returned-non-vote:{type(vote).__name__}"

    def commit(
        self, transaction: Transaction, prepare_result: PrepareResult, seq: int
    ) -> TxnOutcome:
        """Phase 2a: notify every participant to commit.

        Requires a matching all-yes prepare; anything else raises.
        """
        self._check_phase2(transaction, prepare_result, seq, expected="commit")
        return self._broadcast(transaction, prepare_result, seq, commit=True)

    def abort(
        self, transaction: Transaction, prepare_result: PrepareResult, seq: int
    ) -> TxnOutcome:
        """Phase 2b: notify every participant to abort."""
        self._check_phase2(transaction, prepare_result, seq, expected="abort")
        return self._broadcast(transaction, prepare_result, seq, commit=False)

    def _check_phase2(
        self,
        transaction: Transaction,
        prepare_result: PrepareResult,
        seq: int,
        expected: str,
    ) -> int:
        if not isinstance(transaction, Transaction):
            raise TwoPhaseCommitError("transaction must be a Transaction")
        if not isinstance(prepare_result, PrepareResult):
            raise TwoPhaseCommitError("prepare_result must be a PrepareResult")
        seq = _check_seq(seq)
        if prepare_result.transaction_id != transaction.transaction_id:
            raise TwoPhaseCommitError(
                "prepare_result is for a different transaction"
            )
        if prepare_result.decision != expected:
            raise TwoPhaseCommitError(
                f"cannot {expected}: prepare decided {prepare_result.decision!r}"
            )
        return seq

    def _broadcast(
        self,
        transaction: Transaction,
        prepare_result: PrepareResult,
        seq: int,
        commit: bool,
    ) -> TxnOutcome:
        notified: list[str] = []
        for participant in self._participants:
            handler = participant.on_commit if commit else participant.on_abort
            try:
                handler(transaction)
            except Exception:  # noqa: BLE001 - best-effort notification
                pass
            notified.append(participant.participant_id)
        return TxnOutcome(
            transaction_id=transaction.transaction_id,
            decision="commit" if commit else "abort",
            votes=prepare_result.votes,
            notified=tuple(notified),
            seq=seq,
        )


class TwoPhaseCommit:
    """Runs the full protocol and keeps the sticky decision log.

    ``execute`` runs prepare then the decided phase-2, records the
    decision, and returns the outcome. Re-running ``execute`` on an
    already-decided transaction returns the recorded outcome without
    re-voting (idempotent recovery — the decision survives the phases).
    """

    def __init__(self, coordinator: Coordinator) -> None:
        if not isinstance(coordinator, Coordinator):
            raise TwoPhaseCommitError("coordinator must be a Coordinator")
        self._coordinator = coordinator
        self._decisions: Dict[str, TxnOutcome] = {}

    @property
    def coordinator(self) -> Coordinator:
        return self._coordinator

    def execute(self, transaction: Transaction, seq: int) -> TxnOutcome:
        """Run the full two-phase commit for one transaction."""
        if not isinstance(transaction, Transaction):
            raise TwoPhaseCommitError("transaction must be a Transaction")
        seq = _check_seq(seq)
        existing = self._decisions.get(transaction.transaction_id)
        if existing is not None:
            return existing
        prepare_result = self._coordinator.prepare(transaction, seq)
        if prepare_result.decision == "commit":
            outcome = self._coordinator.commit(transaction, prepare_result, seq)
        else:
            outcome = self._coordinator.abort(transaction, prepare_result, seq)
        self._decisions[transaction.transaction_id] = outcome
        return outcome

    def decision_for(self, transaction_id: str) -> Optional[str]:
        """Recover the recorded decision, or None if never decided."""
        _check_id(transaction_id, "transaction_id")
        outcome = self._decisions.get(transaction_id)
        return outcome.decision if outcome is not None else None

    def decided_transactions(self) -> Tuple[str, ...]:
        """Transaction ids decided so far, in decision order."""
        return tuple(self._decisions.keys())


_AUDIT_KINDS = ("prepared", "committed", "aborted")


def two_phase_commit_audit_event(
    kind: str, record: Mapping[str, object], seq: int
) -> dict:
    """Shape an ``audit.ndjson/1``-style record for a 2PC event."""
    if kind not in _AUDIT_KINDS:
        raise TwoPhaseCommitError(
            f"kind must be one of {_AUDIT_KINDS}"
        )
    if not isinstance(record, Mapping):
        raise TwoPhaseCommitError("record must be a mapping")
    seq = _check_seq(seq, "audit seq")
    return {
        "schema": SCHEMA_PIN,
        "kind": f"two-phase-commit.{kind}",
        "record": dict(record),
        "audit_seq": seq,
    }


def _digest(pin: str) -> str:
    return _DIGEST_PREFIX + pin


def _yes(_txn: Transaction) -> Vote:
    return Vote.YES


def _no(_txn: Transaction) -> Vote:
    return Vote.NO


def _noop(_txn: Transaction) -> None:
    return None


def main() -> None:
    txn = Transaction("txn-1", _digest("a" * 64))
    coord = Coordinator(
        "coord-1",
        (
            Participant("p1", _yes, _noop, _noop),
            Participant("p2", _yes, _noop, _noop),
        ),
    )
    tpc = TwoPhaseCommit(coord)
    outcome = tpc.execute(txn, 1)
    assert outcome.decision == "commit", outcome
    assert tpc.decision_for("txn-1") == "commit", outcome
    # Idempotent re-execution: same outcome, no re-vote.
    again = tpc.execute(txn, 2)
    assert again is outcome, again

    coord2 = Coordinator(
        "coord-2",
        (
            Participant("p1", _yes, _noop, _noop),
            Participant("p2", _no, _noop, _noop),
        ),
    )
    tpc2 = TwoPhaseCommit(coord2)
    outcome2 = tpc2.execute(Transaction("txn-2", _digest("b" * 64)), 3)
    assert outcome2.decision == "abort", outcome2
    assert [v.vote for v in outcome2.votes] == [Vote.YES, Vote.NO], outcome2

    # Crashing voter is a NO (fail-closed).
    def boom(_txn: Transaction) -> Vote:
        raise RuntimeError("voter exploded")

    coord3 = Coordinator(
        "coord-3", (Participant("p1", boom, _noop, _noop),)
    )
    outcome3 = TwoPhaseCommit(coord3).execute(
        Transaction("txn-3", _digest("c" * 64)), 4
    )
    assert outcome3.decision == "abort", outcome3
    assert outcome3.votes[0].note == "voter-raised:RuntimeError", outcome3

    print("two-phase-commit OK: unanimous commit, one-no abort, crash-as-no")


if __name__ == "__main__":
    main()
