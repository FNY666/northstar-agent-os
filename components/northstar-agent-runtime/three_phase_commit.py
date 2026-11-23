"""Three-phase commit: non-blocking distributed commit protocol.

Research motivation: two-phase commit (2PC) has a fatal liveness flaw -- a
participant that voted YES and is waiting for the coordinator's decision
("uncertain" state) *blocks* if the coordinator dies: it cannot unilaterally
abort, because another participant may already have committed. 3PC (Skeen &
Stonebraker) inserts a **pre-commit** phase so that no participant is ever
uncertain about the outcome when the coordinator fails:

- ``can-commit``: coordinator asks every participant for a YES/NO vote. A
  single NO aborts the transaction immediately.
- ``pre-commit``: only after *all* YES votes, the coordinator broadcasts
  preCommit. A participant that receives preCommit **knows** the outcome will
  be commit -- every participant voted YES, so none could have aborted.
- ``commit``: coordinator broadcasts doCommit; participants commit and ack.

Non-blocking recovery (the termination protocol): on coordinator failure
(or timeout), survivors do *not* unilaterally abort -- they run
``termination_decision()`` over the reachable states:

- any participant COMMITTED -> commit (someone saw the final decision);
- any participant PRE_COMMITTED -> commit (preCommit implies all YES votes,
  and no one could have aborted without seeing a decision);
- all participants CAN_COMMITTED (voted YES, no preCommit seen) -> commit
  by re-running from preCommit over the surviving set (no decision was
  observed, so choosing to proceed is safe);
- otherwise (any INIT/ABORTED) -> abort.

This module is the coordinator-side state machine plus the termination
rule. It is deterministic and network-free: the host supplies votes, acks,
and (on recovery) the observed participant states.

Honest scope:

- The timeout rule is *termination protocol*, never unilateral abort. A
  state machine that lets participants abort on timeout while others may
  have received preCommit is the inconsistency this protocol exists to
  prevent. Hosts must wire timeouts to ``termination_decision()``, not to
  a local abort.
- ``termination_decision()`` is a *rule over reported states*, not a
  protocol run: it assumes the survivors can see each other's states
  (election + gossip are the host's job). A participant excluded by a
  partition follows the same rule when it reconnects.
- "commit" from the coordinator means "the coordinator decided commit and
  recorded it", never "every participant durably applied it" -- the acks
  are the host's evidence channel.
- Outcome is terminal: once COMMITTED or ABORTED, no further phase
  transition is accepted.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Sequence

#: Version pin for this module's record shape.
THREE_PHASE_COMMIT_VERSION = "three-phase-commit.v1"

#: Schema pin carried by records and audit events.
THREE_PHASE_COMMIT_SCHEMA = "northstar.three-phase-commit.v1"

#: Audit event kinds.
EVENT_TXN_STARTED = "3pc-txn-started"
EVENT_VOTE = "3pc-vote-recorded"
EVENT_PHASE = "3pc-phase-advanced"
EVENT_TXN_COMMITTED = "3pc-txn-committed"
EVENT_TXN_ABORTED = "3pc-txn-aborted"
EVENT_RECOVERY = "3pc-recovery-decision"

_EVENT_TYPES = frozenset(
    {
        EVENT_TXN_STARTED,
        EVENT_VOTE,
        EVENT_PHASE,
        EVENT_TXN_COMMITTED,
        EVENT_TXN_ABORTED,
        EVENT_RECOVERY,
    }
)


class ThreePhaseCommitError(Exception):
    """Base error for three-phase-commit state-machine violations."""


class Vote(Enum):
    """Participant vote in the can-commit phase."""

    YES = "yes"
    NO = "no"


class ParticipantState(Enum):
    """Participant's view of the protocol."""

    INIT = "init"  # never voted
    CAN_COMMITTED = "can-committed"  # voted YES, waiting for preCommit
    PRE_COMMITTED = "pre-committed"  # received preCommit, outcome will be commit
    COMMITTED = "committed"  # applied commit
    ABORTED = "aborted"  # aborted (told to, never unilaterally)


class Phase(Enum):
    """Coordinator's phase."""

    IDLE = "idle"
    CAN_COMMIT = "can-commit"
    PRE_COMMIT = "pre-commit"
    COMMIT = "commit"
    DONE_COMMITTED = "done-committed"
    DONE_ABORTED = "done-aborted"


class TransactionOutcome(Enum):
    """Final transaction outcome."""

    COMMIT = "commit"
    ABORT = "abort"


def _check_txn_id(value: object, name: str = "txn_id") -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    txn_id = value.strip()
    if not txn_id:
        raise ValueError(f"{name} must be non-empty")
    return txn_id


def _check_participant_id(value: object, name: str = "participant_id") -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    pid = value.strip()
    if not pid:
        raise ValueError(f"{name} must be non-empty")
    return pid


def _check_seq(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


def _canonical_body(obj: object) -> bytes:
    """Deterministic JSON encoding for digest pins (stdlib fallback)."""
    try:
        from canonical_json import dumps as _jdumps  # type: ignore

        return _jdumps(obj).encode("utf-8")
    except Exception:
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _pin(obj: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_body(obj)).hexdigest()


@dataclass(frozen=True)
class TransactionRecord:
    """Frozen record of a 3PC transaction and its terminal outcome."""

    txn_id: str
    participants: tuple
    outcome: str
    phase_reached: str
    record_digest: str

    def as_dict(self) -> dict:
        return {
            "schema": THREE_PHASE_COMMIT_SCHEMA,
            "version": THREE_PHASE_COMMIT_VERSION,
            "txn_id": self.txn_id,
            "participants": list(self.participants),
            "outcome": self.outcome,
            "phase_reached": self.phase_reached,
            "record_digest": self.record_digest,
        }


@dataclass(frozen=True)
class ThreePhaseAuditEvent:
    """Frozen audit.ndjson/1-shaped event for the coordinator."""

    kind: str
    txn_id: str
    seq: int
    detail: str

    def as_dict(self) -> dict:
        return {
            "schema": "audit.ndjson/1",
            "module": THREE_PHASE_COMMIT_SCHEMA,
            "version": THREE_PHASE_COMMIT_VERSION,
            "kind": self.kind,
            "txn_id": self.txn_id,
            "seq": self.seq,
            "detail": self.detail,
        }


def three_phase_audit_event(kind: str, txn_id: str, detail: str, seq: int) -> dict:
    """Build an audit.ndjson/1-shaped event dict."""
    if kind not in _EVENT_TYPES:
        raise ValueError(f"unknown event kind: {kind!r}")
    _check_txn_id(txn_id)
    _check_seq(seq, "seq")
    if not isinstance(detail, str):
        raise TypeError("detail must be a string")
    return ThreePhaseAuditEvent(
        kind=kind, txn_id=txn_id, seq=_check_seq(seq, "seq"), detail=detail
    ).as_dict()


def termination_decision(
    states: Mapping[str, ParticipantState],
) -> TransactionOutcome:
    """Non-blocking termination rule over survivor states.

    Run when the coordinator is suspected dead. States are the
    *reachable* participants' views; unknown participants are excluded,
    never assumed. The rule is total and deterministic:

    - any COMMITTED -> COMMIT (the decision was observed);
    - any PRE_COMMITTED -> COMMIT (preCommit was broadcast only after all
      YES votes, so abort was never legitimate);
    - all CAN_COMMITTED -> COMMIT (re-run from preCommit over the surviving
      set; no decision was observed, so proceeding is safe);
    - otherwise -> ABORT.
    """
    if not isinstance(states, Mapping):
        raise TypeError("states must be a mapping")
    if not states:
        raise ValueError("states must be non-empty")
    for pid, state in states.items():
        _check_participant_id(pid)
        if not isinstance(state, ParticipantState):
            raise TypeError(f"state for {pid!r} must be a ParticipantState")

    values = list(states.values())
    if any(s is ParticipantState.COMMITTED for s in values):
        return TransactionOutcome.COMMIT
    if any(s is ParticipantState.PRE_COMMITTED for s in values):
        return TransactionOutcome.COMMIT
    if all(s is ParticipantState.CAN_COMMITTED for s in values):
        return TransactionOutcome.COMMIT
    return TransactionOutcome.ABORT


class ThreePhaseCommit:
    """Coordinator-side 3PC state machine for one transaction.

    Phase flow: ``begin()`` -> ``record_vote()`` * n -> ``pre_commit()`` ->
    ``record_pre_commit_ack()`` * n -> ``commit()`` ->
    ``record_commit_ack()`` * n. Any NO vote (or ``abort()``) moves to
    ABORTED terminally. Timeouts must call ``termination_decision()``,
    never ``abort()`` -- see module docstring.
    """

    def __init__(self, txn_id: str, participant_ids: Sequence[str]) -> None:
        self._txn_id = _check_txn_id(txn_id)
        if not isinstance(participant_ids, (list, tuple)):
            raise TypeError("participant_ids must be a list or tuple")
        if not participant_ids:
            raise ValueError("participant_ids must be non-empty")
        pids = tuple(_check_participant_id(p) for p in participant_ids)
        if len(set(pids)) != len(pids):
            raise ValueError("participant_ids must be distinct")
        self._participants = pids
        self._phase = Phase.IDLE
        self._votes: dict[str, Vote] = {}
        self._pre_commit_acks: set[str] = set()
        self._commit_acks: set[str] = set()
        self._outcome: TransactionOutcome | None = None
        self._abort_reason: str | None = None
        self._events: list[ThreePhaseAuditEvent] = []

    # -- views -----------------------------------------------------------
    @property
    def txn_id(self) -> str:
        return self._txn_id

    @property
    def participants(self) -> tuple:
        return self._participants

    @property
    def phase(self) -> Phase:
        return self._phase

    @property
    def outcome(self) -> TransactionOutcome | None:
        return self._outcome

    @property
    def abort_reason(self) -> str | None:
        return self._abort_reason

    def state_of(self, participant_id: str) -> ParticipantState:
        """Participant's view derived from coordinator progress."""
        pid = _check_participant_id(participant_id)
        if pid not in self._participants:
            raise KeyError(f"unknown participant: {pid!r}")
        if self._phase is Phase.IDLE:
            return ParticipantState.INIT
        if self._phase is Phase.DONE_ABORTED:
            return ParticipantState.ABORTED
        if self._phase is Phase.DONE_COMMITTED:
            return ParticipantState.COMMITTED
        # In-flight: derive from recorded progress.
        if pid in self._commit_acks:
            return ParticipantState.COMMITTED
        if self._phase in (Phase.PRE_COMMIT, Phase.COMMIT):
            return ParticipantState.PRE_COMMITTED
        if pid in self._votes:
            return ParticipantState.CAN_COMMITTED
        return ParticipantState.INIT

    def events(self) -> tuple:
        return tuple(self._events)

    # -- phases ----------------------------------------------------------
    def _require_phase(self, expected: Phase, action: str) -> None:
        if self._phase is not expected:
            raise ThreePhaseCommitError(
                f"cannot {action} in phase {self._phase.value} "
                f"(expected {expected.value})"
            )

    def _log(self, kind: str, seq: int, detail: str) -> None:
        self._events.append(
            ThreePhaseAuditEvent(
                kind=kind, txn_id=self._txn_id, seq=_check_seq(seq, "seq"),
                detail=detail,
            )
        )

    def begin(self, seq: int) -> None:
        """Start the can-commit phase (broadcast canCommit)."""
        self._require_phase(Phase.IDLE, "begin")
        self._phase = Phase.CAN_COMMIT
        self._log(EVENT_TXN_STARTED, seq, f"can-commit to {len(self._participants)}")

    def record_vote(self, participant_id: str, vote: Vote, seq: int) -> None:
        """Record one participant's YES/NO vote. A NO aborts immediately."""
        self._require_phase(Phase.CAN_COMMIT, "record a vote")
        pid = _check_participant_id(participant_id)
        if pid not in self._participants:
            raise KeyError(f"unknown participant: {pid!r}")
        if not isinstance(vote, Vote):
            raise TypeError("vote must be a Vote")
        if pid in self._votes:
            raise ThreePhaseCommitError(f"duplicate vote from {pid!r}")
        self._votes[pid] = vote
        self._log(EVENT_VOTE, seq, f"{pid} voted {vote.value}")
        if vote is Vote.NO:
            self._abort(f"participant {pid} voted NO", seq)

    def pre_commit(self, seq: int) -> None:
        """Advance to pre-commit after all YES votes."""
        self._require_phase(Phase.CAN_COMMIT, "advance to pre-commit")
        if len(self._votes) != len(self._participants):
            raise ThreePhaseCommitError(
                f"missing votes: {len(self._votes)}/{len(self._participants)}"
            )
        if any(v is Vote.NO for v in self._votes.values()):
            raise ThreePhaseCommitError("cannot pre-commit with a NO vote")
        self._phase = Phase.PRE_COMMIT
        self._log(EVENT_PHASE, seq, "pre-commit broadcast")

    def record_pre_commit_ack(self, participant_id: str, seq: int) -> None:
        """Record one participant's preCommit ack."""
        self._require_phase(Phase.PRE_COMMIT, "record a pre-commit ack")
        pid = _check_participant_id(participant_id)
        if pid not in self._participants:
            raise KeyError(f"unknown participant: {pid!r}")
        if pid in self._pre_commit_acks:
            raise ThreePhaseCommitError(f"duplicate pre-commit ack from {pid!r}")
        self._pre_commit_acks.add(pid)
        self._log(EVENT_VOTE, seq, f"{pid} acked pre-commit")

    def commit(self, seq: int) -> None:
        """Broadcast doCommit after all pre-commit acks."""
        self._require_phase(Phase.PRE_COMMIT, "commit")
        if len(self._pre_commit_acks) != len(self._participants):
            raise ThreePhaseCommitError(
                f"missing pre-commit acks: {len(self._pre_commit_acks)}/"
                f"{len(self._participants)}"
            )
        self._phase = Phase.COMMIT
        self._log(EVENT_PHASE, seq, "commit broadcast")

    def record_commit_ack(self, participant_id: str, seq: int) -> None:
        """Record one participant's commit ack; last ack finalizes COMMIT."""
        self._require_phase(Phase.COMMIT, "record a commit ack")
        pid = _check_participant_id(participant_id)
        if pid not in self._participants:
            raise KeyError(f"unknown participant: {pid!r}")
        if pid in self._commit_acks:
            raise ThreePhaseCommitError(f"duplicate commit ack from {pid!r}")
        self._commit_acks.add(pid)
        if len(self._commit_acks) == len(self._participants):
            self._phase = Phase.DONE_COMMITTED
            self._outcome = TransactionOutcome.COMMIT
            self._log(EVENT_TXN_COMMITTED, seq, "all commit acks received")

    def abort(self, reason: str, seq: int) -> None:
        """Operator-driven abort before the transaction is decided."""
        if self._phase in (Phase.DONE_COMMITTED, Phase.DONE_ABORTED):
            raise ThreePhaseCommitError("transaction already decided")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("reason must be a non-empty string")
        self._abort(reason.strip(), seq)

    def _abort(self, reason: str, seq: int) -> None:
        self._phase = Phase.DONE_ABORTED
        self._outcome = TransactionOutcome.ABORT
        self._abort_reason = reason
        self._log(EVENT_TXN_ABORTED, seq, reason)

    def finalize_record(self) -> TransactionRecord:
        """Frozen record of the terminal outcome."""
        if self._outcome is None:
            raise ThreePhaseCommitError("transaction not decided yet")
        body = {
            "txn_id": self._txn_id,
            "participants": list(self._participants),
            "outcome": self._outcome.value,
            "phase_reached": self._phase.value,
        }
        return TransactionRecord(
            txn_id=self._txn_id,
            participants=self._participants,
            outcome=self._outcome.value,
            phase_reached=self._phase.value,
            record_digest=_pin(body),
        )


def main() -> None:
    """Self-check: happy path commits, NO vote aborts, recovery commits."""
    t = ThreePhaseCommit("txn-1", ["a", "b", "c"])
    t.begin(1)
    for p in ("a", "b", "c"):
        t.record_vote(p, Vote.YES, 2)
    t.pre_commit(3)
    for p in ("a", "b", "c"):
        t.record_pre_commit_ack(p, 4)
    t.commit(5)
    for p in ("a", "b", "c"):
        t.record_commit_ack(p, 6)
    assert t.outcome is TransactionOutcome.COMMIT

    t2 = ThreePhaseCommit("txn-2", ["a", "b"])
    t2.begin(1)
    t2.record_vote("a", Vote.YES, 2)
    t2.record_vote("b", Vote.NO, 3)
    assert t2.outcome is TransactionOutcome.ABORT

    assert (
        termination_decision({"a": ParticipantState.PRE_COMMITTED})
        is TransactionOutcome.COMMIT
    )
    assert (
        termination_decision({"a": ParticipantState.INIT})
        is TransactionOutcome.ABORT
    )
    print("three-phase-commit OK: commit, abort, recovery-decision")


if __name__ == "__main__":
    main()
