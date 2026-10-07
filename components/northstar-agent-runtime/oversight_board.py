"""Oversight board: a named panel reviews cases, votes, and decides.

Research basis (second-hand):
- Meta's Oversight Board (2020): an independent panel that reviews content
  moderation decisions, publishes its reasoning, and hears appeals. The
  interface pattern - case intake, member deliberation, published decision,
  one appeal - is borrowed here as bookkeeping.
- AI governance proposals (EU AI Act conformity assessment, US EO 14110
  red-team reporting, Frontier Model Forum's safety evaluations): high-stakes
  model decisions should be reviewable by a body other than the deploying
  team, with the review itself auditable.
- Social choice theory (Black 1948; Condorcet): majority rule over seated
  members is the deterministic aggregation used here; the module does not
  claim any fairness theorem, it only books the tally faithfully.

Distinct layer: :mod:`scalable_oversight` is a *protocol* - a dispatch-time
gate that triages actions and routes them to stronger oversight. This module
is the *board* - a seated panel that accepts cases, casts ballots, reaches
quorum, publishes decisions, and hears appeals. ``review()``/``decide()``/
``appeal()`` name the spec API; ``constitute()``/``vote()`` are the setup
and deliberation primitives the spec API needs to be meaningful.

Design (deterministic single-host ledger):
1. ``constitute(board_id, members, seq)`` -> frozen ``BoardRecord``: seats
   a board with pinned member ids; quorum is a strict majority of seated
   members (floor(n/2)+1). Duplicate board ids refused; ids never recycled.
2. ``review(case_id, board_id, subject_digest, seq)`` -> frozen
   ``CaseRecord``: opens one case for the named board. The subject travels
   as a ``sha256:`` digest pin only - raw case material never enters a
   record. Duplicate case ids refused.
3. ``vote(case_id, member_id, ballot, seq)`` -> frozen ``BallotRecord``
   (minted ``ballot-N`` ids): one ballot per member per round, over the
   pinned vocabulary ``uphold``/``overturn``/``abstain``/``recuse``.
   Unknown case, non-member, duplicate ballot, and bad vocabulary all
   refuse fail-closed. Recusals shrink the seat count for quorum.
4. ``decide(case_id, seq)`` -> frozen ``DecisionRecord``: tallies the
   current round's non-recused ballots. Below quorum refuses with
   ``NoQuorumError``. With quorum: more ``uphold`` than ``overturn`` ->
   ``upheld``; more ``overturn`` than ``uphold`` -> ``overturned`` (both
   terminal for the round); a tie books ``deadlocked`` as *data* and leaves
   the round open for further ballots.
5. ``appeal(case_id, seq, grounds_digest="")`` -> frozen ``AppealRecord``
   (minted ``appeal-N`` ids): booked only after a decisive verdict; it
   seals the current round and opens round N+1 with a fresh ballot box.
   One appeal per case - a second appeal refuses ``AppealExhaustedError``.

Honest scope: a booked decision is ledger truth, never proof of fairness -
quorum arithmetic is deterministic, but it cannot legitimize a captured
board. Recusal is self-declared (GIGO). A digest pin proves the board
looked at *something*, never that the subject was the right artifact.

No wall-clock anywhere. All time is caller-supplied integer sequence
numbers. stdlib-only; raw case material never crosses the audit boundary.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
OVERSIGHT_BOARD_VERSION = "oversight-board.v1"

#: Schema pin carried by records and audit events.
OVERSIGHT_BOARD_SCHEMA = "northstar.oversight-board.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_BOARD_CONSTITUTED = "board-constituted"
KIND_CASE_OPENED = "case-opened"
KIND_BALLOT_CAST = "ballot-cast"
KIND_DECISION_MADE = "decision-made"
KIND_APPEAL_FILED = "appeal-filed"
KIND_REJECTED = "rejected"
_KINDS = (KIND_BOARD_CONSTITUTED, KIND_CASE_OPENED, KIND_BALLOT_CAST,
          KIND_DECISION_MADE, KIND_APPEAL_FILED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw material never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"subject", "grounds", "text", "content", "payload", "raw", "evidence",
     "reason", "value", "members", "note", "brief"})

#: Max id length.
_MAX_ID_LEN = 256

#: Digest pin shape: "sha256:" + 64 lowercase hex.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

#: Pinned ballot vocabulary. Ballots are bookkeeping labels, not positions.
BALLOT_UPHOLD = "uphold"
BALLOT_OVERTURN = "overturn"
BALLOT_ABSTAIN = "abstain"
BALLOT_RECUSE = "recuse"
_BALLOTS = (BALLOT_UPHOLD, BALLOT_OVERTURN, BALLOT_ABSTAIN, BALLOT_RECUSE)

#: Pinned decision verdict vocabulary.
VERDICT_UPHELD = "upheld"
VERDICT_OVERTURNED = "overturned"
VERDICT_DEADLOCKED = "deadlocked"
_VERDICTS = (VERDICT_UPHELD, VERDICT_OVERTURNED, VERDICT_DEADLOCKED)


class OversightBoardError(Exception):
    """Base error for the oversight board ledger (programming errors)."""


class BadIdError(OversightBoardError):
    """Raised when a board/case/member id is malformed."""


class DuplicateBoardError(OversightBoardError):
    """Raised when a board id is constituted twice."""


class UnknownBoardError(OversightBoardError):
    """Raised when a board id names no constituted board."""


class BadMemberError(OversightBoardError):
    """Raised when the member list is malformed."""


class UnknownMemberError(OversightBoardError):
    """Raised when a member id is not seated on the case's board."""


class DuplicateCaseError(OversightBoardError):
    """Raised when a case id is opened twice."""


class UnknownCaseError(OversightBoardError):
    """Raised when a case id names no opened case."""


class BadDigestError(OversightBoardError):
    """Raised when a subject/grounds digest is not a sha256: pin."""


class BadBallotError(OversightBoardError):
    """Raised when a ballot is not in the pinned vocabulary."""


class DuplicateBallotError(OversightBoardError):
    """Raised when a member votes twice in the same round."""


class NoQuorumError(OversightBoardError):
    """Raised when decide() is called with fewer ballots than quorum."""


class AlreadyDecidedError(OversightBoardError):
    """Raised when decide() is called after a decisive verdict."""


class NoDecisionError(OversightBoardError):
    """Raised when appeal() is called before any decisive decision."""


class AppealExhaustedError(OversightBoardError):
    """Raised when a second appeal is filed on the same case."""


class SeqOrderError(OversightBoardError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(OversightBoardError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, label: str) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{label} must be str, got {type(value).__name__}")
    if not value:
        raise BadIdError(f"{label} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{label} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadIdError(f"{label} must not contain whitespace")
    return value


def _check_digest(value: object, label: str, allow_empty: bool = False) -> str:
    """Validate a content pin: ``sha256:<64hex>``."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(
            f"{label} must be a sha256: pin, got {type(value).__name__}")
    if not value and allow_empty:
        return value
    if not _DIGEST_RE.match(value):
        raise BadDigestError(
            f"{label} must match sha256:<64hex>, got {value!r}")
    return value


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": OVERSIGHT_BOARD_SCHEMA,
        "parts": list(parts),
    })


def oversight_board_audit_event(kind: str, detail: Dict[str, object],
                                seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the oversight board."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": OVERSIGHT_BOARD_VERSION,
        "kind": kind,
        "detail": dict(detail),
        "audit_seq": seq,
    }


def _quorum(seated: int) -> int:
    """Strict-majority quorum over the seated member count."""
    return seated // 2 + 1


@dataclass(frozen=True)
class BoardRecord:
    """The seating of one board: pinned members, pinned quorum rule."""
    board_id: str
    member_ids: Tuple[str, ...]
    quorum: int
    seq: int
    schema: str = OVERSIGHT_BOARD_SCHEMA
    digest: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": self.schema,
            "board_id": self.board_id,
            "member_ids": list(self.member_ids),
            "quorum": self.quorum,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == _pin("board", self.board_id,
                                   list(self.member_ids), self.quorum,
                                   self.seq)


@dataclass(frozen=True)
class CaseRecord:
    """One case opened for board review; subject pinned by digest only."""
    case_id: str
    board_id: str
    subject_digest: str
    seq: int
    schema: str = OVERSIGHT_BOARD_SCHEMA
    digest: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": self.schema,
            "case_id": self.case_id,
            "board_id": self.board_id,
            "subject_digest": self.subject_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _pin("case", self.case_id, self.board_id,
                                   self.subject_digest, self.seq)


@dataclass(frozen=True)
class BallotRecord:
    """One member's ballot in one appeal round."""
    ballot_id: str
    case_id: str
    member_id: str
    ballot: str
    round: int
    seq: int
    schema: str = OVERSIGHT_BOARD_SCHEMA
    digest: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": self.schema,
            "ballot_id": self.ballot_id,
            "case_id": self.case_id,
            "member_id": self.member_id,
            "ballot": self.ballot,
            "round": self.round,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _pin("ballot", self.ballot_id, self.case_id,
                                   self.member_id, self.ballot, self.round,
                                   self.seq)


@dataclass(frozen=True)
class DecisionRecord:
    """One round's decision: pinned tally plus verdict."""
    case_id: str
    round: int
    uphold: int
    overturn: int
    abstain: int
    recuse: int
    quorum: int
    verdict: str
    seq: int
    schema: str = OVERSIGHT_BOARD_SCHEMA
    digest: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": self.schema,
            "case_id": self.case_id,
            "round": self.round,
            "uphold": self.uphold,
            "overturn": self.overturn,
            "abstain": self.abstain,
            "recuse": self.recuse,
            "quorum": self.quorum,
            "verdict": self.verdict,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _pin("decision", self.case_id, self.round,
                                   self.uphold, self.overturn, self.abstain,
                                   self.recuse, self.quorum, self.verdict,
                                   self.seq)


@dataclass(frozen=True)
class AppealRecord:
    """One appeal filing: seals the round, opens the next."""
    appeal_id: str
    case_id: str
    new_round: int
    grounds_digest: str
    seq: int
    schema: str = OVERSIGHT_BOARD_SCHEMA
    digest: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": self.schema,
            "appeal_id": self.appeal_id,
            "case_id": self.case_id,
            "new_round": self.new_round,
            "grounds_digest": self.grounds_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _pin("appeal", self.appeal_id, self.case_id,
                                   self.new_round, self.grounds_digest,
                                   self.seq)


@dataclass(frozen=True)
class CaseView:
    """Pure-read snapshot of a case: round, tally, verdict state."""
    case_id: str
    board_id: str
    round: int
    ballots: int
    quorum: int
    decided: bool
    verdict: str
    appealed: bool
    schema: str = OVERSIGHT_BOARD_SCHEMA


class OversightBoard:
    """Deterministic oversight-board ledger: seat, review, vote, decide.

    Frozen records, caller int seqs strictly increasing on mutations
    (failed mutations consume their seq and book ``rejected``; rewinds
    raise bare without consuming), RLock-guarded, fail-closed, stdlib-only
    plus the standard ``canonical_json`` try/except fallback.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._boards: Dict[str, BoardRecord] = {}
        self._cases: Dict[str, CaseRecord] = {}
        self._ballots: Dict[str, BallotRecord] = {}
        # case_id -> round -> set of member ids that have voted
        self._round_voters: Dict[str, Dict[int, set]] = {}
        # case_id -> current round number (1 before any appeal)
        self._rounds: Dict[str, int] = {}
        # case_id -> list of AppealRecord
        self._appeals: Dict[str, list] = {}
        # case_id -> DecisionRecord of the current round (None until decide)
        self._decisions: Dict[str, Optional[DecisionRecord]] = {}
        self._ballot_n = 0
        self._appeal_n = 0
        self._last_seq = -1
        self._audit: Tuple[Dict[str, object], ...] = ()

    # -- seq / audit plumbing ------------------------------------------

    def _claim(self, seq: int) -> None:
        """Claim a seq (strictly increasing); raise bare on rewind."""
        _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be > {self._last_seq}, got {seq}")
            self._last_seq = seq

    def _burn(self, seq: int, case_id: str = "") -> None:
        """Book a rejected row after a failed mutation consumed its seq."""
        detail: Dict[str, object] = {}
        if case_id:
            detail["case_id"] = case_id
        event = oversight_board_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = oversight_board_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    # -- board lifecycle -----------------------------------------------

    def constitute(self, board_id: str, members: Tuple[str, ...],
                   seq: int) -> BoardRecord:
        """Seat one board. Quorum is a strict majority of seated members."""
        self._claim(seq)
        try:
            board_id = _check_id(board_id, "board_id")
            if (isinstance(members, bool) or not isinstance(members, tuple)
                    or not members):
                raise BadMemberError(
                    "members must be a non-empty tuple of member ids")
            member_ids: Tuple[str, ...] = ()
            for m in members:
                mid = _check_id(m, "member_id")
                if mid in member_ids:
                    raise BadMemberError(
                        f"duplicate member id: {mid!r}")
                member_ids = member_ids + (mid,)
            with self._lock:
                if board_id in self._boards:
                    raise DuplicateBoardError(
                        f"board already constituted: {board_id!r}")
                record = BoardRecord(
                    board_id=board_id,
                    member_ids=member_ids,
                    quorum=_quorum(len(member_ids)),
                    seq=seq,
                    digest=_pin("board", board_id, list(member_ids),
                                _quorum(len(member_ids)), seq),
                )
                self._boards[board_id] = record
            self._emit(KIND_BOARD_CONSTITUTED,
                       {"board_id": board_id, "seat_count": len(member_ids)},
                       seq)
            return record
        except OversightBoardError:
            self._burn(seq)
            raise

    def review(self, case_id: str, board_id: str, subject_digest: str,
               seq: int) -> CaseRecord:
        """Open one case for board review; subject pinned by digest only."""
        self._claim(seq)
        try:
            case_id = _check_id(case_id, "case_id")
            board_id = _check_id(board_id, "board_id")
            subject_digest = _check_digest(subject_digest, "subject_digest")
            with self._lock:
                if board_id not in self._boards:
                    raise UnknownBoardError(
                        f"unknown board: {board_id!r}")
                if case_id in self._cases:
                    raise DuplicateCaseError(
                        f"case already opened: {case_id!r}")
                record = CaseRecord(
                    case_id=case_id,
                    board_id=board_id,
                    subject_digest=subject_digest,
                    seq=seq,
                    digest=_pin("case", case_id, board_id, subject_digest,
                                seq),
                )
                self._cases[case_id] = record
                self._rounds[case_id] = 1
                self._round_voters[case_id] = {1: set()}
                self._appeals[case_id] = []
                self._decisions[case_id] = None
            self._emit(KIND_CASE_OPENED,
                       {"case_id": case_id, "board_id": board_id,
                        "round": 1},
                       seq)
            return record
        except OversightBoardError:
            self._burn(seq, case_id if isinstance(case_id, str) else "")
            raise

    # -- deliberation ---------------------------------------------------

    def vote(self, case_id: str, member_id: str, ballot: str,
             seq: int) -> BallotRecord:
        """Cast one member's ballot in the case's current round."""
        self._claim(seq)
        try:
            case_id = _check_id(case_id, "case_id")
            member_id = _check_id(member_id, "member_id")
            if isinstance(ballot, bool) or not isinstance(ballot, str):
                raise BadBallotError(
                    f"ballot must be str, got {type(ballot).__name__}")
            if ballot not in _BALLOTS:
                raise BadBallotError(
                    f"ballot must be one of {list(_BALLOTS)}, got {ballot!r}")
            with self._lock:
                case = self._cases.get(case_id)
                if case is None:
                    raise UnknownCaseError(f"unknown case: {case_id!r}")
                board = self._boards[case.board_id]
                if member_id not in board.member_ids:
                    raise UnknownMemberError(
                        f"{member_id!r} is not seated on board "
                        f"{case.board_id!r}")
                round_no = self._rounds[case_id]
                voters = self._round_voters[case_id][round_no]
                if member_id in voters:
                    raise DuplicateBallotError(
                        f"{member_id!r} already voted in round {round_no}")
                decision = self._decisions[case_id]
                if decision is not None and decision.verdict in (
                        VERDICT_UPHELD, VERDICT_OVERTURNED):
                    raise AlreadyDecidedError(
                        f"case {case_id!r} already decided in round "
                        f"{round_no}")
                self._ballot_n += 1
                ballot_id = f"ballot-{self._ballot_n}"
                record = BallotRecord(
                    ballot_id=ballot_id,
                    case_id=case_id,
                    member_id=member_id,
                    ballot=ballot,
                    round=round_no,
                    seq=seq,
                    digest=_pin("ballot", ballot_id, case_id, member_id,
                                ballot, round_no, seq),
                )
                self._ballots[ballot_id] = record
                voters.add(member_id)
            self._emit(KIND_BALLOT_CAST,
                       {"case_id": case_id, "ballot_id": ballot_id,
                        "round": round_no, "member_id": member_id},
                       seq)
            return record
        except OversightBoardError:
            self._burn(seq, case_id if isinstance(case_id, str) else "")
            raise

    # -- decision -------------------------------------------------------

    def decide(self, case_id: str, seq: int) -> DecisionRecord:
        """Tally the current round. Verdicts: upheld/overturned/deadlocked.

        Below quorum refuses fail-closed. A tie books ``deadlocked`` as data
        and leaves the round open; decisive verdicts are terminal for the
        round (until an appeal opens a new one).
        """
        self._claim(seq)
        try:
            case_id = _check_id(case_id, "case_id")
            with self._lock:
                case = self._cases.get(case_id)
                if case is None:
                    raise UnknownCaseError(f"unknown case: {case_id!r}")
                round_no = self._rounds[case_id]
                decision = self._decisions[case_id]
                if decision is not None and decision.verdict in (
                        VERDICT_UPHELD, VERDICT_OVERTURNED):
                    raise AlreadyDecidedError(
                        f"case {case_id!r} already decided in round "
                        f"{round_no}")
                board = self._boards[case.board_id]
                recuse = 0
                uphold = 0
                overturn = 0
                abstain = 0
                for ballot in self._ballots.values():
                    if ballot.case_id != case_id or ballot.round != round_no:
                        continue
                    if ballot.ballot == BALLOT_RECUSE:
                        recuse += 1
                    elif ballot.ballot == BALLOT_UPHOLD:
                        uphold += 1
                    elif ballot.ballot == BALLOT_OVERTURN:
                        overturn += 1
                    else:
                        abstain += 1
                seated = len(board.member_ids) - recuse
                quorum = _quorum(seated)
                cast = uphold + overturn + abstain
                if cast < quorum:
                    raise NoQuorumError(
                        f"quorum {quorum} not met for case {case_id!r} "
                        f"(ballots cast: {cast})")
                if uphold > overturn:
                    verdict = VERDICT_UPHELD
                elif overturn > uphold:
                    verdict = VERDICT_OVERTURNED
                else:
                    verdict = VERDICT_DEADLOCKED
                record = DecisionRecord(
                    case_id=case_id,
                    round=round_no,
                    uphold=uphold,
                    overturn=overturn,
                    abstain=abstain,
                    recuse=recuse,
                    quorum=quorum,
                    verdict=verdict,
                    seq=seq,
                    digest=_pin("decision", case_id, round_no, uphold,
                                overturn, abstain, recuse, quorum, verdict,
                                seq),
                )
                self._decisions[case_id] = record
            self._emit(KIND_DECISION_MADE,
                       {"case_id": case_id, "round": round_no,
                        "verdict": verdict, "uphold": uphold,
                        "overturn": overturn, "quorum": quorum},
                       seq)
            return record
        except OversightBoardError:
            self._burn(seq, case_id if isinstance(case_id, str) else "")
            raise

    # -- appeal ---------------------------------------------------------

    def appeal(self, case_id: str, seq: int,
               grounds_digest: str = "") -> AppealRecord:
        """File the case's single appeal; seals the round, opens the next."""
        self._claim(seq)
        try:
            case_id = _check_id(case_id, "case_id")
            grounds_digest = _check_digest(grounds_digest, "grounds_digest",
                                           allow_empty=True)
            with self._lock:
                case = self._cases.get(case_id)
                if case is None:
                    raise UnknownCaseError(f"unknown case: {case_id!r}")
                if self._appeals[case_id]:
                    raise AppealExhaustedError(
                        f"appeal already filed for case {case_id!r}")
                decision = self._decisions[case_id]
                if decision is None or decision.verdict not in (
                        VERDICT_UPHELD, VERDICT_OVERTURNED):
                    raise NoDecisionError(
                        f"case {case_id!r} has no decisive verdict to "
                        f"appeal")
                new_round = self._rounds[case_id] + 1
                self._appeal_n += 1
                appeal_id = f"appeal-{self._appeal_n}"
                record = AppealRecord(
                    appeal_id=appeal_id,
                    case_id=case_id,
                    new_round=new_round,
                    grounds_digest=grounds_digest,
                    seq=seq,
                    digest=_pin("appeal", appeal_id, case_id, new_round,
                                grounds_digest, seq),
                )
                self._appeals[case_id].append(record)
                self._rounds[case_id] = new_round
                self._round_voters[case_id][new_round] = set()
                self._decisions[case_id] = None
            self._emit(KIND_APPEAL_FILED,
                       {"case_id": case_id, "appeal_id": appeal_id,
                        "new_round": new_round},
                       seq)
            return record
        except OversightBoardError:
            self._burn(seq, case_id if isinstance(case_id, str) else "")
            raise

    # -- pure-read views (never consume seq, never write audit rows) -----

    def _view_seq(self, seq: object) -> None:
        """Validate a view's seq shape only; consumes nothing."""
        _check_seq(seq)

    def case(self, case_id: str, seq: int) -> CaseView:
        """Snapshot of a case: round, tally state, verdict, appeal flag."""
        _check_id(case_id, "case_id")
        self._view_seq(seq)
        with self._lock:
            case = self._cases.get(case_id)
            if case is None:
                raise UnknownCaseError(f"unknown case: {case_id!r}")
            board = self._boards[case.board_id]
            round_no = self._rounds[case_id]
            recuse = 0
            cast = 0
            for ballot in self._ballots.values():
                if ballot.case_id != case_id or ballot.round != round_no:
                    continue
                if ballot.ballot == BALLOT_RECUSE:
                    recuse += 1
                else:
                    cast += 1
            decision = self._decisions[case_id]
            return CaseView(
                case_id=case_id,
                board_id=case.board_id,
                round=round_no,
                ballots=cast + recuse,
                quorum=_quorum(len(board.member_ids) - recuse),
                decided=decision is not None
                and decision.verdict in (VERDICT_UPHELD, VERDICT_OVERTURNED),
                verdict=decision.verdict if decision is not None else "",
                appealed=bool(self._appeals[case_id]),
            )

    def board(self, board_id: str, seq: int) -> BoardRecord:
        """Fetch a board's seating record."""
        _check_id(board_id, "board_id")
        self._view_seq(seq)
        with self._lock:
            record = self._boards.get(board_id)
            if record is None:
                raise UnknownBoardError(f"unknown board: {board_id!r}")
            return record

    def decision(self, case_id: str, seq: int) -> DecisionRecord:
        """Fetch the current round's decision (fail-closed if none)."""
        _check_id(case_id, "case_id")
        self._view_seq(seq)
        with self._lock:
            if case_id not in self._cases:
                raise UnknownCaseError(f"unknown case: {case_id!r}")
            record = self._decisions[case_id]
            if record is None:
                raise NoDecisionError(
                    f"no decision booked for case {case_id!r}")
            return record

    def ballots_for(self, case_id: str, seq: int) -> Tuple[BallotRecord, ...]:
        """All ballots for the case's current round, ballot-id order."""
        _check_id(case_id, "case_id")
        self._view_seq(seq)
        with self._lock:
            if case_id not in self._cases:
                raise UnknownCaseError(f"unknown case: {case_id!r}")
            round_no = self._rounds[case_id]
            rows = [b for b in self._ballots.values()
                    if b.case_id == case_id and b.round == round_no]
            return tuple(sorted(rows, key=lambda b: b.ballot_id))

    def stats(self, seq: int) -> Dict[str, object]:
        """Ledger counts (pure read)."""
        self._view_seq(seq)
        with self._lock:
            return {
                "schema": OVERSIGHT_BOARD_SCHEMA,
                "boards": len(self._boards),
                "cases": len(self._cases),
                "ballots": len(self._ballots),
                "appeals": self._appeal_n,
                "last_seq": self._last_seq,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, object], ...]:
        """The audit rows booked so far (pure read)."""
        self._view_seq(seq)
        with self._lock:
            return self._audit


def main() -> None:
    """Self-check: seat a board, review, vote, decide, appeal."""
    pin = lambda tag: _pin("main", tag)
    board = OversightBoard()
    board.constitute("board-1", ("m1", "m2", "m3"), 1)
    board.review("case-1", "board-1", pin("subject-a"), 2)
    board.vote("case-1", "m1", "uphold", 3)
    board.vote("case-1", "m2", "overturn", 4)
    board.vote("case-1", "m3", "uphold", 5)
    decision = board.decide("case-1", 6)
    assert decision.verdict == "upheld", decision
    assert decision.verify()
    appeal = board.appeal("case-1", 7, pin("grounds"))
    assert appeal.new_round == 2 and appeal.verify()
    board.vote("case-1", "m1", "overturn", 8)
    board.vote("case-1", "m2", "overturn", 9)
    board.vote("case-1", "m3", "abstain", 10)
    decision2 = board.decide("case-1", 11)
    assert decision2.verdict == "overturned", decision2
    assert decision2.verify()
    view = board.case("case-1", 12)
    assert view.appealed and view.decided and view.verdict == "overturned"
    print("oversight-board OK: constitute, review, vote, decide, appeal, "
          "quorum, pins, audit")


if __name__ == "__main__":
    main()
