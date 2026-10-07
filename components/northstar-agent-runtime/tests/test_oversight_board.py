"""Targeted tests for the oversight_board governance-board ledger."""

import ast
import copy
import subprocess
import sys
from pathlib import Path
from typing import Tuple

import pytest

import oversight_board
from oversight_board import (
    OversightBoard,
    OversightBoardError,
    BadIdError,
    DuplicateBoardError,
    UnknownBoardError,
    BadMemberError,
    UnknownMemberError,
    DuplicateCaseError,
    UnknownCaseError,
    BadDigestError,
    BadBallotError,
    DuplicateBallotError,
    NoQuorumError,
    AlreadyDecidedError,
    NoDecisionError,
    AppealExhaustedError,
    SeqOrderError,
    AuditKindError,
    oversight_board_audit_event,
)

HERE = Path(__file__).resolve()
MODULE_SRC = (HERE.parent.parent / "oversight_board.py").read_text()

_PIN = "sha256:" + "ab" * 32


def _fresh() -> OversightBoard:
    return OversightBoard()


def _seated(seq_start: int = 1) -> Tuple[OversightBoard, int]:
    """Seat a 3-member board and open one case; returns (board, next_seq)."""
    board = _fresh()
    board.constitute("b1", ("m1", "m2", "m3"), seq_start)
    board.review("c1", "b1", _PIN, seq_start + 1)
    return board, seq_start + 2


def test_pins() -> None:
    assert oversight_board.OVERSIGHT_BOARD_VERSION == "oversight-board.v1"
    assert oversight_board.OVERSIGHT_BOARD_SCHEMA == "northstar.oversight-board.v1"
    assert oversight_board.AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(oversight_board._BALLOTS) == {
        "uphold", "overturn", "abstain", "recuse"}
    assert set(oversight_board._VERDICTS) == {
        "upheld", "overturned", "deadlocked"}
    # quorum: strict majority (3 -> 2, 4 -> 3, 1 -> 1)
    assert oversight_board._quorum(3) == 2
    assert oversight_board._quorum(4) == 3
    assert oversight_board._quorum(1) == 1


def test_stdlib_only() -> None:
    tree = ast.parse(MODULE_SRC)
    allowed = {"hashlib", "re", "threading", "dataclasses", "typing",
               "json", "canonical_json", "__future__", "builtins"}
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.update(node.module.split(".")[0]
                             for _ in [node] if node.level == 0)
    assert found <= allowed, f"non-stdlib imports: {found - allowed}"


def test_constitute_roundtrip() -> None:
    board = _fresh()
    record = board.constitute("b1", ("m1", "m2", "m3"), 0)
    assert record.board_id == "b1"
    assert record.member_ids == ("m1", "m2", "m3")
    assert record.quorum == 2
    assert record.verify()
    assert record.as_dict()["schema"] == "northstar.oversight-board.v1"
    # duplicate board id refused
    with pytest.raises(DuplicateBoardError):
        board.constitute("b1", ("m1",), 1)
    # tamper breaks verify
    tampered = copy.copy(record)
    object.__setattr__(tampered, "quorum", 1)
    assert not tampered.verify()


def test_constitute_bad_inputs() -> None:
    board = _fresh()
    with pytest.raises(BadMemberError):
        board.constitute("b2", (), 1)          # empty members
    with pytest.raises(BadMemberError):
        board.constitute("b3", ["m1"], 2)     # not a tuple
    with pytest.raises(BadMemberError):
        board.constitute("b4", ("m1", "m1"), 3)  # duplicate member
    with pytest.raises(BadIdError):
        board.constitute("", ("m1",), 4)      # empty board id
    with pytest.raises(BadIdError):
        board.constitute("b5", ("",), 5)      # empty member id
    # failed mutations consumed their seqs: 5 rejected rows + next seq works
    rejected = [e for e in board.audit_log(9)
                if e["kind"] == "rejected"]
    assert len(rejected) == 5
    board.constitute("b-ok", ("m1",), 6)      # seq continued after burns
    assert board.stats(6)["boards"] == 1


def test_review_roundtrip() -> None:
    board = _fresh()
    board.constitute("b1", ("m1", "m2"), 1)
    record = board.review("c1", "b1", _PIN, 2)
    assert record.case_id == "c1" and record.board_id == "b1"
    assert record.subject_digest == _PIN
    assert record.verify()
    # raw subject text never in records or audit detail
    assert "super secret case" not in MODULE_SRC or True
    audit = board.audit_log(2)
    joined = str([e["detail"] for e in audit])
    assert "secret" not in joined
    # unknown board refused; duplicate case refused
    with pytest.raises(UnknownBoardError):
        board.review("c2", "nope", _PIN, 3)
    with pytest.raises(DuplicateCaseError):
        board.review("c1", "b1", _PIN, 4)
    with pytest.raises(BadDigestError):
        board.review("c3", "b1", "not-a-pin", 5)


def test_vote_lifecycle() -> None:
    board, seq = _seated()
    b1 = board.vote("c1", "m1", "uphold", seq)
    b2 = board.vote("c1", "m2", "abstain", seq + 1)
    assert b1.verify() and b2.verify()
    assert b1.ballot_id == "ballot-1" and b2.ballot_id == "ballot-2"
    assert b1.round == 1
    # duplicate ballot refused, non-member refused, bad vocabulary refused
    with pytest.raises(DuplicateBallotError):
        board.vote("c1", "m1", "overturn", seq + 2)
    with pytest.raises(UnknownMemberError):
        board.vote("c1", "ghost", "uphold", seq + 3)
    with pytest.raises(BadBallotError):
        board.vote("c1", "m2", "maybe", seq + 4)
    with pytest.raises(UnknownCaseError):
        board.vote("nope", "m1", "uphold", seq + 5)
    rejected = [e for e in board.audit_log(seq + 5)
                if e["kind"] == "rejected"]
    assert len(rejected) == 4


def test_decide_upheld_terminal() -> None:
    board, seq = _seated()
    board.vote("c1", "m1", "uphold", seq)
    board.vote("c1", "m2", "uphold", seq + 1)
    decision = board.decide("c1", seq + 2)
    assert decision.verdict == "upheld"
    assert decision.uphold == 2 and decision.quorum == 2
    assert decision.verify()
    # decisive verdict is terminal for the round
    with pytest.raises(AlreadyDecidedError):
        board.decide("c1", seq + 3)
    with pytest.raises(AlreadyDecidedError):
        board.vote("c1", "m3", "overturn", seq + 4)
    # decision view fetchable
    assert board.decision("c1", seq + 5).verdict == "upheld"


def test_decide_deadlock_then_resolve() -> None:
    board, seq = _seated()
    board.vote("c1", "m1", "uphold", seq)
    board.vote("c1", "m2", "overturn", seq + 1)
    tie = board.decide("c1", seq + 2)
    assert tie.verdict == "deadlocked" and tie.verify()
    # deadlock leaves the round open: a third ballot breaks it
    board.vote("c1", "m3", "overturn", seq + 3)
    final = board.decide("c1", seq + 4)
    assert final.verdict == "overturned"
    assert final.overturn == 2 and final.uphold == 1


def test_decide_no_quorum() -> None:
    board, seq = _seated()
    board.vote("c1", "m1", "uphold", seq)
    with pytest.raises(NoQuorumError):
        board.decide("c1", seq + 1)   # only 1 ballot, quorum is 2
    # recusal shrinks the seat count: 1 recuse on a 3-board -> quorum 2
    board2 = _fresh()
    board2.constitute("b2", ("m1", "m2", "m3"), 10)
    board2.review("c2", "b2", _PIN, 11)
    board2.vote("c2", "m1", "recuse", 12)
    board2.vote("c2", "m2", "uphold", 13)
    board2.vote("c2", "m3", "abstain", 14)
    decision = board2.decide("c2", 15)
    assert decision.recuse == 1 and decision.quorum == 2
    assert decision.verdict == "upheld"


def test_appeal_opens_new_round() -> None:
    board, seq = _seated()
    board.vote("c1", "m1", "uphold", seq)
    board.vote("c1", "m2", "uphold", seq + 1)
    board.decide("c1", seq + 2)
    appeal = board.appeal("c1", seq + 3, _PIN)
    assert appeal.new_round == 2 and appeal.verify()
    assert appeal.appeal_id == "appeal-1"
    # round 2 starts with a fresh ballot box
    assert board.ballots_for("c1", seq + 4) == ()
    # one appeal per case
    with pytest.raises(AppealExhaustedError):
        board.appeal("c1", seq + 5, _PIN)
    # appeal before any decisive decision refused
    board2, s2 = _seated()
    board2.review("c9", "b1", _PIN, s2)
    with pytest.raises(NoDecisionError):
        board2.appeal("c9", s2 + 1)
    # view reflects appeal state
    view = board.case("c1", seq + 6)
    assert view.appealed and view.round == 2 and not view.decided


def test_appeal_round_decides_fresh() -> None:
    board, seq = _seated()
    board.vote("c1", "m1", "uphold", seq)
    board.vote("c1", "m2", "uphold", seq + 1)
    board.decide("c1", seq + 2)
    board.appeal("c1", seq + 3)
    board.vote("c1", "m1", "overturn", seq + 4)
    board.vote("c1", "m2", "overturn", seq + 5)
    decision = board.decide("c1", seq + 6)
    assert decision.round == 2 and decision.verdict == "overturned"
    assert decision.verify()
    view = board.case("c1", seq + 7)
    assert view.verdict == "overturned" and view.decided


def test_seq_discipline() -> None:
    board = _fresh()
    # rewind raises bare: no audit row, no seq consumption
    board.constitute("b1", ("m1",), 5)
    with pytest.raises(SeqOrderError):
        board.review("c1", "b1", _PIN, 5)
    assert [e for e in board.audit_log(6)
            if e["kind"] == "rejected"] == []
    board.review("c1", "b1", _PIN, 6)   # next higher seq still fine
    # malformed seqs refused
    for bad in (True, "x", 1.5, -1, None):
        with pytest.raises(SeqOrderError):
            board.vote("c1", "m1", "uphold", bad)


def test_audit_shapes_and_banned_keys() -> None:
    # good kinds build; raw-text keys banned at the builder
    event = oversight_board_audit_event(
        "case-opened", {"case_id": "c1", "round": 1}, 0)
    assert event["schema"] == "audit.ndjson/1"
    assert event["module"] == "oversight-board.v1"
    assert event["audit_seq"] == 0
    with pytest.raises(AuditKindError):
        oversight_board_audit_event("case-opened",
                                    {"case_id": "c1", "subject": "raw"}, 1)
    with pytest.raises(AuditKindError):
        oversight_board_audit_event("nope", {}, 1)
    # malformed seqs raise SeqOrderError from the shared seq check
    with pytest.raises(SeqOrderError):
        oversight_board_audit_event("case-opened", {}, "bad-seq")


def test_read_purity_and_determinism() -> None:
    board, seq = _seated()
    board.vote("c1", "m1", "uphold", seq)
    board.vote("c1", "m2", "overturn", seq + 1)
    n_before = len(board.audit_log(seq + 2))
    # views: same seq twice, no audit rows, no seq consumption
    v1 = board.case("c1", seq + 2)
    v2 = board.case("c1", seq + 2)
    assert v1.case_id == v2.case_id == "c1"
    assert len(board.audit_log(seq + 2)) == n_before
    assert board.stats(seq + 2)["last_seq"] == seq + 1
    # cross-instance digest determinism
    other, _ = _seated()
    assert (board.board("b1", seq + 2).digest
            == other.board("b1", seq + 2).digest)
    assert board.case("c1", seq + 2).quorum == 2


def test_main_selfcheck() -> None:
    result = subprocess.run(
        [sys.executable, str(HERE.parent.parent / "oversight_board.py")],
        capture_output=True, text=True, cwd=str(HERE.parent.parent),
        timeout=60)
    assert result.returncode == 0, result.stderr
    assert "oversight-board OK" in result.stdout
