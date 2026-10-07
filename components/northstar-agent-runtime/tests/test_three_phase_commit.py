"""Tests for three_phase_commit."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from three_phase_commit import (
    EVENT_RECOVERY,
    EVENT_TXN_ABORTED,
    EVENT_TXN_COMMITTED,
    EVENT_TXN_STARTED,
    EVENT_VOTE,
    EVENT_PHASE,
    THREE_PHASE_COMMIT_SCHEMA,
    THREE_PHASE_COMMIT_VERSION,
    ParticipantState,
    Phase,
    ThreePhaseCommit,
    ThreePhaseCommitError,
    TransactionOutcome,
    Vote,
    termination_decision,
    three_phase_audit_event,
)


def _happy_path(txn_id="t1", participants=("a", "b", "c")):
    t = ThreePhaseCommit(txn_id, list(participants))
    t.begin(1)
    for p in participants:
        t.record_vote(p, Vote.YES, 2)
    t.pre_commit(3)
    for p in participants:
        t.record_pre_commit_ack(p, 4)
    t.commit(5)
    for p in participants:
        t.record_commit_ack(p, 6)
    return t


class TestVersionAndSchema(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(THREE_PHASE_COMMIT_VERSION, "three-phase-commit.v1")

    def test_schema_pin(self):
        self.assertEqual(
            THREE_PHASE_COMMIT_SCHEMA, "northstar.three-phase-commit.v1"
        )


class TestConstructor(unittest.TestCase):
    def test_empty_txn_id(self):
        with self.assertRaises(ValueError):
            ThreePhaseCommit("  ", ["a"])

    def test_non_str_txn_id(self):
        with self.assertRaises(TypeError):
            ThreePhaseCommit(123, ["a"])

    def test_empty_participants(self):
        with self.assertRaises(ValueError):
            ThreePhaseCommit("t", [])

    def test_duplicate_participants(self):
        with self.assertRaises(ValueError):
            ThreePhaseCommit("t", ["a", "a"])

    def test_non_list_participants(self):
        with self.assertRaises(TypeError):
            ThreePhaseCommit("t", "abc")

    def test_bad_participant_id(self):
        with self.assertRaises(ValueError):
            ThreePhaseCommit("t", ["a", " "])


class TestHappyPath(unittest.TestCase):
    def test_commit_outcome(self):
        t = _happy_path()
        self.assertIs(t.outcome, TransactionOutcome.COMMIT)
        self.assertEqual(t.phase, Phase.DONE_COMMITTED)

    def test_participant_states_committed(self):
        t = _happy_path()
        for p in ("a", "b", "c"):
            self.assertIs(t.state_of(p), ParticipantState.COMMITTED)

    def test_finalize_record(self):
        t = _happy_path("tx-9", ("x", "y"))
        rec = t.finalize_record()
        self.assertEqual(rec.txn_id, "tx-9")
        self.assertEqual(rec.participants, ("x", "y"))
        self.assertEqual(rec.outcome, "commit")
        self.assertTrue(rec.record_digest.startswith("sha256:"))
        d = rec.as_dict()
        self.assertEqual(d["schema"], THREE_PHASE_COMMIT_SCHEMA)


class TestAbortPaths(unittest.TestCase):
    def test_no_vote_aborts(self):
        t = ThreePhaseCommit("t", ["a", "b"])
        t.begin(1)
        t.record_vote("a", Vote.YES, 2)
        t.record_vote("b", Vote.NO, 3)
        self.assertIs(t.outcome, TransactionOutcome.ABORT)
        self.assertEqual(t.phase, Phase.DONE_ABORTED)
        self.assertIn("b", t.abort_reason)

    def test_operator_abort(self):
        t = ThreePhaseCommit("t", ["a"])
        t.begin(1)
        t.abort("operator request", 2)
        self.assertIs(t.outcome, TransactionOutcome.ABORT)

    def test_vote_after_abort_rejected(self):
        t = ThreePhaseCommit("t", ["a", "b"])
        t.begin(1)
        t.record_vote("a", Vote.NO, 2)
        with self.assertRaises(ThreePhaseCommitError):
            t.record_vote("b", Vote.YES, 3)

    def test_phase_after_abort_rejected(self):
        t = ThreePhaseCommit("t", ["a"])
        t.abort("stop", 2)
        with self.assertRaises(ThreePhaseCommitError):
            t.pre_commit(3)


class TestFailClosed(unittest.TestCase):
    def test_pre_commit_before_all_votes(self):
        t = ThreePhaseCommit("t", ["a", "b"])
        t.begin(1)
        t.record_vote("a", Vote.YES, 2)
        with self.assertRaises(ThreePhaseCommitError):
            t.pre_commit(3)

    def test_commit_before_all_pre_commit_acks(self):
        t = ThreePhaseCommit("t", ["a", "b"])
        t.begin(1)
        t.record_vote("a", Vote.YES, 2)
        t.record_vote("b", Vote.YES, 3)
        t.pre_commit(4)
        t.record_pre_commit_ack("a", 5)
        with self.assertRaises(ThreePhaseCommitError):
            t.commit(6)

    def test_duplicate_vote(self):
        t = ThreePhaseCommit("t", ["a"])
        t.begin(1)
        t.record_vote("a", Vote.YES, 2)
        with self.assertRaises(ThreePhaseCommitError):
            t.record_vote("a", Vote.YES, 3)

    def test_unknown_participant_vote(self):
        t = ThreePhaseCommit("t", ["a"])
        t.begin(1)
        with self.assertRaises(KeyError):
            t.record_vote("zz", Vote.YES, 2)

    def test_vote_in_wrong_phase(self):
        t = ThreePhaseCommit("t", ["a"])
        with self.assertRaises(ThreePhaseCommitError):
            t.record_vote("a", Vote.YES, 1)

    def test_begin_twice(self):
        t = ThreePhaseCommit("t", ["a"])
        t.begin(1)
        with self.assertRaises(ThreePhaseCommitError):
            t.begin(2)

    def test_vote_after_commit(self):
        t = _happy_path()
        with self.assertRaises(ThreePhaseCommitError):
            t.record_vote("a", Vote.YES, 99)

    def test_finalize_before_decision(self):
        t = ThreePhaseCommit("t", ["a"])
        with self.assertRaises(ThreePhaseCommitError):
            t.finalize_record()


class TestTerminationDecision(unittest.TestCase):
    def test_any_committed_commits(self):
        states = {
            "a": ParticipantState.ABORTED,
            "b": ParticipantState.COMMITTED,
        }
        self.assertIs(
            termination_decision(states), TransactionOutcome.COMMIT
        )

    def test_any_pre_committed_commits(self):
        states = {
            "a": ParticipantState.CAN_COMMITTED,
            "b": ParticipantState.PRE_COMMITTED,
        }
        self.assertIs(
            termination_decision(states), TransactionOutcome.COMMIT
        )

    def test_all_can_committed_commits(self):
        states = {
            "a": ParticipantState.CAN_COMMITTED,
            "b": ParticipantState.CAN_COMMITTED,
        }
        self.assertIs(
            termination_decision(states), TransactionOutcome.COMMIT
        )

    def test_mixed_init_aborts(self):
        states = {
            "a": ParticipantState.CAN_COMMITTED,
            "b": ParticipantState.INIT,
        }
        self.assertIs(termination_decision(states), TransactionOutcome.ABORT)

    def test_all_aborted_aborts(self):
        states = {"a": ParticipantState.ABORTED}
        self.assertIs(termination_decision(states), TransactionOutcome.ABORT)

    def test_pre_committed_beats_aborted(self):
        states = {
            "a": ParticipantState.ABORTED,
            "b": ParticipantState.PRE_COMMITTED,
        }
        self.assertIs(
            termination_decision(states), TransactionOutcome.COMMIT
        )

    def test_empty_states_rejected(self):
        with self.assertRaises(ValueError):
            termination_decision({})

    def test_bad_state_type(self):
        with self.assertRaises(TypeError):
            termination_decision({"a": "committed"})


class TestAuditEvents(unittest.TestCase):
    def test_event_shape(self):
        ev = three_phase_audit_event(EVENT_VOTE, "t1", "a voted yes", 7)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], EVENT_VOTE)
        self.assertEqual(ev["txn_id"], "t1")
        self.assertEqual(ev["seq"], 7)

    def test_unknown_kind_rejected(self):
        with self.assertRaises(ValueError):
            three_phase_audit_event("nope", "t1", "x", 1)

    def test_coordinator_events_logged(self):
        t = _happy_path()
        kinds = [e.kind for e in t.events()]
        self.assertIn(EVENT_TXN_STARTED, kinds)
        self.assertIn(EVENT_TXN_COMMITTED, kinds)
        self.assertNotIn(EVENT_TXN_ABORTED, kinds)


class TestMain(unittest.TestCase):
    def test_main(self):
        import three_phase_commit as m

        m.main()


if __name__ == "__main__":
    unittest.main()
