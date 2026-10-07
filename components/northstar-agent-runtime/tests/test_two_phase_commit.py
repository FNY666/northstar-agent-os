"""Tests for two_phase_commit."""

import unittest

from two_phase_commit import (
    SCHEMA_PIN,
    TWO_PHASE_COMMIT_VERSION,
    Coordinator,
    Participant,
    PrepareResult,
    Transaction,
    TxnOutcome,
    TwoPhaseCommit,
    TwoPhaseCommitError,
    Vote,
    VoteRecord,
    two_phase_commit_audit_event,
)


def _digest(ch: str) -> str:
    return "sha256:" + ch * 64


def _txn(tid: str = "txn-1", ch: str = "a") -> Transaction:
    return Transaction(tid, _digest(ch))


def _yes(_t: Transaction) -> Vote:
    return Vote.YES


def _no(_t: Transaction) -> Vote:
    return Vote.NO


def _noop(_t: Transaction) -> None:
    return None


def _boom(_t: Transaction) -> Vote:
    raise RuntimeError("voter exploded")


def _participant(pid: str, decide=_yes) -> Participant:
    return Participant(pid, decide, _noop, _noop)


def _coord(*participants: Participant) -> Coordinator:
    return Coordinator("coord-1", participants)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(TWO_PHASE_COMMIT_VERSION, "two-phase-commit.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.two-phase-commit.v1")


class TestRecords(unittest.TestCase):
    def test_transaction_frozen_and_valid(self):
        t = _txn()
        self.assertEqual(t.transaction_id, "txn-1")
        with self.assertRaises(AttributeError):
            t.transaction_id = "x"  # type: ignore[misc]

    def test_transaction_bad_id(self):
        with self.assertRaises(TwoPhaseCommitError):
            Transaction("", _digest("a"))

    def test_transaction_bad_digest(self):
        with self.assertRaises(TwoPhaseCommitError):
            Transaction("t", "not-a-digest")
        with self.assertRaises(TwoPhaseCommitError):
            Transaction("t", "sha256:" + "g" * 64)  # non-hex

    def test_participant_frozen_and_valid(self):
        p = _participant("p1")
        self.assertEqual(p.participant_id, "p1")
        with self.assertRaises(AttributeError):
            p.participant_id = "x"  # type: ignore[misc]

    def test_participant_bad_id(self):
        with self.assertRaises(TwoPhaseCommitError):
            Participant("", _yes, _noop, _noop)

    def test_participant_non_callable(self):
        with self.assertRaises(TwoPhaseCommitError):
            Participant("p1", "yes", _noop, _noop)  # type: ignore[arg-type]

    def test_vote_record_validation(self):
        with self.assertRaises(TwoPhaseCommitError):
            VoteRecord("p1", "yes", 1)  # type: ignore[arg-type]
        with self.assertRaises(TwoPhaseCommitError):
            VoteRecord("p1", Vote.YES, -1)
        with self.assertRaises(TwoPhaseCommitError):
            VoteRecord("p1", Vote.YES, True)


class TestCoordinatorConstruction(unittest.TestCase):
    def test_empty_participants_rejected(self):
        with self.assertRaises(TwoPhaseCommitError):
            Coordinator("c", ())

    def test_duplicate_participant_id_rejected(self):
        with self.assertRaises(TwoPhaseCommitError):
            _coord(_participant("p1"), _participant("p1"))

    def test_non_participant_rejected(self):
        with self.assertRaises(TwoPhaseCommitError):
            Coordinator("c", ("p1",))  # type: ignore[arg-type]

    def test_empty_coordinator_id_rejected(self):
        with self.assertRaises(TwoPhaseCommitError):
            Coordinator("", (_participant("p1"),))

    def test_participant_ids(self):
        c = _coord(_participant("p1"), _participant("p2"))
        self.assertEqual(c.participant_ids, ("p1", "p2"))


class TestPrepare(unittest.TestCase):
    def test_all_yes_decides_commit(self):
        c = _coord(_participant("p1"), _participant("p2"))
        result = c.prepare(_txn(), 1)
        self.assertEqual(result.decision, "commit")
        self.assertEqual([v.vote for v in result.votes], [Vote.YES, Vote.YES])
        self.assertEqual(
            [v.participant_id for v in result.votes], ["p1", "p2"]
        )

    def test_one_no_decides_abort(self):
        c = _coord(_participant("p1", _yes), _participant("p2", _no))
        result = c.prepare(_txn(), 1)
        self.assertEqual(result.decision, "abort")
        self.assertEqual([v.vote for v in result.votes], [Vote.YES, Vote.NO])

    def test_crashing_voter_is_no(self):
        c = _coord(_participant("p1", _boom))
        result = c.prepare(_txn(), 1)
        self.assertEqual(result.decision, "abort")
        self.assertEqual(result.votes[0].vote, Vote.NO)
        self.assertEqual(result.votes[0].note, "voter-raised:RuntimeError")

    def test_non_vote_return_is_no(self):
        c = _coord(_participant("p1", lambda t: "yes"))  # type: ignore[arg-type]
        result = c.prepare(_txn(), 1)
        self.assertEqual(result.decision, "abort")
        self.assertIn("non-vote", result.votes[0].note)

    def test_prepare_bad_seq(self):
        c = _coord(_participant("p1"))
        with self.assertRaises(TwoPhaseCommitError):
            c.prepare(_txn(), -1)
        with self.assertRaises(TwoPhaseCommitError):
            c.prepare(_txn(), True)


class TestPhase2(unittest.TestCase):
    def test_commit_requires_all_yes_prepare(self):
        c = _coord(_participant("p1", _yes), _participant("p2", _no))
        prep = c.prepare(_txn(), 1)
        with self.assertRaises(TwoPhaseCommitError):
            c.commit(_txn(), prep, 2)

    def test_abort_requires_matching_prepare(self):
        c = _coord(_participant("p1"))
        prep = c.prepare(_txn("other"), 1)
        with self.assertRaises(TwoPhaseCommitError):
            c.abort(_txn(), prep, 2)

    def test_commit_notifies_all_in_order(self):
        seen: list[str] = []

        def on_commit(t: Transaction) -> None:
            seen.append("commit")

        c = Coordinator(
            "c",
            (
                Participant("p1", _yes, on_commit, _noop),
                Participant("p2", _yes, on_commit, _noop),
            ),
        )
        prep = c.prepare(_txn(), 1)
        outcome = c.commit(_txn(), prep, 2)
        self.assertEqual(outcome.decision, "commit")
        self.assertEqual(outcome.notified, ("p1", "p2"))
        self.assertEqual(seen, ["commit", "commit"])

    def test_abort_notifies_all(self):
        seen: list[str] = []

        def on_abort(t: Transaction) -> None:
            seen.append("abort")

        c = Coordinator(
            "c",
            (
                Participant("p1", _no, _noop, on_abort),
                Participant("p2", _yes, _noop, on_abort),
            ),
        )
        prep = c.prepare(_txn(), 1)
        outcome = c.abort(_txn(), prep, 2)
        self.assertEqual(outcome.decision, "abort")
        self.assertEqual(seen, ["abort", "abort"])

    def test_crashing_notification_still_notifies_rest(self):
        def bad(t: Transaction) -> None:
            raise RuntimeError("notify exploded")

        c = Coordinator(
            "c",
            (
                Participant("p1", _yes, bad, _noop),
                Participant("p2", _yes, _noop, _noop),
            ),
        )
        prep = c.prepare(_txn(), 1)
        outcome = c.commit(_txn(), prep, 2)
        self.assertEqual(outcome.notified, ("p1", "p2"))


class TestOrchestrator(unittest.TestCase):
    def test_execute_commit_path(self):
        tpc = TwoPhaseCommit(_coord(_participant("p1"), _participant("p2")))
        outcome = tpc.execute(_txn(), 1)
        self.assertIsInstance(outcome, TxnOutcome)
        self.assertEqual(outcome.decision, "commit")
        self.assertEqual(tpc.decision_for("txn-1"), "commit")
        self.assertEqual(tpc.decided_transactions(), ("txn-1",))

    def test_execute_abort_path(self):
        tpc = TwoPhaseCommit(
            _coord(_participant("p1", _yes), _participant("p2", _no))
        )
        outcome = tpc.execute(_txn(), 1)
        self.assertEqual(outcome.decision, "abort")
        self.assertEqual(tpc.decision_for("txn-1"), "abort")

    def test_execute_idempotent_no_revoting(self):
        calls: list[str] = []

        def counting(t: Transaction) -> Vote:
            calls.append(t.transaction_id)
            return Vote.YES

        tpc = TwoPhaseCommit(_coord(_participant("p1", counting)))
        first = tpc.execute(_txn(), 1)
        second = tpc.execute(_txn(), 2)
        self.assertIs(first, second)
        self.assertEqual(calls, ["txn-1"])

    def test_decision_for_unknown_is_none(self):
        tpc = TwoPhaseCommit(_coord(_participant("p1")))
        self.assertIsNone(tpc.decision_for("never-seen"))

    def test_multiple_transactions(self):
        tpc = TwoPhaseCommit(_coord(_participant("p1")))
        tpc.execute(_txn("t1", "a"), 1)
        tpc.execute(_txn("t2", "b"), 2)
        self.assertEqual(tpc.decided_transactions(), ("t1", "t2"))

    def test_bad_coordinator_rejected(self):
        with self.assertRaises(TwoPhaseCommitError):
            TwoPhaseCommit("not-a-coordinator")  # type: ignore[arg-type]


class TestAudit(unittest.TestCase):
    def test_audit_event_shape(self):
        prep = _coord(_participant("p1")).prepare(_txn(), 1)
        event = two_phase_commit_audit_event("prepared", prep.as_dict(), 5)
        self.assertEqual(event["schema"], SCHEMA_PIN)
        self.assertEqual(event["kind"], "two-phase-commit.prepared")
        self.assertEqual(event["audit_seq"], 5)

    def test_audit_bad_kind(self):
        with self.assertRaises(TwoPhaseCommitError):
            two_phase_commit_audit_event("explode", {}, 1)

    def test_audit_bad_seq(self):
        with self.assertRaises(TwoPhaseCommitError):
            two_phase_commit_audit_event("prepared", {}, -1)


if __name__ == "__main__":
    unittest.main()
