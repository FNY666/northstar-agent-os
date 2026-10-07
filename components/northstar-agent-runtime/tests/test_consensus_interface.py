"""Tests for consensus_interface: propose/accept/commit bookkeeping."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from consensus_interface import (
    CONSENSUS_INTERFACE_SCHEMA,
    CONSENSUS_INTERFACE_VERSION,
    EVENT_ACCEPTED,
    EVENT_COMMITTED,
    EVENT_COMMIT_REFUSED,
    EVENT_PROPOSED,
    Acceptance,
    BallotConflictError,
    CommitRecord,
    ConsensusError,
    ConsensusNode,
    Proposal,
    consensus_audit_event,
    pin_value,
    quorum_size,
)


def make_node(node_id="n1", acceptors=("n1", "n2", "n3")):
    return ConsensusNode(node_id, acceptors)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CONSENSUS_INTERFACE_VERSION, "consensus-interface.v1")

    def test_schema_pin(self):
        self.assertEqual(
            CONSENSUS_INTERFACE_SCHEMA, "northstar.consensus-interface.v1"
        )


class TestQuorumSize(unittest.TestCase):
    def test_quorum_1(self):
        self.assertEqual(quorum_size(1), 1)

    def test_quorum_3(self):
        self.assertEqual(quorum_size(3), 2)

    def test_quorum_5(self):
        self.assertEqual(quorum_size(5), 3)

    def test_quorum_4(self):
        self.assertEqual(quorum_size(4), 3)

    def test_quorum_bad_type(self):
        with self.assertRaises(TypeError):
            quorum_size(True)

    def test_quorum_zero(self):
        with self.assertRaises(ValueError):
            quorum_size(0)


class TestPinValue(unittest.TestCase):
    def test_pin_deterministic(self):
        self.assertEqual(pin_value({"a": 1}), pin_value({"a": 1}))

    def test_pin_key_order_independent(self):
        self.assertEqual(
            pin_value({"a": 1, "b": 2}), pin_value({"b": 2, "a": 1})
        )

    def test_pin_shape(self):
        digest = pin_value("x")
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(len(digest), len("sha256:") + 64)

    def test_pin_non_canonicalizable(self):
        with self.assertRaises(TypeError):
            pin_value(object())

    def test_pin_nan_rejected(self):
        with self.assertRaises(TypeError):
            pin_value(float("nan"))


class TestNodeConstruction(unittest.TestCase):
    def test_happy_path(self):
        node = make_node()
        self.assertEqual(node.node_id, "n1")
        self.assertEqual(node.quorum, 2)

    def test_explicit_quorum(self):
        node = ConsensusNode("n1", ("n1", "n2", "n3"), quorum=3)
        self.assertEqual(node.quorum, 3)

    def test_node_not_in_acceptors(self):
        with self.assertRaises(ValueError):
            ConsensusNode("n9", ("n1", "n2"))

    def test_duplicate_acceptors(self):
        with self.assertRaises(ValueError):
            ConsensusNode("n1", ("n1", "n1", "n2"))

    def test_empty_acceptors(self):
        with self.assertRaises(TypeError):
            ConsensusNode("n1", [])

    def test_bad_quorum(self):
        with self.assertRaises(ValueError):
            ConsensusNode("n1", ("n1", "n2"), quorum=5)


class TestPropose(unittest.TestCase):
    def test_propose_happy(self):
        node = make_node()
        proposal = node.propose({"kill": True}, ballot=1, seq=0)
        self.assertIsInstance(proposal, Proposal)
        self.assertEqual(proposal.proposer_id, "n1")
        self.assertEqual(proposal.ballot, 1)
        self.assertEqual(proposal.value_digest, pin_value({"kill": True}))
        # Own acceptance auto-recorded.
        self.assertEqual(node.acceptance_count(proposal.proposal_id), 1)

    def test_propose_bad_ballot(self):
        node = make_node()
        with self.assertRaises(ValueError):
            node.propose("x", ballot=0, seq=0)

    def test_propose_bool_ballot(self):
        node = make_node()
        with self.assertRaises(TypeError):
            node.propose("x", ballot=True, seq=0)

    def test_propose_ballot_reuse(self):
        node = make_node()
        node.propose("x", ballot=1, seq=0)
        with self.assertRaises(BallotConflictError):
            node.propose("y", ballot=1, seq=1)

    def test_proposal_ids_deterministic(self):
        node = make_node()
        p1 = node.propose("a", ballot=1, seq=0)
        p2 = node.propose("b", ballot=2, seq=1)
        self.assertEqual(p1.proposal_id, "prop-n1-1")
        self.assertEqual(p2.proposal_id, "prop-n1-2")

    def test_propose_non_canonicalizable_value(self):
        node = make_node()
        with self.assertRaises(TypeError):
            node.propose(object(), ballot=1, seq=0)


class TestPrepare(unittest.TestCase):
    def test_prepare_records_promise(self):
        node = make_node()
        proposal = node.propose("x", ballot=3, seq=0)
        other = Proposal(
            proposal_id="prop-n2-9",
            proposer_id="n2",
            ballot=5,
            value_digest=pin_value("y"),
            proposed_seq=0,
        )
        self.assertTrue(node.prepare(other))
        self.assertEqual(node._promised_ballot, 5)

    def test_prepare_lower_ballot_refused(self):
        node = make_node()
        node.propose("x", ballot=5, seq=0)
        late = Proposal(
            proposal_id="prop-n2-1",
            proposer_id="n2",
            ballot=3,
            value_digest=pin_value("y"),
            proposed_seq=0,
        )
        self.assertFalse(node.prepare(late))

    def test_prepare_equal_ballot_ok(self):
        node = make_node()
        node.propose("x", ballot=5, seq=0)
        same = Proposal(
            proposal_id="prop-n2-1",
            proposer_id="n2",
            ballot=5,
            value_digest=pin_value("y"),
            proposed_seq=0,
        )
        self.assertTrue(node.prepare(same))

    def test_prepare_wrong_type(self):
        node = make_node()
        with self.assertRaises(TypeError):
            node.prepare("not-a-proposal")


class TestReceiveAcceptance(unittest.TestCase):
    def test_peer_acceptance_recorded(self):
        node = make_node()
        proposal = node.propose("x", ballot=1, seq=0)
        node.receive_acceptance(
            Acceptance(proposal.proposal_id, "n2", 1, accepted_seq=1)
        )
        self.assertEqual(node.acceptance_count(proposal.proposal_id), 2)

    def test_duplicate_vote_rejected(self):
        node = make_node()
        proposal = node.propose("x", ballot=1, seq=0)
        dup = Acceptance(proposal.proposal_id, "n2", 1, accepted_seq=1)
        node.receive_acceptance(dup)
        with self.assertRaises(ConsensusError):
            node.receive_acceptance(dup)

    def test_unknown_proposal_rejected(self):
        node = make_node()
        with self.assertRaises(ConsensusError):
            node.receive_acceptance(
                Acceptance("prop-nope-1", "n2", 1, accepted_seq=0)
            )

    def test_ballot_mismatch_rejected(self):
        node = make_node()
        proposal = node.propose("x", ballot=1, seq=0)
        with self.assertRaises(ConsensusError):
            node.receive_acceptance(
                Acceptance(proposal.proposal_id, "n2", 2, accepted_seq=1)
            )

    def test_unknown_acceptor_rejected(self):
        node = make_node()
        proposal = node.propose("x", ballot=1, seq=0)
        with self.assertRaises(ConsensusError):
            node.receive_acceptance(
                Acceptance(proposal.proposal_id, "n9", 1, accepted_seq=1)
            )

    def test_wrong_type(self):
        node = make_node()
        with self.assertRaises(TypeError):
            node.receive_acceptance({"proposal_id": "x"})


class TestCommit(unittest.TestCase):
    def test_commit_below_quorum_none(self):
        node = make_node()
        proposal = node.propose("x", ballot=1, seq=0)
        # Only own vote (1 < quorum 2).
        self.assertIsNone(node.commit(proposal.proposal_id, seq=1))

    def test_commit_happy(self):
        node = make_node()
        proposal = node.propose({"v": 1}, ballot=1, seq=0)
        node.receive_acceptance(
            Acceptance(proposal.proposal_id, "n2", 1, accepted_seq=1)
        )
        record = node.commit(proposal.proposal_id, seq=2)
        self.assertIsInstance(record, CommitRecord)
        self.assertEqual(record.acceptors, ("n1", "n2"))
        self.assertEqual(record.quorum, 2)
        self.assertEqual(record.value_digest, pin_value({"v": 1}))

    def test_commit_idempotent(self):
        node = make_node()
        proposal = node.propose("x", ballot=1, seq=0)
        node.receive_acceptance(
            Acceptance(proposal.proposal_id, "n2", 1, accepted_seq=1)
        )
        first = node.commit(proposal.proposal_id, seq=2)
        second = node.commit(proposal.proposal_id, seq=3)
        self.assertEqual(first, second)

    def test_commit_unknown_proposal(self):
        node = make_node()
        with self.assertRaises(ValueError):
            node.commit("prop-nope-1", seq=0)

    def test_commit_status_none_before(self):
        node = make_node()
        proposal = node.propose("x", ballot=1, seq=0)
        self.assertIsNone(node.commit_status(proposal.proposal_id))

    def test_commit_status_after(self):
        node = make_node()
        proposal = node.propose("x", ballot=1, seq=0)
        node.receive_acceptance(
            Acceptance(proposal.proposal_id, "n2", 1, accepted_seq=1)
        )
        node.commit(proposal.proposal_id, seq=2)
        self.assertIsNotNone(node.commit_status(proposal.proposal_id))


class TestProposeCommit(unittest.TestCase):
    def test_full_pipeline_commits(self):
        node = make_node()
        peers = [
            Acceptance("prop-n1-1", "n2", 1, accepted_seq=1),
        ]
        record = node.propose_commit("go", ballot=1, peer_acceptances=peers, seq=0)
        self.assertIsNotNone(record)
        self.assertEqual(record.value_digest, pin_value("go"))

    def test_full_pipeline_no_quorum(self):
        node = ConsensusNode("n1", ("n1", "n2", "n3", "n4", "n5"))
        record = node.propose_commit("go", ballot=1, peer_acceptances=[], seq=0)
        self.assertIsNone(record)


class TestFrozenRecords(unittest.TestCase):
    def test_proposal_frozen(self):
        proposal = Proposal("p", "n1", 1, pin_value("x"), 0)
        with self.assertRaises(Exception):
            proposal.ballot = 2

    def test_commit_record_distinct_acceptors(self):
        with self.assertRaises(ValueError):
            CommitRecord("p", pin_value("x"), 1, ("n1", "n1"), 2, 0)

    def test_acceptance_validation(self):
        with self.assertRaises(ValueError):
            Acceptance("", "n1", 1, 0)


class TestAuditEvents(unittest.TestCase):
    def test_proposed_event_shape(self):
        node = make_node()
        proposal = node.propose("x", ballot=1, seq=0)
        event = consensus_audit_event(EVENT_PROPOSED, proposal, seq=1)
        self.assertEqual(event["event"], EVENT_PROPOSED)
        self.assertEqual(event["audit_seq"], 1)
        self.assertEqual(
            event["record"]["schema"], "northstar.consensus-interface.v1"
        )

    def test_committed_event_shape(self):
        node = make_node()
        proposal = node.propose("x", ballot=1, seq=0)
        node.receive_acceptance(
            Acceptance(proposal.proposal_id, "n2", 1, accepted_seq=1)
        )
        record = node.commit(proposal.proposal_id, seq=2)
        event = consensus_audit_event(EVENT_COMMITTED, record, seq=3)
        self.assertEqual(event["event"], EVENT_COMMITTED)

    def test_bad_kind(self):
        node = make_node()
        proposal = node.propose("x", ballot=1, seq=0)
        with self.assertRaises(ValueError):
            consensus_audit_event("bogus", proposal, seq=0)

    def test_bad_seq(self):
        node = make_node()
        proposal = node.propose("x", ballot=1, seq=0)
        with self.assertRaises(TypeError):
            consensus_audit_event(EVENT_PROPOSED, proposal, seq=True)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import consensus_interface

        # main() asserts internally; just ensure it doesn't raise.
        consensus_interface.main()


if __name__ == "__main__":
    unittest.main()
