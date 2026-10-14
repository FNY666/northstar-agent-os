"""Tests for paxos_interface: proposer / acceptor / learner bookkeeping.

Run: python3 -m unittest discover -s tests -p 'test_paxos_interface.py'
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "paxos_interface",
    Path(__file__).resolve().parents[1] / "paxos_interface.py",
)
_mod = importlib.util.module_from_spec(_SPEC)
sys.modules["paxos_interface"] = _mod
_SPEC.loader.exec_module(_mod)

Proposer = _mod.Proposer
Acceptor = _mod.Acceptor
Learner = _mod.Learner
Prepare = _mod.Prepare
Promise = _mod.Promise
AcceptRequest = _mod.AcceptRequest
Accepted = _mod.Accepted
ChosenValue = _mod.ChosenValue
PaxosError = _mod.PaxosError
BallotConflictError = _mod.BallotConflictError
InsufficientPromises = _mod.InsufficientPromises
pin_value = _mod.pin_value
quorum_size = _mod.quorum_size
paxos_audit_event = _mod.paxos_audit_event
PAXOS_INTERFACE_VERSION = _mod.PAXOS_INTERFACE_VERSION
PAXOS_INTERFACE_SCHEMA = _mod.PAXOS_INTERFACE_SCHEMA

_ACCEPTORS = ("a1", "a2", "a3")


def _round(value, ballot=1, proposer_id="p1"):
    """Run a full 3-acceptor round; return (chosen, proposer, acceptors)."""
    proposer = Proposer(proposer_id, _ACCEPTORS)
    nodes = {a: Acceptor(a) for a in _ACCEPTORS}
    learner = Learner(_ACCEPTORS)
    prepare = proposer.prepare(ballot, 0)
    promises = [nodes[a].on_prepare(prepare, seq=1) for a in _ACCEPTORS]
    assert all(p is not None for p in promises)
    request = proposer.receive_promises(prepare, promises, value, seq=2)
    chosen = None
    for a in _ACCEPTORS:
        accepted = nodes[a].on_accept(request, seq=3)
        assert accepted is not None
        result = learner.on_accepted(accepted, seq=4)
        if result is not None:
            chosen = result
    assert chosen is not None
    return chosen, proposer, nodes


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(PAXOS_INTERFACE_VERSION, "paxos-interface.v1")
        self.assertEqual(PAXOS_INTERFACE_SCHEMA, "northstar.paxos-interface.v1")


class TestPinValue(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(pin_value({"x": 1}), pin_value({"x": 1}))

    def test_key_order_independent(self):
        self.assertEqual(pin_value({"a": 1, "b": 2}), pin_value({"b": 2, "a": 1}))

    def test_non_canonicalizable_raises(self):
        with self.assertRaises(PaxosError):
            pin_value(object())


class TestQuorumSize(unittest.TestCase):
    def test_majority_math(self):
        self.assertEqual(quorum_size(1), 1)
        self.assertEqual(quorum_size(3), 2)
        self.assertEqual(quorum_size(5), 3)

    def test_rejects_bool_and_zero(self):
        with self.assertRaises(TypeError):
            quorum_size(True)
        with self.assertRaises(ValueError):
            quorum_size(0)


class TestProposer(unittest.TestCase):
    def test_prepare_mints_record(self):
        p = Proposer("p1", _ACCEPTORS)
        prepare = p.prepare(1, 0)
        self.assertIsInstance(prepare, Prepare)
        self.assertEqual(prepare.proposer_id, "p1")
        self.assertEqual(prepare.ballot, 1)
        self.assertTrue(prepare.proposal_id.startswith("prop-p1-"))

    def test_ballot_reuse_raises(self):
        p = Proposer("p1", _ACCEPTORS)
        p.prepare(1, 0)
        with self.assertRaises(BallotConflictError):
            p.prepare(1, 1)

    def test_ballot_zero_rejected(self):
        p = Proposer("p1", _ACCEPTORS)
        with self.assertRaises(ValueError):
            p.prepare(0, 0)

    def test_duplicate_acceptor_rejected(self):
        with self.assertRaises(ValueError):
            Proposer("p1", ("a1", "a1"))

    def test_insufficient_promises(self):
        p = Proposer("p1", _ACCEPTORS)
        nodes = {a: Acceptor(a) for a in _ACCEPTORS}
        prepare = p.prepare(1, 0)
        one = [nodes["a1"].on_prepare(prepare, seq=1)]
        with self.assertRaises(InsufficientPromises):
            p.receive_promises(prepare, one, "v", seq=2)

    def test_value_selection_highest_accepted(self):
        """A proposer adopts the value with the highest accepted ballot."""
        # First round chooses "old".
        chosen, _, nodes = _round("old", ballot=1)
        # Second proposer prepares ballot 2; promises carry ballot-1 accepts.
        p2 = Proposer("p2", _ACCEPTORS)
        prepare2 = p2.prepare(2, 10)
        promises = [nodes[a].on_prepare(prepare2, seq=11) for a in _ACCEPTORS]
        self.assertTrue(all(pr is not None for pr in promises))
        request = p2.receive_promises(prepare2, promises, "new", seq=12)
        # Paxos rule: "old" (accepted at ballot 1) wins over "new".
        self.assertEqual(request.value_digest, pin_value("old"))

    def test_mismatched_promise_rejected(self):
        p = Proposer("p1", _ACCEPTORS)
        prepare = p.prepare(1, 0)
        other = Proposer("p2", _ACCEPTORS).prepare(1, 0)
        other_nodes = {a: Acceptor(a) for a in _ACCEPTORS}
        foreign = other_nodes["a1"].on_prepare(other, seq=1)
        with self.assertRaises(PaxosError):
            p.receive_promises(prepare, [foreign] * 2, "v", seq=2)

    def test_frozen_records(self):
        p = Proposer("p1", _ACCEPTORS)
        prepare = p.prepare(1, 0)
        with self.assertRaises(AttributeError):
            prepare.ballot = 99  # type: ignore[misc]

    def test_schema_pin_on_records(self):
        p = Proposer("p1", _ACCEPTORS)
        prepare = p.prepare(1, 0)
        self.assertEqual(prepare.as_dict()["schema"], PAXOS_INTERFACE_SCHEMA)


class TestAcceptor(unittest.TestCase):
    def test_lower_ballot_prepare_refused(self):
        node = Acceptor("a1")
        p = Proposer("p1", _ACCEPTORS)
        hi = p.prepare(5, 0)
        self.assertIsNotNone(node.on_prepare(hi, seq=1))
        p2 = Proposer("p2", _ACCEPTORS)
        lo = p2.prepare(3, 2)
        self.assertIsNone(node.on_prepare(lo, seq=3))

    def test_equal_ballot_prepare_promised(self):
        """Refusal is strict <: a ballot equal to promised is promised."""
        node = Acceptor("a1")
        p = Proposer("p1", _ACCEPTORS)
        first = p.prepare(2, 0)
        self.assertIsNotNone(node.on_prepare(first, seq=1))
        p2 = Proposer("p2", _ACCEPTORS)
        second = p2.prepare(2, 2)
        self.assertIsNotNone(node.on_prepare(second, seq=3))

    def test_lower_ballot_accept_refused(self):
        node = Acceptor("a1")
        p = Proposer("p1", _ACCEPTORS)
        hi = p.prepare(4, 0)
        node.on_prepare(hi, seq=1)
        stale = AcceptRequest(
            proposal_id="prop-x-1", proposer_id="px", ballot=2,
            value_digest=pin_value("v"), seq=2,
        )
        self.assertIsNone(node.on_accept(stale, seq=3))

    def test_accept_records_pair(self):
        node = Acceptor("a1")
        p = Proposer("p1", _ACCEPTORS)
        prepare = p.prepare(1, 0)
        node.on_prepare(prepare, seq=1)
        digest = pin_value("hello")
        req = AcceptRequest(
            proposal_id=prepare.proposal_id, proposer_id="p1", ballot=1,
            value_digest=digest, seq=2,
        )
        accepted = node.on_accept(req, seq=3)
        self.assertIsNotNone(accepted)
        self.assertEqual(node.accepted_pair, (1, digest))

    def test_promise_carries_accepted_pair(self):
        chosen, _, nodes = _round("v", ballot=1)
        p2 = Proposer("p2", _ACCEPTORS)
        prepare2 = p2.prepare(2, 10)
        promise = nodes["a1"].on_prepare(prepare2, seq=11)
        self.assertIsNotNone(promise)
        self.assertEqual(promise.accepted_ballot, 1)
        self.assertEqual(promise.accepted_digest, chosen.value_digest)

    def test_bad_input_type(self):
        node = Acceptor("a1")
        with self.assertRaises(TypeError):
            node.on_prepare("not-a-prepare", seq=1)  # type: ignore[arg-type]


class TestLearner(unittest.TestCase):
    def test_chooses_at_quorum(self):
        chosen, _, _ = _round({"cmd": "halt"}, ballot=1)
        self.assertIsInstance(chosen, ChosenValue)
        self.assertEqual(chosen.ballot, 1)
        self.assertEqual(chosen.value_digest, pin_value({"cmd": "halt"}))
        self.assertEqual(chosen.quorum, 2)
        self.assertEqual(len(chosen.acceptors), 2)

    def test_duplicate_acceptor_counts_once(self):
        learner = Learner(_ACCEPTORS)
        digest = pin_value("v")
        acc = Accepted("prop-1", "a1", 1, digest, 0)
        self.assertIsNone(learner.on_accepted(acc, seq=1))
        self.assertIsNone(learner.on_accepted(acc, seq=2))  # same acceptor again
        acc2 = Accepted("prop-1", "a2", 1, digest, 0)
        chosen = learner.on_accepted(acc2, seq=3)
        self.assertIsNotNone(chosen)

    def test_idempotent_learn(self):
        chosen, _, nodes = None, None, None
        chosen, _, _ = _round("v", ballot=1)
        # Re-learning the same choice returns the same record.
        learner2 = Learner(_ACCEPTORS)
        digest = chosen.value_digest
        a1 = Accepted(chosen.proposal_id, "a1", 1, digest, 0)
        a2 = Accepted(chosen.proposal_id, "a2", 1, digest, 0)
        first = learner2.on_accepted(a1, seq=1)
        self.assertIsNone(first)
        second = learner2.on_accepted(a2, seq=2)
        third = learner2.on_accepted(a2, seq=3)  # replay after choice
        self.assertEqual(second, third)
        self.assertTrue(learner2.is_chosen(chosen.proposal_id, 1))

    def test_conflicting_choice_raises(self):
        learner = Learner(_ACCEPTORS)
        d1, d2 = pin_value("v1"), pin_value("v2")
        learner.on_accepted(Accepted("prop-1", "a1", 1, d1, 0), seq=1)
        learner.on_accepted(Accepted("prop-1", "a2", 1, d1, 0), seq=2)  # chosen d1
        # Any later vote for a conflicting digest raises immediately,
        # even before it reaches quorum: the choice is already recorded.
        with self.assertRaises(PaxosError):
            learner.on_accepted(Accepted("prop-1", "a3", 1, d2, 0), seq=3)

    def test_unknown_acceptor_rejected(self):
        learner = Learner(_ACCEPTORS)
        with self.assertRaises(PaxosError):
            learner.on_accepted(
                Accepted("prop-1", "stranger", 1, pin_value("v"), 0), seq=1
            )

    def test_not_chosen_yet(self):
        learner = Learner(_ACCEPTORS)
        self.assertFalse(learner.is_chosen("prop-1", 1))
        with self.assertRaises(ValueError):
            learner.is_chosen("", 1)


class TestAuditEvents(unittest.TestCase):
    def test_audit_event_shape(self):
        chosen, _, _ = _round("v", ballot=1)
        event = paxos_audit_event(_mod.EVENT_CHOSEN, chosen.as_dict(), seq=9)
        self.assertEqual(event["schema"], "audit.ndjson/1")
        self.assertEqual(event["kind"], "paxos-chosen")
        self.assertEqual(event["audit_seq"], 9)

    def test_unknown_kind_rejected(self):
        with self.assertRaises(ValueError):
            paxos_audit_event("paxos-nope", {}, seq=0)

    def test_bad_audit_seq_rejected(self):
        chosen, _, _ = _round("v", ballot=1)
        with self.assertRaises(TypeError):
            paxos_audit_event(_mod.EVENT_CHOSEN, chosen.as_dict(), seq=True)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        _mod.main()  # asserts internally; must not raise


if __name__ == "__main__":
    unittest.main()
