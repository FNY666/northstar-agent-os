"""Integration tests: approval SLA queue -> signed receipt -> edge gate."""

import unittest

from approval_chain import (
    APPROVAL_CHAIN_VERSION,
    CHAIN_ALLOW,
    CHAIN_DENY,
    ApprovalChain,
    ChainDecision,
)
from signed_receipt_reflux import SignedReceipt


def make_chain(**kwargs):
    kwargs.setdefault("approver_secret", bytes(range(32)))
    return ApprovalChain(**kwargs)


class TestVersion(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(APPROVAL_CHAIN_VERSION, "approval-chain.v1")


class TestFullFlow(unittest.TestCase):
    def test_reversible_action_full_flow(self):
        chain = make_chain()
        rid = chain.request_approval("db.query", "abstain: check", 100)
        self.assertEqual(chain.poll(rid, 120), "pending")
        receipt = chain.approve(rid, "human:op", 120)
        self.assertIsInstance(receipt, SignedReceipt)
        self.assertEqual(
            chain.execute_with_approval({"action_type": "db.query"}, receipt), CHAIN_ALLOW
        )

    def test_irreversible_action_receipt_satisfies_human(self):
        chain = make_chain()
        rid = chain.request_approval("db.delete", "abstain: irreversible", 100)
        receipt = chain.approve(rid, "human:op", 100)
        self.assertIsNotNone(receipt)
        # edge gate alone would say require_human; the receipt IS the human.
        self.assertEqual(
            chain.execute_with_approval({"action_type": "db.delete"}, receipt), CHAIN_ALLOW
        )

    def test_physical_action_receipt_satisfies_human(self):
        chain = make_chain()
        rid = chain.request_approval("robot.move_to", "abstain: physical", 100)
        receipt = chain.approve(rid, "human:op", 100)
        self.assertEqual(
            chain.execute_with_approval({"action_type": "robot.move_to"}, receipt), CHAIN_ALLOW
        )

    def test_collect_receipt_path(self):
        chain = make_chain()
        rid = chain.request_approval("db.query", "abstain", 100)
        issued = chain.approve(rid, "human:op", 100)
        collected = chain.collect_receipt(rid)
        self.assertIsNotNone(collected)
        self.assertEqual(collected.signature, issued.signature)
        self.assertIsNone(chain.collect_receipt(rid))  # consumed
        self.assertEqual(
            chain.execute_with_approval({"action_type": "db.query"}, collected), CHAIN_ALLOW
        )

    def test_allowlisted_irreversible(self):
        chain = make_chain(irreversible_allowlist=["newsletter.send"])
        rid = chain.request_approval("newsletter.send", "abstain", 100)
        receipt = chain.approve(rid, "human:op", 100)
        decision = chain.execute_detailed({"action_type": "newsletter.send"}, receipt)
        self.assertEqual(decision.verdict, CHAIN_ALLOW)
        self.assertEqual(decision.edge_verdict, "allow")


class TestFailClosed(unittest.TestCase):
    def test_expired_sla_yields_no_receipt(self):
        chain = make_chain()
        rid = chain.request_approval("db.delete", "abstain", 200, sla_ticks=5)
        self.assertIsNone(chain.approve(rid, "human:op", 206))
        self.assertEqual(chain.poll(rid, 206), "expired")

    def test_denied_approval_yields_no_receipt(self):
        chain = make_chain()
        rid = chain.request_approval("db.delete", "abstain", 100)
        self.assertIsNone(chain.approve(rid, "human:op", 100, approved=False))
        self.assertEqual(chain.poll(rid, 100), "denied")

    def test_double_approve_returns_none(self):
        chain = make_chain()
        rid = chain.request_approval("db.query", "abstain", 100)
        self.assertIsNotNone(chain.approve(rid, "human:op", 100))
        self.assertIsNone(chain.approve(rid, "human:op", 101))

    def test_unknown_request_id_raises(self):
        chain = make_chain()
        with self.assertRaises(KeyError):
            chain.approve("apr-nope", "human:op", 100)

    def test_no_receipt_denied(self):
        chain = make_chain()
        self.assertEqual(
            chain.execute_with_approval({"action_type": "db.query"}, None), CHAIN_DENY
        )

    def test_tampered_receipt_denied(self):
        chain = make_chain()
        rid = chain.request_approval("db.query", "abstain", 100)
        receipt = chain.approve(rid, "human:op", 100)
        tampered = SignedReceipt(
            request_id=receipt.request_id,
            action=receipt.action,
            approver=receipt.approver,
            approved_at_seq=receipt.approved_at_seq,
            signature=b"\x00" * 64,
        )
        self.assertEqual(
            chain.execute_with_approval({"action_type": "db.query"}, tampered), CHAIN_DENY
        )

    def test_wrong_approver_key_denied(self):
        chain_a = make_chain(approver_secret=bytes(range(32)))
        chain_b = make_chain(approver_secret=bytes(range(1, 33)))
        rid = chain_a.request_approval("db.query", "abstain", 100)
        receipt = chain_a.approve(rid, "human:op", 100)
        self.assertEqual(
            chain_b.execute_with_approval({"action_type": "db.query"}, receipt), CHAIN_DENY
        )

    def test_receipt_for_different_action_denied(self):
        chain = make_chain()
        rid = chain.request_approval("db.delete", "abstain", 100)
        receipt = chain.approve(rid, "human:op", 100)
        # receipt authorizes db.delete, not email.send: not a capability token.
        self.assertEqual(
            chain.execute_with_approval({"action_type": "email.send"}, receipt), CHAIN_DENY
        )

    def test_malformed_action_denied(self):
        chain = make_chain()
        rid = chain.request_approval("db.query", "abstain", 100)
        receipt = chain.approve(rid, "human:op", 100)
        self.assertEqual(chain.execute_with_approval("not-a-mapping", receipt), CHAIN_DENY)
        self.assertEqual(chain.execute_with_approval({}, receipt), CHAIN_DENY)

    def test_replay_refused(self):
        chain = make_chain()
        rid = chain.request_approval("db.query", "abstain", 100)
        receipt = chain.approve(rid, "human:op", 100)
        action = {"action_type": "db.query"}
        self.assertEqual(chain.execute_with_approval(action, receipt), CHAIN_ALLOW)
        self.assertEqual(chain.execute_with_approval(action, receipt), CHAIN_DENY)


class TestDetailed(unittest.TestCase):
    def test_decision_record_shape(self):
        chain = make_chain()
        rid = chain.request_approval("db.query", "abstain", 100)
        receipt = chain.approve(rid, "human:op", 100)
        d = chain.execute_detailed({"action_type": "db.query"}, receipt)
        self.assertIsInstance(d, ChainDecision)
        self.assertEqual(d.verdict, CHAIN_ALLOW)
        self.assertEqual(d.request_id, rid)
        self.assertTrue(d.receipt_ok)
        self.assertTrue(d.action_bound)
        self.assertEqual(d.reason, "ok")

    def test_detailed_bad_receipt(self):
        chain = make_chain()
        d = chain.execute_detailed({"action_type": "db.query"}, None)
        self.assertEqual(d.verdict, CHAIN_DENY)
        self.assertFalse(d.receipt_ok)
        self.assertEqual(d.reason, "bad-receipt")

    def test_constructor_validation(self):
        with self.assertRaises(ValueError):
            make_chain(approver_secret=b"short")
        with self.assertRaises(ValueError):
            make_chain(sla_ticks=0)
        with self.assertRaises(ValueError):
            make_chain(sla_ticks=True)

    def test_custom_sla_ticks(self):
        chain = make_chain(sla_ticks=3)
        rid = chain.request_approval("db.query", "abstain", 100)
        self.assertIsNone(chain.approve(rid, "human:op", 104))

    def test_main_runs(self):
        import approval_chain

        approval_chain.main()


if __name__ == "__main__":
    unittest.main()
