"""Tests for approval_chain_time: wall-clock SLA variant of approval_chain."""

from __future__ import annotations

import unittest
from unittest import mock

from approval_chain_time import (
    APPROVAL_CHAIN_TIME_VERSION,
    CHAIN_ALLOW,
    CHAIN_DENY,
    ApprovalChainTime,
    ChainDecision,
)
from approval_sla_time import STATUS_PENDING
from signed_receipt_reflux import SignedReceipt


class FakeClock:
    """Deterministic stand-in for time.time."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def time(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_chain(**kwargs):
    kwargs.setdefault("approver_secret", bytes(range(32)))
    return ApprovalChainTime(**kwargs)


class VersionTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(APPROVAL_CHAIN_TIME_VERSION, "approval-chain-time.v1")

    def test_verdict_vocabulary(self):
        self.assertEqual((CHAIN_ALLOW, CHAIN_DENY), ("allow", "deny"))


class ConstructorTests(unittest.TestCase):
    def test_bad_secret_rejected(self):
        for bad in (b"short", bytes(31), bytes(33), "not-bytes", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ApprovalChainTime(approver_secret=bad)

    def test_bad_timeout_rejected(self):
        for bad in (0, -1, -0.5, True, "300", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ApprovalChainTime(approver_secret=bytes(range(32)), sla_timeout_seconds=bad)

    def test_default_timeout_accepted(self):
        chain = make_chain()
        self.assertEqual(chain._sla_timeout, 300.0)


class RequestTests(unittest.TestCase):
    def test_request_and_poll(self):
        chain = make_chain()
        rid = chain.request_approval("db.delete", "abstain: irreversible", 60.0)
        self.assertTrue(rid.startswith("apr-"))
        self.assertEqual(chain.poll(rid), STATUS_PENDING)

    def test_request_validation(self):
        chain = make_chain()
        for action, reason, timeout in [
            ("", "r", 60.0),
            ("a", "", 60.0),
            ("a", "r", 0),
            ("a", "r", -5),
            ("a", "r", True),
        ]:
            with self.assertRaises(ValueError):
                chain.request_approval(action, reason, timeout)

    def test_poll_unknown_raises(self):
        chain = make_chain()
        with self.assertRaises(KeyError):
            chain.poll("apr-nope")


class ApproveTests(unittest.TestCase):
    def test_full_flow(self):
        clock = FakeClock()
        with mock.patch("time.time", clock.time):
            chain = make_chain()
            rid = chain.request_approval("db.delete", "abstain", 60.0)
            receipt = chain.approve(rid, "human:op")
            self.assertIsInstance(receipt, SignedReceipt)
            self.assertEqual(receipt.request_id, rid)
            self.assertEqual(receipt.action, "db.delete")
            self.assertIsInstance(receipt.approved_at_seq, int)
            self.assertEqual(
                chain.execute_with_approval({"action_type": "db.delete"}, receipt),
                CHAIN_ALLOW,
            )

    def test_denied_yields_no_receipt(self):
        clock = FakeClock()
        with mock.patch("time.time", clock.time):
            chain = make_chain()
            rid = chain.request_approval("db.delete", "abstain", 60.0)
            self.assertIsNone(chain.approve(rid, "human:op", approved=False))

    def test_double_approve_returns_none(self):
        clock = FakeClock()
        with mock.patch("time.time", clock.time):
            chain = make_chain()
            rid = chain.request_approval("db.delete", "abstain", 60.0)
            self.assertIsNotNone(chain.approve(rid, "human:op"))
            self.assertIsNone(chain.approve(rid, "human:op"))

    def test_expired_request_never_yields_receipt(self):
        clock = FakeClock()
        with mock.patch("time.time", clock.time):
            chain = make_chain()
            rid = chain.request_approval("db.delete", "abstain", 10.0)
            clock.advance(11.0)
            self.assertEqual(chain.poll(rid), "expired")
            self.assertIsNone(chain.approve(rid, "human:op"))

    def test_approve_unknown_raises(self):
        chain = make_chain()
        with self.assertRaises(KeyError):
            chain.approve("apr-nope", "human:op")

    def test_approve_non_bool_raises(self):
        clock = FakeClock()
        with mock.patch("time.time", clock.time):
            chain = make_chain()
            rid = chain.request_approval("db.delete", "abstain", 60.0)
            with self.assertRaises(TypeError):
                chain.approve(rid, "human:op", approved="yes")

    def test_collect_receipt_consumes(self):
        clock = FakeClock()
        with mock.patch("time.time", clock.time):
            chain = make_chain()
            rid = chain.request_approval("db.delete", "abstain", 60.0)
            receipt = chain.approve(rid, "human:op")
            self.assertIsNotNone(chain.collect_receipt(rid))
            self.assertIsNone(chain.collect_receipt(rid))
            # the held receipt object still executes once; the channel
            # pop only prevents a second party from collecting it again.
            self.assertEqual(
                chain.execute_with_approval({"action_type": "db.delete"}, receipt),
                CHAIN_ALLOW,
            )
            # ...but a second execution is still refused by replay protection.
            self.assertEqual(
                chain.execute_with_approval({"action_type": "db.delete"}, receipt),
                CHAIN_DENY,
            )


class ExecuteTests(unittest.TestCase):
    def _approved(self, chain, action="db.delete"):
        rid = chain.request_approval(action, "abstain", 60.0)
        return chain.approve(rid, "human:op"), rid

    def test_no_receipt_denied(self):
        chain = make_chain()
        self.assertEqual(
            chain.execute_with_approval({"action_type": "db.read"}, None), CHAIN_DENY
        )

    def test_wrong_key_receipt_denied(self):
        clock = FakeClock()
        with mock.patch("time.time", clock.time):
            chain_a = make_chain(approver_secret=bytes(range(32)))
            chain_b = make_chain(approver_secret=bytes(range(1, 33)))
            rid = chain_b.request_approval("db.delete", "abstain", 60.0)
            receipt_b = chain_b.approve(rid, "human:op")
            self.assertEqual(
                chain_a.execute_with_approval({"action_type": "db.delete"}, receipt_b),
                CHAIN_DENY,
            )

    def test_action_mismatch_denied(self):
        clock = FakeClock()
        with mock.patch("time.time", clock.time):
            chain = make_chain()
            receipt, _ = self._approved(chain, "db.delete")
            self.assertEqual(
                chain.execute_with_approval({"action_type": "email.send"}, receipt),
                CHAIN_DENY,
            )

    def test_replay_denied(self):
        clock = FakeClock()
        with mock.patch("time.time", clock.time):
            chain = make_chain()
            receipt, _ = self._approved(chain)
            action = {"action_type": "db.delete"}
            self.assertEqual(chain.execute_with_approval(action, receipt), CHAIN_ALLOW)
            self.assertEqual(chain.execute_with_approval(action, receipt), CHAIN_DENY)

    def test_malformed_action_denied(self):
        clock = FakeClock()
        with mock.patch("time.time", clock.time):
            chain = make_chain()
            receipt, _ = self._approved(chain)
            self.assertEqual(chain.execute_with_approval("not-a-mapping", receipt), CHAIN_DENY)

    def test_receipt_satisfies_human_requirement(self):
        # db.delete is irreversible and not allowlisted: without a receipt
        # the edge gate would demand a human; the receipt satisfies it.
        clock = FakeClock()
        with mock.patch("time.time", clock.time):
            chain = make_chain()
            receipt, _ = self._approved(chain, "db.delete")
            decision = chain.execute_detailed({"action_type": "db.delete"}, receipt)
            self.assertIsInstance(decision, ChainDecision)
            self.assertEqual(decision.verdict, CHAIN_ALLOW)
            self.assertEqual(decision.edge_verdict, "require_human")
            self.assertTrue(decision.receipt_ok)
            self.assertTrue(decision.action_bound)
            self.assertEqual(decision.reason, "ok")

    def test_execute_detailed_record_shape(self):
        chain = make_chain()
        decision = chain.execute_detailed({"action_type": "db.read"}, None)
        self.assertEqual(decision.verdict, CHAIN_DENY)
        self.assertFalse(decision.receipt_ok)
        self.assertEqual(decision.reason, "bad-receipt")


if __name__ == "__main__":
    unittest.main()
