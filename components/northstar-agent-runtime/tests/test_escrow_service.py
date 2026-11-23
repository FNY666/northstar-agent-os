"""Tests for the escrow_service module (hold/release/dispute bookkeeping)."""

import unittest

from escrow_service import (
    ESCROW_SERVICE_VERSION,
    SCHEMA_PIN,
    DisputeStateError,
    EscrowService,
    HoldAmountError,
    HoldDisputedError,
    HoldIdentityError,
    HoldNotActiveError,
    IdempotencyMismatchError,
    ReleaseExceedsHoldError,
    SplitSumError,
    UnknownHoldError,
    escrow_service_audit_event,
    main,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(ESCROW_SERVICE_VERSION, "escrow-service.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.escrow-service.v1")


class TestHold(unittest.TestCase):
    def test_hold_happy_path(self):
        svc = EscrowService()
        h = svc.hold("payer-1", "payee-1", 5000, "USD", 1, "delivery confirmed")
        self.assertEqual(h.hold_id, "esc-1")
        self.assertEqual(h.status, "held")
        self.assertTrue(h.digest.startswith("sha256:"))
        self.assertEqual(svc.hold_status("esc-1"), "held")
        self.assertEqual(svc.remaining_releasable("esc-1"), 5000)

    def test_hold_fail_closed_on_amounts(self):
        svc = EscrowService()
        for bad in (0, -100, 10.5, True, "5000", None):
            with self.assertRaises(HoldAmountError):
                svc.hold("payer-1", "payee-1", bad, "USD", 1)

    def test_hold_fail_closed_on_identities(self):
        svc = EscrowService()
        with self.assertRaises(HoldIdentityError):
            svc.hold("", "payee-1", 100, "USD", 1)
        with self.assertRaises(HoldIdentityError):
            svc.hold("payer-1", "", 100, "USD", 1)
        with self.assertRaises(HoldIdentityError):
            svc.hold("payer-1", "payee-1", 100, "usd", 1)
        with self.assertRaises(HoldIdentityError):
            svc.hold("payer-1", "payee-1", 100, "US", 1)

    def test_hold_idempotent_replay(self):
        svc = EscrowService()
        first = svc.hold("payer-1", "payee-1", 2500, "USD", 1,
                         idempotency_key="idem-key")
        replay = svc.hold("payer-1", "payee-1", 2500, "USD", 2,
                          idempotency_key="idem-key")
        self.assertIs(replay, first)
        self.assertEqual(replay.hold_id, "esc-1")

    def test_hold_idempotency_mismatch(self):
        svc = EscrowService()
        svc.hold("payer-1", "payee-1", 2500, "USD", 1,
                 idempotency_key="idem-key")
        with self.assertRaises(IdempotencyMismatchError):
            svc.hold("payer-1", "payee-1", 9999, "USD", 2,
                     idempotency_key="idem-key")


class TestRelease(unittest.TestCase):
    def test_release_full_default_amount(self):
        svc = EscrowService()
        svc.hold("payer-1", "payee-1", 5000, "USD", 1)
        r = svc.release("esc-1", 2)
        self.assertEqual(r.release_id, "rl-1")
        self.assertEqual(r.amount, 5000)
        self.assertEqual(r.cumulative_released, 5000)
        self.assertEqual(svc.hold_status("esc-1"), "released")
        self.assertEqual(svc.remaining_releasable("esc-1"), 0)

    def test_release_partial_cumulative_ceiling(self):
        svc = EscrowService()
        svc.hold("payer-1", "payee-1", 5000, "USD", 1)
        r1 = svc.release("esc-1", 2, amount=2000)
        self.assertEqual(r1.cumulative_released, 2000)
        r2 = svc.release("esc-1", 3, amount=3000)
        self.assertEqual(r2.cumulative_released, 5000)
        self.assertEqual(svc.hold_status("esc-1"), "released")
        self.assertEqual(len(svc.releases_for("esc-1")), 2)

    def test_release_overrun_fails(self):
        svc = EscrowService()
        svc.hold("payer-1", "payee-1", 5000, "USD", 1)
        svc.release("esc-1", 2, amount=4000)
        with self.assertRaises(ReleaseExceedsHoldError):
            svc.release("esc-1", 3, amount=2000)

    def test_release_unknown_or_terminal_hold_fails(self):
        svc = EscrowService()
        with self.assertRaises(UnknownHoldError):
            svc.release("esc-999", 1)
        svc.hold("payer-1", "payee-1", 1000, "USD", 1)
        svc.release("esc-1", 2)
        with self.assertRaises(HoldNotActiveError):
            svc.release("esc-1", 3)


class TestDispute(unittest.TestCase):
    def test_dispute_freezes_hold(self):
        svc = EscrowService()
        svc.hold("payer-1", "payee-1", 5000, "USD", 1)
        d = svc.dispute("esc-1", "payer-1", "goods not delivered", 2)
        self.assertEqual(d.dispute_id, "ed-1")
        self.assertEqual(d.status, "open")
        self.assertEqual(svc.hold_status("esc-1"), "disputed")
        with self.assertRaises(HoldDisputedError):
            svc.release("esc-1", 3)

    def test_dispute_state_errors(self):
        svc = EscrowService()
        with self.assertRaises(UnknownHoldError):
            svc.dispute("esc-999", "payer-1", "reason", 1)
        svc.hold("payer-1", "payee-1", 5000, "USD", 1)
        svc.dispute("esc-1", "payer-1", "reason", 2)
        with self.assertRaises(DisputeStateError):
            svc.dispute("esc-1", "payee-1", "reason again", 3)
        svc2 = EscrowService()
        svc2.hold("payer-1", "payee-1", 5000, "USD", 1)
        svc2.release("esc-1", 2)
        with self.assertRaises(DisputeStateError):
            svc2.dispute("esc-1", "payer-1", "too late", 3)

    def test_resolve_release_awards_payee(self):
        svc = EscrowService()
        svc.hold("payer-1", "payee-1", 5000, "USD", 1)
        svc.dispute("esc-1", "payee-1", "delivered per terms", 2)
        res = svc.resolve_dispute("esc-1", "release", 3)
        self.assertEqual(res.outcome, "release")
        self.assertEqual(res.to_payee, 5000)
        self.assertEqual(res.to_payer, 0)
        self.assertEqual(svc.hold_status("esc-1"), "released")
        self.assertIsNotNone(svc.resolution_for("esc-1"))

    def test_resolve_refund_returns_payer(self):
        svc = EscrowService()
        svc.hold("payer-1", "payee-1", 5000, "USD", 1)
        svc.dispute("esc-1", "payer-1", "never delivered", 2)
        res = svc.resolve_dispute("esc-1", "refund", 3)
        self.assertEqual(res.outcome, "refund")
        self.assertEqual(res.to_payer, 5000)
        self.assertEqual(svc.hold_status("esc-1"), "refunded")

    def test_resolve_split_must_sum_exactly(self):
        svc = EscrowService()
        svc.hold("payer-1", "payee-1", 5000, "USD", 1)
        svc.dispute("esc-1", "payer-1", "partial delivery", 2)
        with self.assertRaises(SplitSumError):
            svc.resolve_dispute("esc-1", "split", 3, split_payee=2000, split_payer=2000)
        res = svc.resolve_dispute("esc-1", "split", 4, split_payee=2000,
                                  split_payer=3000)
        self.assertEqual(res.outcome, "split")
        self.assertEqual(svc.hold_status("esc-1"), "split")


class TestAuditAndMain(unittest.TestCase):
    def test_audit_event_shape(self):
        ev = escrow_service_audit_event("held", 1, record_id="esc-1")
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertNotIn("amount", ev)
        ev2 = escrow_service_audit_event("held", 2, record_id="esc-1", amount=5000)
        self.assertEqual(ev2["amount"], 5000)
        with self.assertRaises(HoldAmountError):
            escrow_service_audit_event("held", 3, record_id="esc-1", amount=-1)

    def test_main_self_check(self):
        main()


if __name__ == "__main__":
    unittest.main()
