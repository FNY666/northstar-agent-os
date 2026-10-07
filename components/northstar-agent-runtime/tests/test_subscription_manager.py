"""Tests for subscription_manager.py: plans, trials, billing, cancellation."""

import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from subscription_manager import (  # noqa: E402
    AlreadyCanceledError,
    CancellationRecord,
    DuplicatePlanError,
    DuplicateSubscriptionError,
    PeriodTransition,
    PlanRecord,
    RetiredPlanError,
    SCHEMA_PIN,
    SUBSCRIPTION_MANAGER_VERSION,
    SeqOrderError,
    SubscriptionError,
    SubscriptionManager,
    SubscriptionRecord,
    UnknownPlanError,
    UnknownSubscriptionError,
    subscription_manager_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(SUBSCRIPTION_MANAGER_VERSION, "subscription-manager.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.subscription-manager.v1")

    def test_frozen_records(self):
        mgr = SubscriptionManager()
        plan = mgr.define_plan("p1", "Pro", 2000, "month", 1)
        self.assertIsInstance(plan, PlanRecord)
        with self.assertRaises(AttributeError):
            plan.name = "Hacked"  # type: ignore[misc]
        sub = mgr.subscribe("c1", "p1", 2)
        self.assertIsInstance(sub, SubscriptionRecord)
        with self.assertRaises(AttributeError):
            sub.state = "canceled"  # type: ignore[misc]


class TestPlans(unittest.TestCase):
    def setUp(self):
        self.mgr = SubscriptionManager()

    def test_define_plan_roundtrip(self):
        plan = self.mgr.define_plan("pro", "Pro", 2000, "month", 1,
                                    trial_period_seqs=10)
        self.assertEqual(plan.plan_id, "pro")
        self.assertEqual(plan.price_cents, 2000)
        self.assertEqual(plan.interval, "month")
        self.assertEqual(plan.trial_period_seqs, 10)
        self.assertFalse(plan.retired)
        self.assertTrue(plan.digest.startswith("sha256:"))
        self.assertTrue(plan.verify())

    def test_define_duplicate_refused(self):
        self.mgr.define_plan("pro", "Pro", 2000, "month", 1)
        with self.assertRaises(DuplicatePlanError):
            self.mgr.define_plan("pro", "Pro", 2000, "month", 2)

    def test_bad_inputs(self):
        with self.assertRaises(SubscriptionError):
            self.mgr.define_plan("", "Pro", 2000, "month", 1)
        with self.assertRaises(SubscriptionError):
            self.mgr.define_plan("p", "Pro", -1, "month", 1)
        with self.assertRaises(SubscriptionError):
            self.mgr.define_plan("p", "Pro", 2000, "week", 1)
        with self.assertRaises(SubscriptionError):
            self.mgr.define_plan("p", "Pro", True, "month", 1)  # bool not a number
        with self.assertRaises(SubscriptionError):
            self.mgr.define_plan("p", "Pro", 2000, "month", 1, trial_period_seqs=-1)

    def test_free_tier_zero_price(self):
        plan = self.mgr.define_plan("free", "Free", 0, "month", 1)
        self.assertEqual(plan.price_cents, 0)

    def test_unknown_plan_lookup(self):
        with self.assertRaises(UnknownPlanError):
            self.mgr.plan("nope")

    def test_retire_plan(self):
        self.mgr.define_plan("p", "Pro", 100, "month", 1)
        retired = self.mgr.retire_plan("p", 2)
        self.assertTrue(retired.retired)
        self.assertTrue(retired.verify())
        with self.assertRaises(RetiredPlanError):
            self.mgr.subscribe("c1", "p", 3)
        with self.assertRaises(UnknownPlanError):
            self.mgr.retire_plan("nope", 4)


class TestSubscribe(unittest.TestCase):
    def setUp(self):
        self.mgr = SubscriptionManager()
        self.mgr.define_plan("pro", "Pro", 2000, "month", 1, trial_period_seqs=10)

    def test_subscribe_active(self):
        sub = self.mgr.subscribe("c1", "pro", 2)
        self.assertEqual(sub.state, "active")
        self.assertIsNone(sub.trial_end_seq)
        self.assertTrue(sub.subscription_id.startswith("sub-"))
        self.assertTrue(sub.verify())

    def test_subscribe_trial(self):
        sub = self.mgr.trial("c1", "pro", 2)
        self.assertEqual(sub.state, "trialing")
        self.assertEqual(sub.trial_end_seq, 2 + 10)

    def test_trial_on_plan_without_trial_refused(self):
        self.mgr.define_plan("basic", "Basic", 500, "month", 2)
        with self.assertRaises(SubscriptionError):
            self.mgr.trial("c1", "basic", 3)

    def test_duplicate_subscription_refused(self):
        self.mgr.subscribe("c1", "pro", 2)
        with self.assertRaises(DuplicateSubscriptionError):
            self.mgr.subscribe("c1", "pro", 3)
        # Different plan for the same customer is fine.
        self.mgr.define_plan("team", "Team", 5000, "month", 4)
        sub = self.mgr.subscribe("c1", "team", 5)
        self.assertEqual(sub.plan_id, "team")

    def test_end_trial(self):
        sub = self.mgr.trial("c1", "pro", 2)
        sub = self.mgr.end_trial(sub.subscription_id, 12)
        self.assertEqual(sub.state, "active")
        with self.assertRaises(SubscriptionError):
            self.mgr.end_trial(sub.subscription_id, 13)  # no longer trialing

    def test_seq_order_enforced(self):
        self.mgr.subscribe("c1", "pro", 5)
        with self.assertRaises(SeqOrderError):
            self.mgr.subscribe("c2", "pro", 5)  # not strictly increasing
        with self.assertRaises(SubscriptionError):
            self.mgr.subscribe("c2", "pro", True)


class TestBilling(unittest.TestCase):
    def setUp(self):
        self.mgr = SubscriptionManager()
        self.mgr.define_plan("pro", "Pro", 2000, "month", 1)

    def test_advance_period_paid(self):
        sub = self.mgr.subscribe("c1", "pro", 2)
        t = self.mgr.advance_period(sub.subscription_id, 3, 100, paid=True)
        self.assertIsInstance(t, PeriodTransition)
        self.assertEqual(t.outcome, "paid")
        self.assertEqual(self.mgr.subscription(sub.subscription_id).state, "active")

    def test_advance_period_unpaid_then_paid(self):
        sub = self.mgr.subscribe("c1", "pro", 2)
        t = self.mgr.advance_period(sub.subscription_id, 3, 100, paid=False)
        self.assertEqual(t.outcome, "past_due")
        self.assertEqual(self.mgr.subscription(sub.subscription_id).state, "past_due")
        # past_due is non-terminal, so is_active stays True (Stripe dunning
        # discipline: the subscription exists, it is just not in good standing).
        self.assertTrue(self.mgr.is_active(sub.subscription_id, 50))
        sub = self.mgr.mark_paid(sub.subscription_id, 4)
        self.assertEqual(sub.state, "active")
        self.assertTrue(self.mgr.is_active(sub.subscription_id, 50))

    def test_advance_refusals(self):
        sub = self.mgr.subscribe("c1", "pro", 2)
        with self.assertRaises(UnknownSubscriptionError):
            self.mgr.advance_period("sub-999", 3, 100)
        with self.assertRaises(SubscriptionError):
            self.mgr.advance_period(sub.subscription_id, 3, 1)  # before start


class TestCancel(unittest.TestCase):
    def setUp(self):
        self.mgr = SubscriptionManager()
        self.mgr.define_plan("pro", "Pro", 2000, "month", 1)

    def test_cancel_now_terminal(self):
        sub = self.mgr.subscribe("c1", "pro", 2)
        rec = self.mgr.cancel_now(sub.subscription_id, 3)
        self.assertIsInstance(rec, CancellationRecord)
        self.assertFalse(rec.cancel_at_period_end)
        self.assertEqual(self.mgr.subscription(sub.subscription_id).state, "canceled")
        with self.assertRaises(AlreadyCanceledError):
            self.mgr.cancel(sub.subscription_id, 4)
        self.assertFalse(self.mgr.is_active(sub.subscription_id, 10))

    def test_cancel_at_period_end_then_finalize(self):
        sub = self.mgr.subscribe("c1", "pro", 2)
        rec = self.mgr.cancel(sub.subscription_id, 3, at_period_end=True)
        self.assertTrue(rec.cancel_at_period_end)
        # Still active until the period ends.
        self.assertEqual(self.mgr.subscription(sub.subscription_id).state, "active")
        sub = self.mgr.finalize_cancellation(sub.subscription_id, 4)
        self.assertEqual(sub.state, "canceled")

    def test_cancellation_record_lookup(self):
        sub = self.mgr.subscribe("c1", "pro", 2)
        self.assertIsNone(self.mgr.cancellation(sub.subscription_id))
        self.mgr.cancel_now(sub.subscription_id, 3)
        rec = self.mgr.cancellation(sub.subscription_id)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.subscription_id, sub.subscription_id)


class TestViews(unittest.TestCase):
    def test_filters_and_views(self):
        mgr = SubscriptionManager()
        mgr.define_plan("pro", "Pro", 2000, "month", 1)
        mgr.define_plan("team", "Team", 5000, "year", 2)
        a = mgr.subscribe("c1", "pro", 3)
        b = mgr.subscribe("c2", "team", 4)
        self.assertEqual(len(mgr.subscriptions()), 2)
        self.assertEqual(len(mgr.subscriptions(customer_id="c1")), 1)
        self.assertEqual(mgr.subscriptions(customer_id="c1")[0].subscription_id,
                         a.subscription_id)
        self.assertEqual(len(mgr.subscriptions(state="active")), 2)
        self.assertEqual(set(mgr.subscription_ids()),
                         {a.subscription_id, b.subscription_id})
        self.assertEqual(mgr.plan_ids(), ("pro", "team"))


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ev = subscription_manager_audit_event("subscribed", 1,
                                             {"subscription_id": "sub-1"})
        self.assertEqual(ev["kind"], "subscribed")
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertEqual(ev["detail"]["subscription_id"], "sub-1")
        # Non-scalar details are digest-pinned, never inlined.
        ev2 = subscription_manager_audit_event("plan-defined", 2,
                                               {"plan": {"plan_id": "p"}})
        self.assertIn("plan_digest", ev2["detail"])
        self.assertNotIn("plan", ev2["detail"])
        with self.assertRaises(SubscriptionError):
            subscription_manager_audit_event("bogus-kind", 3)
        with self.assertRaises(SubscriptionError):
            subscription_manager_audit_event("subscribed", -1)


class TestMain(unittest.TestCase):
    def test_main(self):
        from subscription_manager import main
        main()


if __name__ == "__main__":
    unittest.main()
