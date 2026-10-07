"""Tests for billing_engine.py (metered usage, tiers, invoices, proration)."""

import ast
import unittest
from pathlib import Path

import billing_engine as be
from billing_engine import (
    BadPeriodError,
    BadQuantityError,
    BadMoneyError,
    BadTierError,
    BillingEngine,
    BillingError,
    DuplicatePlanError,
    SeqOrderError,
    UnpricedMetricError,
    UnknownPlanError,
    billing_engine_audit_event,
)


def _ast_stdlib_only():
    tree = ast.parse(Path(__file__).resolve().parent.parent.joinpath("billing_engine.py").read_text())
    allowed = {"__future__", "hashlib", "dataclasses", "threading", "typing", "canonical_json", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(be.BILLING_ENGINE_VERSION, "billing-engine.v1")
        self.assertEqual(be.SCHEMA_PIN, "northstar.billing-engine.v1")
        _ast_stdlib_only()


class TestPlans(unittest.TestCase):
    def test_define_flat_plan(self):
        eng = BillingEngine()
        rec = eng.define_plan("basic", 1000, {"api": 2}, seq=1)
        self.assertEqual(rec.kind, "flat")
        self.assertEqual(rec.base_fee_cents, 1000)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(rec.version, "billing-engine.v1")

    def test_duplicate_plan_refused(self):
        eng = BillingEngine()
        eng.define_plan("basic", 0, {"api": 1}, seq=1)
        with self.assertRaises(DuplicatePlanError):
            eng.define_plan("basic", 0, {"api": 1}, seq=2)

    def test_define_bad_inputs(self):
        eng = BillingEngine()
        with self.assertRaises(BadMoneyError):
            eng.define_plan("p", -1, {"api": 1}, seq=1)
        with self.assertRaises(BillingError):
            eng.define_plan("", 0, {"api": 1}, seq=1)
        with self.assertRaises(BillingError):
            eng.define_plan("p", 0, {}, seq=1)
        with self.assertRaises(BadMoneyError):
            eng.define_plan("p", 0, {"api": -1}, seq=1)
        with self.assertRaises(BillingError):
            eng.define_plan("p", 0, {"api": True}, seq=1)

    def test_seq_ordering(self):
        eng = BillingEngine()
        eng.define_plan("a", 0, {"m": 1}, seq=5)
        with self.assertRaises(SeqOrderError):
            eng.define_plan("b", 0, {"m": 1}, seq=5)
        with self.assertRaises(SeqOrderError):
            eng.define_plan("b", 0, {"m": 1}, seq=3)

    def test_define_tiered_plan(self):
        eng = BillingEngine()
        rec = eng.define_tiered_plan("pro", 5000, {"api": ((100, 5), (None, 2))}, seq=1)
        self.assertEqual(rec.kind, "tiered")
        self.assertEqual(rec.as_dict()["plan_id"], "pro")

    def test_tier_validation(self):
        eng = BillingEngine()
        with self.assertRaises(BadTierError):  # final tier must be unbounded
            eng.define_tiered_plan("p", 0, {"m": ((100, 5),)}, seq=1)
        with self.assertRaises(BadTierError):  # non-increasing limits
            eng.define_tiered_plan("p", 0, {"m": ((100, 5), (100, 4), (None, 1))}, seq=1)
        with self.assertRaises(BadTierError):  # unbounded not last
            eng.define_tiered_plan("p", 0, {"m": ((None, 5), (100, 4))}, seq=1)
        with self.assertRaises(BadTierError):  # empty tiers
            eng.define_tiered_plan("p", 0, {"m": ()}, seq=1)
        with self.assertRaises(BillingError):  # bool seq
            eng.define_tiered_plan("p", 0, {"m": ((100, 5), (None, 1))}, seq=True)


class TestUsage(unittest.TestCase):
    def test_record_usage(self):
        eng = BillingEngine()
        eng.define_plan("basic", 0, {"api": 2}, seq=1)
        rec = eng.record_usage("acme", "basic", "api", 10, seq=2)
        self.assertEqual(rec.quantity, 10)
        self.assertFalse(rec.invoiced)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(eng.uninvoiced_count("acme", "basic"), 1)

    def test_record_unknown_plan(self):
        eng = BillingEngine()
        with self.assertRaises(UnknownPlanError):
            eng.record_usage("acme", "nope", "api", 1, seq=1)

    def test_record_unpriced_metric(self):
        eng = BillingEngine()
        eng.define_plan("basic", 0, {"api": 2}, seq=1)
        with self.assertRaises(UnpricedMetricError):
            eng.record_usage("acme", "basic", "other", 1, seq=2)

    def test_record_bad_quantity(self):
        eng = BillingEngine()
        eng.define_plan("basic", 0, {"api": 2}, seq=1)
        for bad in (0, -3, True, 1.5, "10"):
            with self.assertRaises(BadQuantityError):
                eng.record_usage("acme", "basic", "api", bad, seq=2)


class TestInvoice(unittest.TestCase):
    def test_invoice_flat(self):
        eng = BillingEngine()
        eng.define_plan("basic", 1000, {"api": 2, "gb": 50}, seq=1)
        eng.record_usage("acme", "basic", "api", 100, seq=2)
        eng.record_usage("acme", "basic", "gb", 3, seq=3)
        inv = eng.invoice("acme", "basic", "2026-10", seq=4)
        self.assertEqual(inv.invoice_id, "inv-1")
        self.assertEqual(inv.total_cents, 1000 + 200 + 150)
        self.assertEqual(len(inv.line_items), 2)
        self.assertEqual(len(inv.usage_digests), 2)
        self.assertTrue(inv.digest.startswith("sha256:"))
        # usage consumed exactly once
        self.assertEqual(eng.uninvoiced_count("acme", "basic"), 0)
        inv2 = eng.invoice("acme", "basic", "2026-11", seq=5)
        self.assertEqual(inv2.total_cents, 1000)  # base fee only
        self.assertEqual(len(inv2.line_items), 0)

    def test_invoice_tiered_math(self):
        eng = BillingEngine()
        eng.define_tiered_plan("pro", 5000, {"api": ((1000, 2), (9000, 1), (None, 0))}, seq=1)
        eng.record_usage("globex", "pro", "api", 12000, seq=2)
        inv = eng.invoice("globex", "pro", "2026-10", seq=3)
        self.assertEqual(inv.total_cents, 15000)
        li = inv.line_items[0]
        self.assertEqual(li.quantity, 12000)
        self.assertEqual(
            li.breakdown, ((1000, 2, 2000), (8000, 1, 8000), (3000, 0, 0))
        )

    def test_invoice_tier_boundary(self):
        eng = BillingEngine()
        eng.define_tiered_plan("pro", 0, {"api": ((100, 5), (None, 2))}, seq=1)
        eng.record_usage("c", "pro", "api", 100, seq=2)
        inv = eng.invoice("c", "pro", "p", seq=3)
        self.assertEqual(inv.total_cents, 500)
        self.assertEqual(inv.line_items[0].breakdown, ((100, 5, 500),))

    def test_invoice_unknown_plan(self):
        eng = BillingEngine()
        with self.assertRaises(UnknownPlanError):
            eng.invoice("acme", "nope", "2026-10", seq=1)

    def test_invoice_lookup(self):
        eng = BillingEngine()
        eng.define_plan("basic", 0, {"api": 1}, seq=1)
        inv = eng.invoice("acme", "basic", "2026-10", seq=2)
        self.assertEqual(eng.invoice_lookup("inv-1").digest, inv.digest)
        with self.assertRaises(BillingError):
            eng.invoice_lookup("inv-9")


class TestProrate(unittest.TestCase):
    def test_prorate_math(self):
        eng = BillingEngine()
        eng.define_plan("basic", 1000, {"api": 1}, seq=1)
        eng.define_plan("pro", 5000, {"api": 1}, seq=2)
        pr = eng.prorate("acme", "basic", "pro", 0, 100, 40, seq=3)
        self.assertEqual(pr.old_plan_used_cents, 400)
        self.assertEqual(pr.old_plan_credit_cents, 600)
        self.assertEqual(pr.new_plan_charge_cents, 3000)
        self.assertEqual(pr.net_cents, 2400)
        self.assertTrue(pr.digest.startswith("sha256:"))

    def test_prorate_downgrade_credit(self):
        eng = BillingEngine()
        eng.define_plan("pro", 5000, {"api": 1}, seq=1)
        eng.define_plan("basic", 1000, {"api": 1}, seq=2)
        pr = eng.prorate("acme", "pro", "basic", 0, 100, 40, seq=3)
        # old used 2000, credit 3000; new charge 600; net = 600-3000 = -2400
        self.assertEqual(pr.net_cents, -2400)

    def test_prorate_rounding_whole_cent(self):
        eng = BillingEngine()
        eng.define_plan("a", 101, {"m": 1}, seq=1)
        eng.define_plan("b", 0, {"m": 1}, seq=2)
        pr = eng.prorate("c", "a", "b", 0, 3, 1, seq=3)
        # used = round(101*1/3) = 34; credit = 67; new = 0; net = -67
        self.assertEqual(pr.old_plan_used_cents, 34)
        self.assertEqual(pr.old_plan_credit_cents, 67)
        self.assertEqual(pr.net_cents, -67)

    def test_prorate_bad_period(self):
        eng = BillingEngine()
        eng.define_plan("a", 0, {"m": 1}, seq=1)
        eng.define_plan("b", 0, {"m": 1}, seq=2)
        with self.assertRaises(BadPeriodError):
            eng.prorate("c", "a", "b", 50, 100, 100, seq=3)  # switch == end
        with self.assertRaises(BadPeriodError):
            eng.prorate("c", "a", "b", 50, 100, 50, seq=3)  # switch == start
        with self.assertRaises(BadPeriodError):
            eng.prorate("c", "a", "b", 100, 100, 90, seq=3)  # end == start
        with self.assertRaises(UnknownPlanError):
            eng.prorate("c", "nope", "b", 0, 100, 40, seq=3)


class TestViews(unittest.TestCase):
    def test_views(self):
        eng = BillingEngine()
        eng.define_plan("b", 0, {"m": 1}, seq=1)
        eng.define_plan("a", 0, {"m": 1}, seq=2)
        self.assertEqual(eng.plans(), ("a", "b"))
        self.assertEqual(eng.plan("a").plan_id, "a")
        self.assertEqual(eng.uninvoiced_count("x", "a"), 0)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ev = billing_engine_audit_event("invoiced", 1, {"invoice_id": "inv-1"})
        self.assertEqual(ev["version"], "audit.ndjson/1")
        self.assertEqual(ev["schema"], "northstar.billing-engine.v1")
        self.assertEqual(ev["module"], "billing-engine.v1")
        self.assertEqual(ev["kind"], "invoiced")
        ev2 = billing_engine_audit_event("rejected", 2)
        self.assertNotIn("detail", ev2)
        with self.assertRaises(BillingError):
            billing_engine_audit_event("bogus", 1)
        with self.assertRaises(BillingError):
            billing_engine_audit_event("rejected", -1)
        with self.assertRaises(BillingError):
            billing_engine_audit_event("rejected", 1, detail="x")


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        be.main()


if __name__ == "__main__":
    unittest.main()
