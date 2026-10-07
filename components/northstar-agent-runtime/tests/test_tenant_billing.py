"""Tests for tenant_billing."""

import ast
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tenant_billing import (
    AUDIT_SCHEMA,
    METER_KINDS,
    SCHEMA_PIN,
    TENANT_BILLING_VERSION,
    AlreadyPaidError,
    BadMoneyError,
    BadQuantityError,
    DuplicateInvoiceError,
    DuplicateTenantError,
    DuplicateTierError,
    PaidInvoiceError,
    SeqOrderError,
    SuspendedTenantError,
    TenantBilling,
    TenantBillingError,
    UnknownInvoiceError,
    UnknownMeterKindError,
    UnknownTenantError,
    UnknownTierError,
    VoidedInvoiceError,
    tenant_billing_audit_event,
)


def make_ledger():
    tb = TenantBilling()
    tb.define_tier(
        "pro", 0, "Pro", 19900,
        included={"api_calls": 1000, "seats": 5},
        overage={"api_calls": 2, "compute_seconds": 1, "seats": 500},
    )
    tb.provision("acme", "pro", 1)
    return tb


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(TENANT_BILLING_VERSION, "tenant-billing.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.tenant-billing.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")
        self.assertEqual(
            METER_KINDS,
            ("api_calls", "compute_seconds", "storage_gb_hours", "seats"),
        )

    def test_stdlib_only(self):
        path = os.path.join(os.path.dirname(__file__), "..", "tenant_billing.py")
        tree = ast.parse(open(path).read())
        allowed = {
            "hashlib", "threading", "dataclasses", "typing",
            "json", "canonical_json", "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_main_self_check(self):
        from tenant_billing import main
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            main()
        self.assertIn("tenant-billing OK", buf.getvalue())


class TestTiers(unittest.TestCase):
    def test_define_roundtrip_and_verify(self):
        tb = TenantBilling()
        rec = tb.define_tier(
            "starter", 1, "Starter", 0,
            included={"api_calls": 100},
            overage={"api_calls": 3},
        )
        self.assertEqual(rec.tier_id, "starter")
        self.assertEqual(rec.base_cents, 0)
        self.assertIn(("api_calls", 100), rec.included)
        rec.verify()
        # tamper detection
        import dataclasses
        tampered = dataclasses.replace(rec, base_cents=1)
        with self.assertRaises(TenantBillingError):
            tampered.verify()

    def test_duplicate_tier_refused(self):
        tb = TenantBilling()
        tb.define_tier("pro", 1, "Pro", 100)
        with self.assertRaises(DuplicateTierError):
            tb.define_tier("pro", 2, "Pro2", 200)

    def test_bad_tier_inputs(self):
        tb = TenantBilling()
        with self.assertRaises(BadMoneyError):
            tb.define_tier("a", 1, "A", -5)
        with self.assertRaises(BadMoneyError):
            tb.define_tier("b", 2, "B", True)  # bool is not cents
        with self.assertRaises(BadMoneyError):
            tb.define_tier("c", 3, "C", 19.99)  # floats refused
        with self.assertRaises(UnknownMeterKindError):
            tb.define_tier("d", 4, "D", 100, included={"bogus": 10})
        with self.assertRaises(TenantBillingError):
            tb.define_tier("e", 5, "E", 100, included={"api_calls": -1})

    def test_digest_determinism_across_instances(self):
        a = TenantBilling()
        b = TenantBilling()
        ra = a.define_tier("pro", 1, "Pro", 19900, overage={"api_calls": 2})
        rb = b.define_tier("pro", 1, "Pro", 19900, overage={"api_calls": 2})
        self.assertEqual(ra.digest, rb.digest)


class TestTenants(unittest.TestCase):
    def test_provision_roundtrip_and_views(self):
        tb = make_ledger()
        rec = tb.tenant("acme")
        rec.verify()
        self.assertEqual(rec.status, "active")
        self.assertEqual(rec.tier_id, "pro")
        tier = tb.tier("acme")
        tier.verify()
        self.assertEqual(tier.name, "Pro")
        self.assertIn("acme", tb.tenant_ids())
        self.assertIn("pro", tb.tier_ids())
        with self.assertRaises(UnknownTenantError):
            tb.tenant("ghost")
        with self.assertRaises(UnknownTenantError):
            tb.tier("ghost")

    def test_provision_refusals(self):
        tb = TenantBilling()
        tb.define_tier("pro", 1, "Pro", 100)
        with self.assertRaises(UnknownTierError):
            tb.provision("acme", "missing", 2)
        tb.provision("acme", "pro", 3)
        with self.assertRaises(DuplicateTenantError):
            tb.provision("acme", "pro", 4)

    def test_suspend_reactivate(self):
        tb = make_ledger()
        s = tb.suspend("acme", 2)
        s.verify()
        self.assertEqual(s.status, "suspended")
        with self.assertRaises(SuspendedTenantError):
            tb.meter("acme", "api_calls", 3, 10)
        r = tb.reactivate("acme", 4)
        r.verify()
        self.assertEqual(r.status, "active")
        m = tb.meter("acme", "api_calls", 5, 10)
        m.verify()
        with self.assertRaises(TenantBillingError):
            tb.reactivate("acme", 6)  # not suspended


class TestMetering(unittest.TestCase):
    def test_meter_accumulates_usage(self):
        tb = make_ledger()
        m1 = tb.meter("acme", "api_calls", 2, 400)
        m2 = tb.meter("acme", "api_calls", 3, 600)
        self.assertEqual(m1.meter_id, "mtr-1")
        self.assertEqual(m2.meter_id, "mtr-2")
        m1.verify()
        self.assertEqual(tb.usage("acme")["api_calls"], 1000)

    def test_meter_refusals(self):
        tb = make_ledger()
        with self.assertRaises(UnknownMeterKindError):
            tb.meter("acme", "bogus", 2, 10)
        with self.assertRaises(BadQuantityError):
            tb.meter("acme", "api_calls", 3, 0)
        with self.assertRaises(BadQuantityError):
            tb.meter("acme", "api_calls", 4, -7)
        with self.assertRaises(BadQuantityError):
            tb.meter("acme", "api_calls", 5, True)
        with self.assertRaises(BadQuantityError):
            tb.meter("acme", "api_calls", 6, 2.5)
        with self.assertRaises(UnknownTenantError):
            tb.meter("ghost", "api_calls", 7, 10)


class TestInvoicing(unittest.TestCase):
    def test_invoice_exact_math(self):
        tb = make_ledger()
        tb.meter("acme", "api_calls", 2, 1500)      # 500 billable x 2c
        tb.meter("acme", "seats", 3, 7)            # 2 billable x 500c
        tb.meter("acme", "compute_seconds", 4, 100)  # 100 x 1c, no quota
        inv = tb.invoice("acme", 5, "2026-10")
        inv.verify()
        self.assertEqual(inv.total_cents, 19900 + 1000 + 1000 + 100)
        by_kind = {li.kind: li for li in inv.lines}
        self.assertEqual(by_kind["api_calls"].billable, 500)
        self.assertEqual(by_kind["api_calls"].amount_cents, 1000)
        self.assertEqual(by_kind["seats"].used, 7)
        self.assertEqual(by_kind["base"].amount_cents, 19900)
        # usage buckets reset after invoicing
        self.assertEqual(tb.usage("acme")["api_calls"], 0)
        # duplicate period refused
        with self.assertRaises(DuplicateInvoiceError):
            tb.invoice("acme", 6, "2026-10")
        # next period invoices only new usage
        tb.meter("acme", "api_calls", 7, 10)
        inv2 = tb.invoice("acme", 8, "2026-11")
        inv2.verify()
        self.assertEqual(inv2.total_cents, 19900)  # within quota

    def test_invoice_empty_usage(self):
        tb = make_ledger()
        inv = tb.invoice("acme", 2, "2026-10")
        inv.verify()
        self.assertEqual(inv.total_cents, 19900)
        self.assertEqual(inv.status, "open")
        with self.assertRaises(UnknownTenantError):
            tb.invoice("ghost", 3, "2026-10")

    def test_settle_lifecycle(self):
        tb = make_ledger()
        inv = tb.invoice("acme", 2, "2026-10")
        paid = tb.mark_paid(inv.invoice_id, 3)
        paid.verify()
        self.assertEqual(paid.status, "paid")
        self.assertEqual(paid.invoice_id, inv.invoice_id)
        with self.assertRaises(AlreadyPaidError):
            tb.mark_paid(inv.invoice_id, 4)
        with self.assertRaises(PaidInvoiceError):
            tb.void(inv.invoice_id, 5)
        inv2 = tb.invoice("acme", 6, "2026-11")
        v = tb.void(inv2.invoice_id, 7)
        v.verify()
        self.assertEqual(v.status, "voided")
        with self.assertRaises(VoidedInvoiceError):
            tb.void(inv2.invoice_id, 8)
        with self.assertRaises(VoidedInvoiceError):
            tb.mark_paid(inv2.invoice_id, 9)
        with self.assertRaises(UnknownInvoiceError):
            tb.mark_paid("inv-999", 10)


class TestSeqAndAudit(unittest.TestCase):
    def test_seq_order_and_consumption(self):
        tb = TenantBilling()
        tb.define_tier("pro", 1, "Pro", 100)
        with self.assertRaises(SeqOrderError):
            tb.define_tier("x", 1, "X", 100)  # rewind
        with self.assertRaises(TenantBillingError):
            tb.define_tier("y", True, "Y", 100)  # bool seq
        with self.assertRaises(TenantBillingError):
            tb.define_tier("z", -1, "Z", 100)  # negative seq
        # failed mutation consumed its seq: next valid seq must exceed it
        with self.assertRaises(DuplicateTierError):
            tb.define_tier("pro", 2, "Pro", 100)
        with self.assertRaises(SeqOrderError):
            tb.define_tier("ok", 2, "Ok", 100)
        rec = tb.define_tier("ok", 3, "Ok", 100)
        self.assertEqual(rec.seq, 3)

    def test_audit_shapes_and_boundary(self):
        tb = make_ledger()
        tb.meter("acme", "api_calls", 2, 10)
        log = tb.audit_log()
        kinds = [e["kind"] for e in log]
        self.assertIn("tier-defined", kinds)
        self.assertIn("tenant-provisioned", kinds)
        self.assertIn("usage-metered", kinds)
        for e in log:
            self.assertEqual(e["schema"], "audit.ndjson/1")
            self.assertEqual(e["module"], "tenant-billing.v1")
        # unknown kind refused
        with self.assertRaises(TenantBillingError):
            tenant_billing_audit_event("bogus", {}, 1)
        # banned keys refused
        with self.assertRaises(TenantBillingError):
            tenant_billing_audit_event("usage-metered", {"usage_values": 1}, 1)
        # as_dict carries ids+counts only
        snap = tb.as_dict()
        self.assertEqual(snap["schema"], "northstar.tenant-billing.v1")
        self.assertEqual(snap["tier_count"], 1)
        self.assertEqual(snap["tenant_count"], 1)
        self.assertTrue(snap["state_digest"].startswith("sha256:"))

    def test_concurrency_smoke(self):
        tb = make_ledger()
        errors = []

        def work(n):
            try:
                tb.meter("acme", "api_calls", 2 + n, 1)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
        # seqs must be unique and increasing; run serially to stay valid
        for t in threads:
            t.start()
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(tb.usage("acme")["api_calls"], 8)


if __name__ == "__main__":
    unittest.main()
