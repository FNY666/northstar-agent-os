"""Tests for bulkhead.py: per-tenant fault isolation."""

import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bulkhead import (
    ALLOW,
    BULKHEAD_SCHEMA,
    BULKHEAD_VERSION,
    CALL_QUOTA,
    CONCURRENCY_LIMIT,
    COST_QUOTA,
    DENY,
    UNKNOWN_TENANT,
    Bulkhead,
    BulkheadDecision,
    BulkheadError,
    TenantPartition,
    TenantUsage,
    bulkhead_audit_event,
)


def make_bulkhead() -> Bulkhead:
    return Bulkhead(
        [
            TenantPartition("a", max_concurrent=2, max_calls=3, max_cost_usd=1.0),
            TenantPartition("b", max_concurrent=1),
        ]
    )


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(BULKHEAD_VERSION, "bulkhead.v1")
        self.assertEqual(BULKHEAD_SCHEMA, "northstar.bulkhead.v1")


class TestPartitionValidation(unittest.TestCase):
    def test_empty_tenant_id_rejected(self):
        with self.assertRaises(BulkheadError):
            TenantPartition("", max_concurrent=1)

    def test_zero_concurrency_rejected(self):
        with self.assertRaises(ValueError):
            TenantPartition("t", max_concurrent=0)

    def test_bool_concurrency_rejected(self):
        with self.assertRaises(TypeError):
            TenantPartition("t", max_concurrent=True)

    def test_negative_quota_rejected(self):
        with self.assertRaises(ValueError):
            TenantPartition("t", max_concurrent=1, max_calls=-1)

    def test_frozen(self):
        part = TenantPartition("t", max_concurrent=1)
        with self.assertRaises(Exception):
            part.max_concurrent = 5  # type: ignore[misc]


class TestAdmission(unittest.TestCase):
    def test_happy_path(self):
        bh = make_bulkhead()
        decision, result = bh.execute("a", lambda: "ok", seq=0)
        self.assertEqual(decision.verdict, ALLOW)
        self.assertIsNone(decision.reason)
        self.assertEqual(result, "ok")

    def test_unknown_tenant_denied(self):
        bh = make_bulkhead()
        decision, result = bh.execute("ghost", lambda: "x", seq=0)
        self.assertEqual(decision.verdict, DENY)
        self.assertEqual(decision.reason, UNKNOWN_TENANT)
        self.assertIsNone(result)

    def test_concurrency_limit_fail_fast(self):
        bh = make_bulkhead()
        entered = threading.Event()
        release = threading.Event()

        def hold():
            entered.set()
            release.wait(timeout=10)
            return "held"

        t = threading.Thread(target=lambda: bh.execute("b", hold, seq=0))
        t.start()
        entered.wait(timeout=10)
        # b has max_concurrent=1; second call refused immediately, no queue.
        decision, result = bh.execute("b", lambda: "x", seq=1)
        self.assertEqual(decision.verdict, DENY)
        self.assertEqual(decision.reason, CONCURRENCY_LIMIT)
        self.assertIsNone(result)
        release.set()
        t.join(timeout=10)
        self.assertFalse(t.is_alive())

    def test_call_quota(self):
        bh = make_bulkhead()
        for i in range(3):
            decision, _ = bh.execute("a", lambda: i, seq=i)
            self.assertEqual(decision.verdict, ALLOW)
        decision, result = bh.execute("a", lambda: "x", seq=3)
        self.assertEqual(decision.verdict, DENY)
        self.assertEqual(decision.reason, CALL_QUOTA)
        self.assertIsNone(result)

    def test_cost_quota(self):
        bh = make_bulkhead()
        decision, _ = bh.execute("a", lambda: 1, seq=0, cost_usd=0.9)
        self.assertEqual(decision.verdict, ALLOW)
        decision, result = bh.execute("a", lambda: 2, seq=1, cost_usd=0.2)
        self.assertEqual(decision.verdict, DENY)
        self.assertEqual(decision.reason, COST_QUOTA)
        self.assertIsNone(result)

    def test_cost_exactly_at_quota_allowed(self):
        bh = make_bulkhead()
        decision, _ = bh.execute("a", lambda: 1, seq=0, cost_usd=1.0)
        self.assertEqual(decision.verdict, ALLOW)

    def test_refusal_charges_nothing(self):
        bh = make_bulkhead()
        bh.execute("a", lambda: 1, seq=0, cost_usd=0.9)
        bh.execute("a", lambda: 2, seq=1, cost_usd=0.2)  # denied
        usage = bh.usage("a")
        self.assertEqual(usage.calls_used, 1)
        self.assertAlmostEqual(usage.cost_used_usd, 0.9)


class TestIsolation(unittest.TestCase):
    def test_one_tenant_saturated_other_unaffected(self):
        bh = make_bulkhead()
        # Exhaust a's call quota entirely.
        for i in range(3):
            bh.execute("a", lambda: i, seq=i)
        denied, _ = bh.execute("a", lambda: "x", seq=3)
        self.assertEqual(denied.verdict, DENY)
        # b is fully unaffected.
        ok, result = bh.execute("b", lambda: "fine", seq=4)
        self.assertEqual(ok.verdict, ALLOW)
        self.assertEqual(result, "fine")

    def test_failure_isolated_and_slot_released(self):
        bh = make_bulkhead()

        def boom():
            raise RuntimeError("tenant failure")

        with self.assertRaises(RuntimeError):
            bh.execute("a", boom, seq=0)
        usage = bh.usage("a")
        self.assertEqual(usage.failures, 1)
        self.assertEqual(usage.in_flight, 0)
        # Slot was released: a fresh call is admitted.
        decision, result = bh.execute("a", lambda: "again", seq=1)
        self.assertEqual(decision.verdict, ALLOW)
        self.assertEqual(result, "again")

    def test_non_callable_rejected(self):
        bh = make_bulkhead()
        with self.assertRaises(TypeError):
            bh.execute("a", "not-callable", seq=0)  # type: ignore[arg-type]

    def test_bad_cost_types(self):
        bh = make_bulkhead()
        with self.assertRaises(TypeError):
            bh.execute("a", lambda: 1, seq=0, cost_usd=True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            bh.execute("a", lambda: 1, seq=0, cost_usd=-0.5)


class TestManagement(unittest.TestCase):
    def test_add_partition(self):
        bh = make_bulkhead()
        bh.add_partition(TenantPartition("c", max_concurrent=1))
        self.assertIn("c", bh.tenants())
        decision, _ = bh.execute("c", lambda: 1, seq=0)
        self.assertEqual(decision.verdict, ALLOW)

    def test_add_duplicate_rejected(self):
        bh = make_bulkhead()
        with self.assertRaises(BulkheadError):
            bh.add_partition(TenantPartition("a", max_concurrent=5))

    def test_remove_partition(self):
        bh = make_bulkhead()
        bh.remove_partition("b")
        self.assertNotIn("b", bh.tenants())
        decision, _ = bh.execute("b", lambda: 1, seq=0)
        self.assertEqual(decision.reason, UNKNOWN_TENANT)

    def test_remove_while_in_flight_rejected(self):
        bh = make_bulkhead()
        entered = threading.Event()
        release = threading.Event()

        def hold():
            entered.set()
            release.wait(timeout=10)

        t = threading.Thread(target=lambda: bh.execute("b", hold, seq=0))
        t.start()
        entered.wait(timeout=10)
        with self.assertRaises(BulkheadError):
            bh.remove_partition("b")
        release.set()
        t.join(timeout=10)


class TestRecords(unittest.TestCase):
    def test_decision_shape(self):
        d = BulkheadDecision("a", ALLOW, None, 7)
        record = d.as_dict()
        self.assertEqual(record["schema"], BULKHEAD_SCHEMA)
        self.assertEqual(record["seq"], 7)

    def test_decision_invariants(self):
        with self.assertRaises(BulkheadError):
            BulkheadDecision("a", ALLOW, "some-reason", 0)
        with self.assertRaises(BulkheadError):
            BulkheadDecision("a", DENY, None, 0)
        with self.assertRaises(BulkheadError):
            BulkheadDecision("a", "maybe", None, 0)

    def test_usage_snapshot(self):
        bh = make_bulkhead()
        bh.execute("a", lambda: 1, seq=0, cost_usd=0.25)
        usage = bh.usage("a")
        self.assertIsInstance(usage, TenantUsage)
        self.assertEqual(usage.calls_used, 1)
        self.assertAlmostEqual(usage.cost_used_usd, 0.25)
        self.assertEqual(usage.in_flight, 0)

    def test_audit_event_shape(self):
        d = BulkheadDecision("a", DENY, CALL_QUOTA, 2)
        event = bulkhead_audit_event(d, audit_seq=9)
        self.assertEqual(event["audit_seq"], 9)
        self.assertEqual(event["reason"], CALL_QUOTA)
        with self.assertRaises(TypeError):
            bulkhead_audit_event("nope", audit_seq=0)  # type: ignore[arg-type]

    def test_admit_is_check_only(self):
        bh = make_bulkhead()
        decision = bh.admit("a", seq=0, cost_usd=5.0)
        self.assertEqual(decision.reason, COST_QUOTA)
        usage = bh.usage("a")
        self.assertEqual(usage.calls_used, 0)  # admit reserves nothing

    def test_main_self_check(self):
        import bulkhead as mod

        mod.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
