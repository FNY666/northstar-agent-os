"""Tests for hyperloglog.py."""

import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hyperloglog import (  # noqa: E402
    HYPERLOGLOG_VERSION,
    SCHEMA_PIN,
    CardinalityReport,
    HyperLogLog,
    hyperloglog_audit_event,
)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(HYPERLOGLOG_VERSION, "hyperloglog.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.hyperloglog.v1")


class TestConstructor(unittest.TestCase):
    def test_default_precision(self):
        hll = HyperLogLog()
        self.assertEqual(hll.precision, 10)
        self.assertEqual(hll.register_count, 1024)

    def test_min_precision(self):
        hll = HyperLogLog(4)
        self.assertEqual(hll.register_count, 16)

    def test_max_precision(self):
        hll = HyperLogLog(16)
        self.assertEqual(hll.register_count, 65536)

    def test_precision_too_small(self):
        with self.assertRaises(ValueError):
            HyperLogLog(3)

    def test_precision_too_large(self):
        with self.assertRaises(ValueError):
            HyperLogLog(17)

    def test_precision_zero(self):
        with self.assertRaises(ValueError):
            HyperLogLog(0)

    def test_precision_negative(self):
        with self.assertRaises(ValueError):
            HyperLogLog(-1)

    def test_precision_bool_rejected(self):
        with self.assertRaises(TypeError):
            HyperLogLog(True)

    def test_precision_str_rejected(self):
        with self.assertRaises(TypeError):
            HyperLogLog("10")

    def test_precision_float_rejected(self):
        with self.assertRaises(TypeError):
            HyperLogLog(10.0)


class TestAdd(unittest.TestCase):
    def test_add_str(self):
        hll = HyperLogLog()
        hll.add("hello")
        self.assertGreater(hll.count(), 0.0)

    def test_add_bytes(self):
        hll = HyperLogLog()
        hll.add(b"hello")
        self.assertGreater(hll.count(), 0.0)

    def test_add_empty_str(self):
        hll = HyperLogLog()
        hll.add("")
        self.assertAlmostEqual(hll.count(), 1.0, delta=0.6)

    def test_add_int_rejected(self):
        hll = HyperLogLog()
        with self.assertRaises(TypeError):
            hll.add(42)

    def test_add_none_rejected(self):
        hll = HyperLogLog()
        with self.assertRaises(TypeError):
            hll.add(None)

    def test_add_list_rejected(self):
        hll = HyperLogLog()
        with self.assertRaises(TypeError):
            hll.add(["a"])

    def test_empty_count_zero(self):
        hll = HyperLogLog()
        self.assertEqual(hll.count(), 0.0)


class TestAccuracy(unittest.TestCase):
    def test_small_cardinality_linear_counting(self):
        hll = HyperLogLog(precision=10)
        for i in range(5):
            hll.add(f"item-{i}")
        self.assertAlmostEqual(hll.count(), 5.0, delta=0.6)

    def test_medium_cardinality_in_band(self):
        hll = HyperLogLog(precision=14)
        n = 20000
        for i in range(n):
            hll.add(f"user-{i}")
        est = hll.count()
        # Relative std error at p=14 is ~0.81%; 5% band is very safe.
        self.assertGreaterEqual(est, n * 0.95)
        self.assertLessEqual(est, n * 1.05)

    def test_duplicates_do_not_inflate(self):
        hll = HyperLogLog(precision=12)
        for _ in range(100):
            for i in range(100):
                hll.add(f"dup-{i}")
        self.assertAlmostEqual(hll.count(), 100.0, delta=15.0)

    def test_order_independent(self):
        items = [f"k-{i}" for i in range(500)]
        a = HyperLogLog(precision=12)
        b = HyperLogLog(precision=12)
        for item in items:
            a.add(item)
        for item in reversed(items):
            b.add(item)
        self.assertEqual(a.count(), b.count())

    def test_deterministic(self):
        a = HyperLogLog(precision=10)
        b = HyperLogLog(precision=10)
        for i in range(300):
            a.add(f"x-{i}")
            b.add(f"x-{i}")
        self.assertEqual(a._registers, b._registers)


class TestMerge(unittest.TestCase):
    def test_merge_is_union(self):
        a = HyperLogLog(precision=12)
        b = HyperLogLog(precision=12)
        for i in range(500):
            a.add(f"u-{i}")
        for i in range(500, 1000):
            b.add(f"u-{i}")
        a.merge(b)
        self.assertAlmostEqual(a.count(), 1000.0, delta=60.0)

    def test_merge_overlapping(self):
        a = HyperLogLog(precision=12)
        b = HyperLogLog(precision=12)
        for i in range(1000):
            a.add(f"u-{i}")
        for i in range(500, 1500):
            b.add(f"u-{i}")
        a.merge(b)
        self.assertAlmostEqual(a.count(), 1500.0, delta=90.0)

    def test_merge_non_hll_rejected(self):
        hll = HyperLogLog()
        with self.assertRaises(TypeError):
            hll.merge("not-a-sketch")

    def test_merge_precision_mismatch_rejected(self):
        a = HyperLogLog(precision=10)
        b = HyperLogLog(precision=12)
        with self.assertRaises(ValueError):
            a.merge(b)


class TestReport(unittest.TestCase):
    def test_report_shape(self):
        hll = HyperLogLog(precision=10)
        for i in range(100):
            hll.add(f"r-{i}")
        rep = hll.report()
        self.assertIsInstance(rep, CardinalityReport)
        self.assertEqual(rep.precision, 10)
        self.assertEqual(rep.registers_total, 1024)
        self.assertGreater(rep.registers_used, 0)
        self.assertLessEqual(rep.registers_used, 1024)
        self.assertAlmostEqual(rep.relative_error, 1.04 / math.sqrt(1024))
        self.assertEqual(rep.schema, SCHEMA_PIN)

    def test_report_frozen(self):
        hll = HyperLogLog()
        rep = hll.report()
        with self.assertRaises(Exception):
            rep.estimate = 5.0  # type: ignore

    def test_report_as_dict(self):
        hll = HyperLogLog()
        d = hll.report().as_dict()
        self.assertEqual(
            set(d),
            {
                "estimate",
                "precision",
                "registers_used",
                "registers_total",
                "relative_error",
                "schema",
            },
        )

    def test_report_bad_estimate_rejected(self):
        with self.assertRaises(ValueError):
            CardinalityReport(
                estimate=float("nan"),
                precision=10,
                registers_used=0,
                registers_total=1024,
                relative_error=0.03,
            )

    def test_report_negative_estimate_rejected(self):
        with self.assertRaises(ValueError):
            CardinalityReport(
                estimate=-1.0,
                precision=10,
                registers_used=0,
                registers_total=1024,
                relative_error=0.03,
            )

    def test_report_registers_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            CardinalityReport(
                estimate=1.0,
                precision=10,
                registers_used=0,
                registers_total=999,
                relative_error=0.03,
            )

    def test_report_bad_relative_error_rejected(self):
        with self.assertRaises(ValueError):
            CardinalityReport(
                estimate=1.0,
                precision=10,
                registers_used=0,
                registers_total=1024,
                relative_error=0.0,
            )


class TestAuditEvent(unittest.TestCase):
    def test_audit_event_shape(self):
        hll = HyperLogLog()
        hll.add("audit-me")
        rep = hll.report()
        evt = hyperloglog_audit_event(rep, audit_seq=7)
        self.assertEqual(evt["audit_seq"], 7)
        self.assertEqual(evt["schema"], SCHEMA_PIN)
        self.assertIn("estimate", evt)

    def test_audit_event_bad_seq_rejected(self):
        hll = HyperLogLog()
        rep = hll.report()
        with self.assertRaises(TypeError):
            hyperloglog_audit_event(rep, audit_seq=True)
        with self.assertRaises(ValueError):
            hyperloglog_audit_event(rep, audit_seq=-1)

    def test_audit_event_wrong_type_rejected(self):
        with self.assertRaises(TypeError):
            hyperloglog_audit_event("not-a-report", audit_seq=0)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import hyperloglog

        self.assertIsNone(hyperloglog.main())


if __name__ == "__main__":
    unittest.main()
