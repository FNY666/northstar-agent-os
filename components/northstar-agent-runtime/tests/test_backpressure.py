"""Tests for backpressure.py (15 required)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backpressure import (  # noqa: E402
    BACKPRESSURE_VERSION,
    SCHEMA_PIN,
    Backpressure,
    BackpressureError,
    BackpressureOverflowError,
    BackpressureRecord,
    backpressure_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(BACKPRESSURE_VERSION, "backpressure.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.backpressure.v1")


class TestRequest(unittest.TestCase):
    def test_initial_demand_zero(self):
        bp = Backpressure()
        self.assertEqual(bp.demand, 0)
        self.assertEqual(bp.delivered, 0)
        self.assertFalse(bp.cancelled)

    def test_request_adds_demand(self):
        bp = Backpressure()
        self.assertEqual(bp.request(5), 5)
        self.assertEqual(bp.request(3), 8)

    def test_request_rejects_non_positive(self):
        bp = Backpressure()
        for bad in (0, -1, -100):
            with self.assertRaises(BackpressureError, msg=f"n={bad!r}"):
                bp.request(bad)
        self.assertEqual(bp.demand, 0)  # no partial state change

    def test_request_rejects_non_int(self):
        bp = Backpressure()
        for bad in (True, 1.5, "3", None, [3]):
            with self.assertRaises(BackpressureError, msg=f"n={bad!r}"):
                bp.request(bad)

    def test_request_saturates_at_max(self):
        bp = Backpressure()
        self.assertEqual(bp.request(Backpressure.UNBOUNDED), Backpressure.MAX_DEMAND)
        self.assertEqual(bp.request(Backpressure.UNBOUNDED), Backpressure.MAX_DEMAND)
        self.assertEqual(bp.demand, Backpressure.MAX_DEMAND)


class TestOnNext(unittest.TestCase):
    def test_on_next_consumes_demand(self):
        bp = Backpressure()
        bp.request(3)
        self.assertEqual(bp.on_next(), 2)
        self.assertEqual(bp.on_next(), 1)
        self.assertEqual(bp.on_next(), 0)
        self.assertEqual(bp.delivered, 3)

    def test_on_next_overflow_raises(self):
        bp = Backpressure()
        with self.assertRaises(BackpressureOverflowError):
            bp.on_next()
        self.assertEqual(bp.overflows, 1)
        self.assertEqual(bp.delivered, 0)

    def test_on_next_partial_flow_then_replenish(self):
        bp = Backpressure()
        bp.request(2)
        bp.on_next()
        bp.on_next()
        with self.assertRaises(BackpressureOverflowError):
            bp.on_next()
        self.assertEqual(bp.request(1), 1)
        self.assertEqual(bp.on_next(), 0)
        self.assertEqual(bp.delivered, 3)


class TestCancel(unittest.TestCase):
    def test_cancel_clears_demand(self):
        bp = Backpressure()
        bp.request(10)
        bp.cancel()
        self.assertTrue(bp.cancelled)
        self.assertEqual(bp.demand, 0)
        self.assertEqual(bp.delivered, 0)

    def test_cancel_idempotent(self):
        bp = Backpressure()
        bp.cancel()
        bp.cancel()
        self.assertTrue(bp.cancelled)

    def test_request_after_cancel_raises(self):
        bp = Backpressure()
        bp.cancel()
        with self.assertRaises(BackpressureError):
            bp.request(1)
        self.assertEqual(bp.demand, 0)

    def test_on_next_after_cancel_raises(self):
        bp = Backpressure()
        bp.request(5)
        bp.cancel()
        with self.assertRaises(BackpressureError):
            bp.on_next()
        self.assertEqual(bp.delivered, 0)


class TestRecords(unittest.TestCase):
    def test_snapshot_frozen(self):
        bp = Backpressure()
        bp.request(4)
        bp.on_next()
        snap = bp.snapshot()
        self.assertIsInstance(snap, BackpressureRecord)
        self.assertEqual((snap.demand, snap.delivered, snap.cancelled, snap.overflows),
                         (3, 1, False, 0))
        with self.assertRaises(AttributeError):
            snap.demand = 9  # type: ignore

    def test_audit_event_shape(self):
        bp = Backpressure()
        bp.request(2)
        event = backpressure_audit_event(7, bp.snapshot())
        self.assertEqual(event["audit_seq"], 7)
        self.assertEqual(event["event"], "backpressure")
        self.assertEqual(event["schema"], SCHEMA_PIN)
        self.assertEqual(event["demand"], 2)


if __name__ == "__main__":
    unittest.main()
