"""Tests for watermark_tracker: event-time watermark tracking."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import watermark_tracker
from watermark_tracker import (
    AUDIT_ADVANCED,
    AUDIT_LATE,
    AUDIT_OBSERVED,
    SCHEMA_PIN,
    STATUS_LATE,
    STATUS_ON_TIME,
    STATUS_TOO_LATE,
    WATERMARK_TRACKER_VERSION,
    LatenessReport,
    WatermarkError,
    WatermarkTracker,
    WatermarkUpdate,
    watermark_tracker_audit_event,
)


class TestWatermarkTracker(unittest.TestCase):
    def test_version_and_schema_pins(self) -> None:
        self.assertEqual(WATERMARK_TRACKER_VERSION, "watermark-tracker.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.watermark-tracker.v1")

    def test_no_watermark_before_events(self) -> None:
        tracker = WatermarkTracker()
        self.assertIsNone(tracker.current())
        self.assertIsNone(tracker.max_event_time())
        self.assertEqual(tracker.event_count(), 0)

    def test_zero_out_of_orderness_first_event(self) -> None:
        tracker = WatermarkTracker()
        update = tracker.update(1_000)
        self.assertTrue(update.advanced)
        self.assertIsNone(update.previous_watermark)
        self.assertEqual(update.watermark, 1_000)
        self.assertEqual(tracker.current(), 1_000)

    def test_out_of_orderness_lag(self) -> None:
        tracker = WatermarkTracker(max_out_of_orderness_ms=250)
        update = tracker.update(1_000)
        self.assertEqual(update.watermark, 750)

    def test_watermark_none_until_bound_covered(self) -> None:
        tracker = WatermarkTracker(max_out_of_orderness_ms=500)
        update = tracker.update(300)
        self.assertIsNone(update.watermark)
        self.assertIsNone(tracker.current())
        update = tracker.update(600)
        self.assertEqual(update.watermark, 100)

    def test_watermark_monotonic_late_event_no_regress(self) -> None:
        tracker = WatermarkTracker()
        tracker.update(5_000)
        update = tracker.update(1_000)  # late arrival
        self.assertFalse(update.advanced)
        self.assertEqual(tracker.current(), 5_000)
        self.assertEqual(update.previous_watermark, 5_000)
        self.assertEqual(tracker.max_event_time(), 5_000)

    def test_max_seen_only_grows(self) -> None:
        tracker = WatermarkTracker()
        tracker.update(10)
        tracker.update(20)
        tracker.update(15)
        self.assertEqual(tracker.max_event_time(), 20)
        self.assertEqual(tracker.event_count(), 3)

    def test_lateness_requires_watermark(self) -> None:
        tracker = WatermarkTracker(max_out_of_orderness_ms=1_000)
        tracker.update(100)
        with self.assertRaises(WatermarkError):
            tracker.lateness(50)

    def test_lateness_on_time(self) -> None:
        tracker = WatermarkTracker()
        tracker.update(1_000)
        report = tracker.lateness(1_000)
        self.assertEqual(report.status, STATUS_ON_TIME)
        self.assertEqual(report.lateness_ms, 0)
        report = tracker.lateness(1_200)
        self.assertEqual(report.status, STATUS_ON_TIME)
        self.assertEqual(tracker.late_count(), 0)

    def test_lateness_late(self) -> None:
        tracker = WatermarkTracker(allowed_lateness_ms=200)
        tracker.update(1_000)
        report = tracker.lateness(850)
        self.assertEqual(report.status, STATUS_LATE)
        self.assertEqual(report.lateness_ms, 150)
        self.assertEqual(tracker.late_count(), 1)

    def test_lateness_too_late(self) -> None:
        tracker = WatermarkTracker(allowed_lateness_ms=200)
        tracker.update(1_000)
        report = tracker.lateness(700)
        self.assertEqual(report.status, STATUS_TOO_LATE)
        self.assertEqual(report.lateness_ms, 300)
        self.assertEqual(tracker.too_late_count(), 1)

    def test_lateness_boundary(self) -> None:
        tracker = WatermarkTracker(allowed_lateness_ms=200)
        tracker.update(1_000)
        # Exactly at watermark - allowed: still late, not too-late.
        report = tracker.lateness(800)
        self.assertEqual(report.status, STATUS_LATE)
        report = tracker.lateness(799)
        self.assertEqual(report.status, STATUS_TOO_LATE)

    def test_lateness_report_frozen_and_dict(self) -> None:
        tracker = WatermarkTracker(allowed_lateness_ms=200)
        tracker.update(1_000)
        report = tracker.lateness(900)
        with self.assertRaises(AttributeError):
            report.status = STATUS_ON_TIME  # type: ignore[misc]
        as_dict = report.as_dict()
        self.assertEqual(as_dict["schema"], SCHEMA_PIN)
        self.assertEqual(as_dict["status"], STATUS_LATE)
        self.assertEqual(as_dict["watermark"], 1_000)
        self.assertEqual(as_dict["lateness_ms"], 100)

    def test_update_record_frozen_and_dict(self) -> None:
        tracker = WatermarkTracker()
        update = tracker.update(1_000)
        with self.assertRaises(AttributeError):
            update.watermark = 2_000  # type: ignore[misc]
        as_dict = update.as_dict()
        self.assertEqual(as_dict["schema"], SCHEMA_PIN)
        self.assertEqual(as_dict["event_time"], 1_000)
        self.assertTrue(as_dict["advanced"])

    def test_constructor_validation(self) -> None:
        with self.assertRaises(TypeError):
            WatermarkTracker(max_out_of_orderness_ms=True)
        with self.assertRaises(ValueError):
            WatermarkTracker(max_out_of_orderness_ms=-1)
        with self.assertRaises(TypeError):
            WatermarkTracker(allowed_lateness_ms="100")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            WatermarkTracker(allowed_lateness_ms=-5)

    def test_update_validation(self) -> None:
        tracker = WatermarkTracker()
        with self.assertRaises(TypeError):
            tracker.update(True)
        with self.assertRaises(TypeError):
            tracker.update("1000")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            tracker.update(-1)

    def test_lateness_validation(self) -> None:
        tracker = WatermarkTracker()
        tracker.update(1_000)
        with self.assertRaises(TypeError):
            tracker.lateness(1.5)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            tracker.lateness(-10)

    def test_bounds_view(self) -> None:
        tracker = WatermarkTracker(max_out_of_orderness_ms=300, allowed_lateness_ms=60)
        self.assertEqual(tracker.bounds(), (300, 60))

    def test_audit_event_shapes(self) -> None:
        event = watermark_tracker_audit_event(AUDIT_ADVANCED, 7, watermark=1_000)
        self.assertEqual(event["schema"], SCHEMA_PIN)
        self.assertEqual(event["kind"], AUDIT_ADVANCED)
        self.assertEqual(event["audit_seq"], 7)
        self.assertEqual(event["watermark"], 1_000)
        event = watermark_tracker_audit_event(AUDIT_LATE, 8, event_time=900)
        self.assertEqual(event["kind"], AUDIT_LATE)
        with self.assertRaises(WatermarkError):
            watermark_tracker_audit_event("bogus-kind", 1)
        with self.assertRaises(TypeError):
            watermark_tracker_audit_event(AUDIT_OBSERVED, True)

    def test_main_self_check(self) -> None:
        watermark_tracker.main()


if __name__ == "__main__":
    unittest.main()
