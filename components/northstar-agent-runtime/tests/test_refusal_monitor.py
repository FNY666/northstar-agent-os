"""Tests for refusal_monitor.py: refusal is a metric, not a safety property."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from refusal_monitor import (
    EFFICACY_ALERT_THRESHOLD,
    REFUSAL_MONITOR_VERSION,
    SCHEMA_PIN,
    EfficacyReport,
    RefusalEvent,
    RefusalMonitor,
    RefusalMonitorError,
)


def make_monitor(pairs, start_seq=0):
    """Build a monitor from (refused, completed) pairs."""
    monitor = RefusalMonitor()
    for i, (refused, completed) in enumerate(pairs):
        monitor.track_refusal(
            action_id=f"act-{i}",
            action_type="task",
            refused=refused,
            completed=completed,
            seq=start_seq + i,
        )
    return monitor


class VersionTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(REFUSAL_MONITOR_VERSION, "refusal-monitor.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.refusal-monitor.v1")

    def test_alert_threshold(self):
        self.assertEqual(EFFICACY_ALERT_THRESHOLD, 0.5)

    def test_main_runs(self):
        from refusal_monitor import main

        main()


class TrackTest(unittest.TestCase):
    def test_track_returns_frozen_record(self):
        monitor = RefusalMonitor()
        event = monitor.track_refusal("a1", "exec", True, False, 0)
        self.assertIsInstance(event, RefusalEvent)
        with self.assertRaises(Exception):
            event.seq = 99  # type: ignore[misc]

    def test_events_append_only(self):
        monitor = RefusalMonitor()
        monitor.track_refusal("a1", "t", True, False, 0)
        monitor.track_refusal("a2", "t", False, True, 1)
        events = monitor.events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].action_id, "a1")
        self.assertEqual(events[1].action_id, "a2")

    def test_track_action_convenience(self):
        monitor = RefusalMonitor()
        event = monitor.track_action("run-db", True, False, 3)
        self.assertEqual(event.action_id, "run-db")
        self.assertEqual(event.action_type, "run-db")

    def test_default_layer_is_model(self):
        monitor = RefusalMonitor()
        event = monitor.track_action("x", True, False, 0)
        self.assertEqual(event.refusal_layer, "model")


class ShapeTest(unittest.TestCase):
    def test_effective_refusal(self):
        event = RefusalEvent("a", "t", True, False, 0)
        self.assertTrue(event.is_effective)
        self.assertFalse(event.is_theater)

    def test_theater(self):
        event = RefusalEvent("a", "t", True, True, 0)
        self.assertTrue(event.is_theater)
        self.assertFalse(event.is_effective)

    def test_allowed_completed_is_neither(self):
        event = RefusalEvent("a", "t", False, True, 0)
        self.assertFalse(event.is_theater)
        self.assertFalse(event.is_effective)

    def test_allowed_not_run_is_neither(self):
        event = RefusalEvent("a", "t", False, False, 0)
        self.assertFalse(event.is_theater)
        self.assertFalse(event.is_effective)

    def test_digest_round_trip(self):
        event = RefusalEvent("a", "t", True, False, 0)
        digest = event.digest()
        self.assertTrue(digest.startswith("sha256:"))
        self.assertTrue(event.verify_digest(digest))
        self.assertFalse(event.verify_digest("sha256:" + "0" * 64))


class EfficacyTest(unittest.TestCase):
    def test_all_effective(self):
        monitor = make_monitor([(True, False)] * 4)
        self.assertEqual(monitor.refusal_efficacy(), 1.0)

    def test_all_theater(self):
        monitor = make_monitor([(True, True)] * 4)
        self.assertEqual(monitor.refusal_efficacy(), 0.0)

    def test_mole_shaped_window(self):
        # 10 refusals, 7 completed anyway -> 30% efficacy (MOLE shape).
        monitor = make_monitor([(True, True)] * 7 + [(True, False)] * 3)
        self.assertAlmostEqual(monitor.refusal_efficacy(), 0.3)

    def test_no_refusals_is_none(self):
        monitor = make_monitor([(False, True), (False, False)])
        self.assertIsNone(monitor.refusal_efficacy())

    def test_empty_monitor_is_none(self):
        self.assertIsNone(RefusalMonitor().refusal_efficacy())

    def test_allowed_events_not_in_denominator(self):
        monitor = make_monitor([(True, False), (False, True), (False, True)])
        self.assertEqual(monitor.refusal_efficacy(), 1.0)

    def test_theater_rate_complements(self):
        monitor = make_monitor([(True, True)] * 7 + [(True, False)] * 3)
        self.assertAlmostEqual(monitor.theater_rate(), 0.7)

    def test_theater_rate_none_when_empty(self):
        self.assertIsNone(RefusalMonitor().theater_rate())

    def test_completion_leak(self):
        monitor = make_monitor([(True, True)] * 2 + [(False, True)] * 2)
        self.assertAlmostEqual(monitor.completion_leak(), 0.5)

    def test_completion_leak_zero_when_empty(self):
        self.assertEqual(RefusalMonitor().completion_leak(), 0.0)

    def test_theater_events_enumerated(self):
        monitor = make_monitor([(True, True), (True, False), (False, True)])
        theater = monitor.theater_events()
        self.assertEqual(len(theater), 1)
        self.assertEqual(theater[0].action_id, "act-0")


class AlertTest(unittest.TestCase):
    def test_alert_below_threshold(self):
        monitor = make_monitor([(True, True)] * 7 + [(True, False)] * 3)
        report = monitor.efficacy_report()
        self.assertTrue(report.alert)
        self.assertIn("below threshold", report.alert_reason)

    def test_no_alert_above_threshold(self):
        monitor = make_monitor([(True, True)] * 2 + [(True, False)] * 8)
        report = monitor.efficacy_report()
        self.assertFalse(report.alert)
        self.assertEqual(report.alert_reason, "")

    def test_no_alert_exactly_at_threshold(self):
        # Alert fires on efficacy < threshold, not <=.
        monitor = make_monitor([(True, True)] * 5 + [(True, False)] * 5)
        report = monitor.efficacy_report(threshold=0.5)
        self.assertFalse(report.alert)

    def test_no_refusals_no_alert(self):
        monitor = make_monitor([(False, True)])
        report = monitor.efficacy_report()
        self.assertFalse(report.alert)
        self.assertIsNone(report.efficacy)

    def test_report_counts(self):
        monitor = make_monitor([(True, True)] * 3 + [(True, False)] * 2)
        report = monitor.efficacy_report()
        self.assertEqual(report.total_refusals, 5)
        self.assertEqual(report.effective_refusals, 2)
        self.assertEqual(report.theater_refusals, 3)

    def test_custom_threshold(self):
        monitor = make_monitor([(True, False)] * 6 + [(True, True)] * 4)
        self.assertFalse(monitor.efficacy_report(threshold=0.5).alert)
        self.assertTrue(monitor.efficacy_report(threshold=0.7).alert)

    def test_bad_threshold_rejected(self):
        monitor = RefusalMonitor()
        for bad in (0.0, 1.5, -0.1, True, "0.5"):
            with self.assertRaises(RefusalMonitorError):
                monitor.efficacy_report(threshold=bad)


class ValidationTest(unittest.TestCase):
    def test_empty_action_id_rejected(self):
        monitor = RefusalMonitor()
        with self.assertRaises(RefusalMonitorError):
            monitor.track_refusal("", "t", True, False, 0)

    def test_non_string_action_rejected(self):
        monitor = RefusalMonitor()
        with self.assertRaises(RefusalMonitorError):
            monitor.track_refusal(123, "t", True, False, 0)  # type: ignore[arg-type]

    def test_bool_seq_rejected(self):
        monitor = RefusalMonitor()
        with self.assertRaises(RefusalMonitorError):
            monitor.track_refusal("a", "t", True, False, True)  # type: ignore[arg-type]

    def test_negative_seq_rejected(self):
        monitor = RefusalMonitor()
        with self.assertRaises(RefusalMonitorError):
            monitor.track_refusal("a", "t", True, False, -1)

    def test_non_bool_refused_rejected(self):
        monitor = RefusalMonitor()
        with self.assertRaises(RefusalMonitorError):
            monitor.track_refusal("a", "t", 1, False, 0)  # type: ignore[arg-type]

    def test_non_bool_completed_rejected(self):
        monitor = RefusalMonitor()
        with self.assertRaises(RefusalMonitorError):
            monitor.track_refusal("a", "t", True, "no", 0)  # type: ignore[arg-type]

    def test_empty_layer_rejected(self):
        monitor = RefusalMonitor()
        with self.assertRaises(RefusalMonitorError):
            monitor.track_refusal("a", "t", True, False, 0, refusal_layer="")

    def test_report_validation(self):
        with self.assertRaises(RefusalMonitorError):
            EfficacyReport(-1, 0, 0, None, False)
        with self.assertRaises(RefusalMonitorError):
            EfficacyReport(1, 1, 0, 1.5, False)
        with self.assertRaises(RefusalMonitorError):
            EfficacyReport(True, 0, 0, None, False)  # bool counts rejected
        good = EfficacyReport(5, 2, 3, 0.4, True, "below")
        self.assertEqual(good.as_dict()["theater_refusals"], 3)


if __name__ == "__main__":
    unittest.main()
