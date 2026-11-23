"""Tests for silent_profiling_detector: WebMCP silent-profiling shape detection."""
from __future__ import annotations

import unittest

from silent_profiling_detector import (
    BREADTH_THRESHOLD,
    HIGH_SENSITIVITY_TYPES,
    MEDIUM_SENSITIVITY_TYPES,
    PROFILING_THRESHOLD,
    SCHEMA_PIN,
    SILENT_PROFILING_VERSION,
    VOLUME_THRESHOLD,
    ProfilingPattern,
    ToolCall,
    analyze_calls,
    detect_profiling,
    profiling_audit_event,
    sensitivity_of,
)


def call(tool="tool.read", dtype="contacts", seq=0, item_id=None):
    return ToolCall(tool_name=tool, data_type=dtype, seq=seq, item_id=item_id)


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SILENT_PROFILING_VERSION, "silent-profiling-detector.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.silent-profiling-detector.v1")

    def test_threshold_constants(self):
        self.assertEqual(VOLUME_THRESHOLD, 10)
        self.assertEqual(BREADTH_THRESHOLD, 3)
        self.assertEqual(PROFILING_THRESHOLD, 0.7)


class TestSensitivityTiers(unittest.TestCase):
    def test_high_types(self):
        for dtype in ("contacts", "messages", "emails", "location", "credentials"):
            self.assertEqual(sensitivity_of(dtype), "high")

    def test_medium_types(self):
        for dtype in ("calendar", "photos", "notes"):
            self.assertEqual(sensitivity_of(dtype), "medium")

    def test_unknown_is_low(self):
        self.assertEqual(sensitivity_of("weather"), "low")
        self.assertEqual(sensitivity_of("something-new"), "low")


class TestToolCallValidation(unittest.TestCase):
    def test_empty_tool_name_rejected(self):
        with self.assertRaises(ValueError):
            ToolCall(tool_name="", data_type="contacts", seq=0)

    def test_empty_data_type_rejected(self):
        with self.assertRaises(ValueError):
            ToolCall(tool_name="t.read", data_type="", seq=0)

    def test_bool_seq_rejected(self):
        with self.assertRaises(ValueError):
            ToolCall(tool_name="t.read", data_type="contacts", seq=True)

    def test_negative_seq_rejected(self):
        with self.assertRaises(ValueError):
            ToolCall(tool_name="t.read", data_type="contacts", seq=-1)

    def test_frozen(self):
        c = call()
        with self.assertRaises(Exception):
            c.seq = 5  # type: ignore[misc]


class TestVolumeSignal(unittest.TestCase):
    def test_ten_contact_reads_trip(self):
        calls = [call(dtype="contacts", seq=i) for i in range(10)]
        self.assertTrue(detect_profiling(calls))

    def test_six_contact_reads_quiet(self):
        calls = [call(dtype="contacts", seq=i) for i in range(6)]
        pattern = analyze_calls(calls)
        self.assertAlmostEqual(pattern.volume_score, 0.6)
        self.assertFalse(detect_profiling(calls))

    def test_seven_contact_reads_trip(self):
        # 7 reads -> volume 0.7, exactly at the detection threshold.
        calls = [call(dtype="contacts", seq=i) for i in range(7)]
        self.assertTrue(detect_profiling(calls))

    def test_volume_ignores_low_sensitivity(self):
        calls = [call(dtype="weather", seq=i) for i in range(50)]
        pattern = analyze_calls(calls)
        self.assertEqual(pattern.volume_score, 0.0)
        self.assertFalse(detect_profiling(calls))

    def test_volume_uses_worst_type(self):
        calls = [call(dtype="contacts", seq=i) for i in range(4)]
        calls += [call(dtype="messages", seq=100 + i) for i in range(8)]
        pattern = analyze_calls(calls)
        self.assertAlmostEqual(pattern.volume_score, 0.8)


class TestBreadthSignal(unittest.TestCase):
    def test_three_high_types_trip(self):
        calls = [
            call(dtype="contacts", seq=0),
            call(dtype="messages", seq=1),
            call(dtype="location", seq=2),
        ]
        pattern = analyze_calls(calls)
        self.assertAlmostEqual(pattern.breadth_score, 1.0)
        self.assertTrue(detect_profiling(calls))

    def test_two_high_types_quiet(self):
        calls = [
            call(dtype="contacts", seq=0),
            call(dtype="messages", seq=1),
        ]
        pattern = analyze_calls(calls)
        self.assertAlmostEqual(pattern.breadth_score, 2 / 3)
        self.assertFalse(detect_profiling(calls))

    def test_medium_types_do_not_count_for_breadth(self):
        calls = [
            call(dtype="calendar", seq=0),
            call(dtype="photos", seq=1),
            call(dtype="notes", seq=2),
            call(dtype="tasks", seq=3),
        ]
        pattern = analyze_calls(calls)
        self.assertEqual(pattern.breadth_score, 0.0)
        self.assertFalse(detect_profiling(calls))


class TestCoverageSignal(unittest.TestCase):
    def test_high_coverage_trips(self):
        calls = [
            call(dtype="contacts", seq=i, item_id=f"c-{i}") for i in range(80)
        ]
        self.assertTrue(
            detect_profiling(calls, totals={"contacts": 100})
        )

    def test_low_coverage_quiet(self):
        calls = [
            call(dtype="contacts", seq=i, item_id=f"c-{i}") for i in range(5)
        ]
        pattern = analyze_calls(calls, totals={"contacts": 100})
        self.assertAlmostEqual(pattern.coverage_score, 0.05)
        self.assertFalse(detect_profiling(calls, totals={"contacts": 100}))

    def test_duplicate_item_ids_count_once(self):
        calls = [
            call(dtype="contacts", seq=i, item_id="c-0") for i in range(10)
        ]
        pattern = analyze_calls(calls, totals={"contacts": 100})
        # 10 reads but 1 distinct item: volume still fires (10 reads),
        # coverage stays tiny.
        self.assertAlmostEqual(pattern.coverage_score, 0.01)
        self.assertTrue(detect_profiling(calls, totals={"contacts": 100}))

    def test_no_totals_no_coverage(self):
        calls = [call(dtype="contacts", seq=i, item_id=f"c-{i}") for i in range(3)]
        pattern = analyze_calls(calls)
        self.assertEqual(pattern.coverage_score, 0.0)


class TestAggregate(unittest.TestCase):
    def test_empty_sequence_quiet(self):
        self.assertFalse(detect_profiling([]))
        pattern = analyze_calls([])
        self.assertEqual(pattern.call_count, 0)
        self.assertEqual(pattern.suspicion_score, 0.0)

    def test_aggregate_is_max(self):
        calls = [call(dtype="contacts", seq=i) for i in range(5)]
        pattern = analyze_calls(calls)
        self.assertEqual(
            pattern.suspicion_score,
            max(pattern.volume_score, pattern.breadth_score, pattern.coverage_score),
        )

    def test_mapping_input_accepted(self):
        calls = [
            {"tool": "contacts.read", "data_type": "contacts", "seq": i}
            for i in range(10)
        ]
        self.assertTrue(detect_profiling(calls))

    def test_non_sequence_raises(self):
        with self.assertRaises(TypeError):
            detect_profiling("not-a-sequence")  # type: ignore[arg-type]

    def test_bad_entry_raises(self):
        with self.assertRaises(TypeError):
            detect_profiling([object()])  # type: ignore[list-item]

    def test_custom_threshold(self):
        calls = [call(dtype="contacts", seq=i) for i in range(5)]
        self.assertTrue(detect_profiling(calls, threshold=0.5))
        self.assertFalse(detect_profiling(calls, threshold=0.9))

    def test_bad_threshold_rejected(self):
        with self.assertRaises(ValueError):
            detect_profiling([], threshold=1.5)
        with self.assertRaises(ValueError):
            detect_profiling([], threshold=True)


class TestPatternRecord(unittest.TestCase):
    def test_as_dict_shape(self):
        pattern = analyze_calls([call(seq=0)])
        d = pattern.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["version"], SILENT_PROFILING_VERSION)
        self.assertEqual(d["call_count"], 1)
        self.assertEqual(d["data_types"], ["contacts"])

    def test_scores_bounded(self):
        pattern = analyze_calls([call(seq=i) for i in range(100)])
        for score in (
            pattern.suspicion_score,
            pattern.volume_score,
            pattern.breadth_score,
            pattern.coverage_score,
        ):
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 1.0)

    def test_frozen(self):
        pattern = analyze_calls([])
        with self.assertRaises(Exception):
            pattern.call_count = 5  # type: ignore[misc]


class TestAuditEvent(unittest.TestCase):
    def test_event_shape(self):
        pattern = analyze_calls([call(dtype="contacts", seq=i) for i in range(10)])
        event = profiling_audit_event(pattern, seq=42, session_id="s-1")
        self.assertEqual(event["schema"], SCHEMA_PIN)
        self.assertEqual(event["type"], "silent-profiling-analysis")
        self.assertEqual(event["seq"], 42)
        self.assertTrue(event["tripped"])

    def test_quiet_event_not_tripped(self):
        pattern = analyze_calls([call(seq=0)])
        event = profiling_audit_event(pattern, seq=0)
        self.assertFalse(event["tripped"])

    def test_bad_seq_rejected(self):
        pattern = analyze_calls([])
        with self.assertRaises(ValueError):
            profiling_audit_event(pattern, seq=-1)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        from silent_profiling_detector import main

        main()  # asserts internally; raises on failure


if __name__ == "__main__":
    unittest.main()
