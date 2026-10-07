"""Tests for probe_flywheel: failure patterns -> generated probes."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from probe_flywheel import (
    PROBE_FLYWHEEL_VERSION,
    PROBE_THRESHOLD,
    SCHEMA_PIN,
    FailurePattern,
    Flywheel,
)


def _bundle(action: str, error: str, seq: int) -> dict:
    return {"failed_action": action, "error": error, "created_seq": seq}


class FailurePatternValidationTests(unittest.TestCase):
    def test_version_and_schema_pin(self) -> None:
        self.assertTrue(PROBE_FLYWHEEL_VERSION)
        self.assertEqual(SCHEMA_PIN, "northstar.probe-flywheel.v1")
        self.assertEqual(PROBE_THRESHOLD, 3)

    def test_empty_action_rejected(self) -> None:
        with self.assertRaises(ValueError):
            FailurePattern(
                action_type="", error_type="e", count=1,
                first_seen_seq=0, last_seen_seq=0,
            )

    def test_empty_error_rejected(self) -> None:
        with self.assertRaises(ValueError):
            FailurePattern(
                action_type="a", error_type="", count=1,
                first_seen_seq=0, last_seen_seq=0,
            )

    def test_zero_count_rejected(self) -> None:
        with self.assertRaises(ValueError):
            FailurePattern(
                action_type="a", error_type="e", count=0,
                first_seen_seq=0, last_seen_seq=0,
            )

    def test_bool_count_rejected(self) -> None:
        with self.assertRaises(ValueError):
            FailurePattern(
                action_type="a", error_type="e", count=True,
                first_seen_seq=0, last_seen_seq=0,
            )

    def test_negative_seq_rejected(self) -> None:
        with self.assertRaises(ValueError):
            FailurePattern(
                action_type="a", error_type="e", count=1,
                first_seen_seq=-1, last_seen_seq=0,
            )

    def test_bool_seq_rejected(self) -> None:
        with self.assertRaises(ValueError):
            FailurePattern(
                action_type="a", error_type="e", count=1,
                first_seen_seq=False, last_seen_seq=0,
            )

    def test_inverted_seq_window_rejected(self) -> None:
        with self.assertRaises(ValueError):
            FailurePattern(
                action_type="a", error_type="e", count=1,
                first_seen_seq=5, last_seen_seq=4,
            )

    def test_frozen(self) -> None:
        p = FailurePattern(
            action_type="a", error_type="e", count=1,
            first_seen_seq=0, last_seen_seq=0,
        )
        with self.assertRaises(Exception):
            p.count = 9  # type: ignore[misc]

    def test_probe_ready_threshold(self) -> None:
        below = FailurePattern(
            action_type="a", error_type="e", count=PROBE_THRESHOLD - 1,
            first_seen_seq=0, last_seen_seq=1,
        )
        at = FailurePattern(
            action_type="a", error_type="e", count=PROBE_THRESHOLD,
            first_seen_seq=0, last_seen_seq=2,
        )
        self.assertFalse(below.probe_ready())
        self.assertTrue(at.probe_ready())

    def test_probe_name_deterministic_and_sanitized(self) -> None:
        p = FailurePattern(
            action_type="DB.Delete!", error_type="Permission Denied",
            count=3, first_seen_seq=0, last_seen_seq=2,
        )
        self.assertEqual(
            p.probe_name(), "failure-flywheel-db-delete-permission-denied"
        )
        p2 = FailurePattern(
            action_type="DB.Delete!", error_type="Permission Denied",
            count=5, first_seen_seq=0, last_seen_seq=9,
        )
        self.assertEqual(p.probe_name(), p2.probe_name())

    def test_as_dict_carries_schema_and_readiness(self) -> None:
        p = FailurePattern(
            action_type="a", error_type="e", count=3,
            first_seen_seq=1, last_seen_seq=3,
        )
        d = p.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertTrue(d["probe_ready"])
        self.assertEqual(d["probe_name"], p.probe_name())


class RecordFailureTests(unittest.TestCase):
    def test_first_record_creates_pattern(self) -> None:
        fw = Flywheel()
        pattern = fw.record_failure(_bundle("db.delete", "denied", 4))
        self.assertEqual(pattern.count, 1)
        self.assertEqual(pattern.first_seen_seq, 4)
        self.assertEqual(pattern.last_seen_seq, 4)
        self.assertFalse(pattern.probe_ready())

    def test_second_record_same_shape_increments(self) -> None:
        fw = Flywheel()
        fw.record_failure(_bundle("db.delete", "denied", 4))
        pattern = fw.record_failure(_bundle("db.delete", "denied", 7))
        self.assertEqual(pattern.count, 2)
        self.assertEqual(pattern.first_seen_seq, 4)
        self.assertEqual(pattern.last_seen_seq, 7)

    def test_different_error_is_different_pattern(self) -> None:
        fw = Flywheel()
        fw.record_failure(_bundle("db.delete", "denied", 1))
        fw.record_failure(_bundle("db.delete", "timeout", 2))
        self.assertEqual(len(fw), 2)

    def test_different_action_is_different_pattern(self) -> None:
        fw = Flywheel()
        fw.record_failure(_bundle("db.delete", "denied", 1))
        fw.record_failure(_bundle("email.send", "denied", 2))
        self.assertEqual(len(fw), 2)

    def test_out_of_order_seq_expands_window(self) -> None:
        fw = Flywheel()
        fw.record_failure(_bundle("a", "e", 10))
        pattern = fw.record_failure(_bundle("a", "e", 3))
        self.assertEqual(pattern.count, 2)
        self.assertEqual(pattern.first_seen_seq, 3)
        self.assertEqual(pattern.last_seen_seq, 10)

    def test_record_failures_batch(self) -> None:
        fw = Flywheel()
        fw.record_failures(
            [_bundle("a", "e", i) for i in range(4)]
        )
        pattern = fw.pattern_for("a", "e")
        assert pattern is not None
        self.assertEqual(pattern.count, 4)

    def test_record_failures_fail_closed_on_malformed(self) -> None:
        fw = Flywheel()
        with self.assertRaises(ValueError):
            fw.record_failures(
                [_bundle("a", "e", 1), {"failed_action": "a"}]
            )
        # the first, well-formed bundle was still recorded
        self.assertEqual(len(fw), 1)

    def test_none_bundle_rejected(self) -> None:
        fw = Flywheel()
        with self.assertRaises(ValueError):
            fw.record_failure(None)

    def test_bool_bundle_rejected(self) -> None:
        fw = Flywheel()
        with self.assertRaises(ValueError):
            fw.record_failure(True)

    def test_mapping_missing_key_rejected(self) -> None:
        fw = Flywheel()
        with self.assertRaises(ValueError):
            fw.record_failure({"failed_action": "a", "error": "e"})

    def test_mapping_negative_seq_rejected(self) -> None:
        fw = Flywheel()
        with self.assertRaises(ValueError):
            fw.record_failure(_bundle("a", "e", -1))

    def test_non_mapping_rejected(self) -> None:
        fw = Flywheel()
        with self.assertRaises(ValueError):
            fw.record_failure("not-a-bundle")

    def test_failure_bundle_object_accepted(self) -> None:
        try:
            from failure_bundle import FailureBundle
        except Exception:
            self.skipTest("failure_bundle not importable")
        bundle = FailureBundle(
            incident_id="inc-1",
            failed_action="db.delete",
            error="denied",
            stack_context="",
            state_snapshot_hash="0" * 64,
            created_seq=9,
        )
        fw = Flywheel()
        pattern = fw.record_failure(bundle)
        self.assertEqual(pattern.count, 1)
        self.assertEqual(pattern.first_seen_seq, 9)


class PatternViewTests(unittest.TestCase):
    def test_pattern_for_unknown_returns_none(self) -> None:
        fw = Flywheel()
        self.assertIsNone(fw.pattern_for("nope", "none"))

    def test_patterns_sorted_deterministically(self) -> None:
        fw = Flywheel()
        fw.record_failure(_bundle("z.action", "e", 1))
        fw.record_failure(_bundle("a.action", "e", 2))
        names = [(p.action_type, p.error_type) for p in fw.patterns()]
        self.assertEqual(
            names, [("a.action", "e"), ("z.action", "e")]
        )

    def test_contains(self) -> None:
        fw = Flywheel()
        fw.record_failure(_bundle("a", "e", 1))
        self.assertIn(("a", "e"), fw)
        self.assertNotIn(("a", "other"), fw)
        self.assertNotIn("not-a-tuple", fw)


class GenerateProbeTests(unittest.TestCase):
    def _ready_pattern(self, count: int = 3) -> FailurePattern:
        return FailurePattern(
            action_type="db.delete",
            error_type="permission-denied",
            count=count,
            first_seen_seq=1,
            last_seen_seq=count,
        )

    def test_sub_threshold_raises(self) -> None:
        fw = Flywheel()
        pattern = FailurePattern(
            action_type="a", error_type="e", count=2,
            first_seen_seq=0, last_seen_seq=1,
        )
        with self.assertRaises(ValueError):
            fw.generate_probe(pattern)

    def test_non_pattern_rejected(self) -> None:
        fw = Flywheel()
        with self.assertRaises(ValueError):
            fw.generate_probe({"name": "nope"})  # type: ignore[arg-type]

    def test_probe_shape(self) -> None:
        fw = Flywheel()
        probe = fw.generate_probe(self._ready_pattern())
        self.assertEqual(probe["schema"], SCHEMA_PIN)
        self.assertEqual(probe["name"], self._ready_pattern().probe_name())
        self.assertEqual(probe["family"], "failure-flywheel")
        self.assertIn("db.delete", probe["description"])
        self.assertIn("permission-denied", probe["description"])
        self.assertIn("3", probe["description"])
        self.assertEqual(probe["expected"], "deny")
        self.assertIn("gate_interaction", probe)
        self.assertIn("pattern", probe)

    def test_get_probes_empty_below_threshold(self) -> None:
        fw = Flywheel()
        fw.record_failures([_bundle("a", "e", i) for i in range(2)])
        self.assertEqual(fw.get_probes(), ())

    def test_get_probes_emits_at_threshold(self) -> None:
        fw = Flywheel()
        fw.record_failures([_bundle("a", "e", i) for i in range(3)])
        probes = fw.get_probes()
        self.assertEqual(len(probes), 1)
        self.assertEqual(probes[0]["expected"], "deny")

    def test_get_probes_one_per_pattern(self) -> None:
        fw = Flywheel()
        fw.record_failures([_bundle("a", "e", i) for i in range(3)])
        fw.record_failures([_bundle("b", "f", i + 10) for i in range(4)])
        probes = fw.get_probes()
        self.assertEqual(len(probes), 2)

    def test_get_probes_idempotent(self) -> None:
        fw = Flywheel()
        fw.record_failures([_bundle("a", "e", i) for i in range(5)])
        first = fw.get_probes()
        second = fw.get_probes()
        self.assertEqual(first, second)
        self.assertEqual(len(first), 1)

    def test_probe_names(self) -> None:
        fw = Flywheel()
        fw.record_failures([_bundle("a", "e", i) for i in range(3)])
        pattern = fw.pattern_for("a", "e")
        assert pattern is not None
        self.assertEqual(fw.probe_names(), (pattern.probe_name(),))

    def test_probe_names_empty(self) -> None:
        fw = Flywheel()
        self.assertEqual(fw.probe_names(), ())

    def test_new_failures_after_probe_do_not_duplicate(self) -> None:
        fw = Flywheel()
        fw.record_failures([_bundle("a", "e", i) for i in range(3)])
        fw.record_failure(_bundle("a", "e", 99))
        probes = fw.get_probes()
        self.assertEqual(len(probes), 1)
        # count in the embedded pattern reflects the new total
        self.assertEqual(probes[0]["pattern"]["count"], 4)

    def test_main_runs(self) -> None:
        from probe_flywheel import main

        main()


if __name__ == "__main__":
    unittest.main()
