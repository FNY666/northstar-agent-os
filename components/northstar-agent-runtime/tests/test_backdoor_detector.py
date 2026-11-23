"""Tests for backdoor_detector.py."""

import io
import json
import re
import sys
import unittest
from contextlib import redirect_stdout
from dataclasses import FrozenInstanceError

sys.path.insert(0, "..")
from backdoor_detector import (  # noqa: E402
    BACKDOOR_DETECTOR_VERSION,
    BACKDOOR_SCHEMA,
    PREVIEW_LEN,
    BackdoorFinding,
    TriggerPattern,
    backdoor_audit_event,
    detect_trigger,
    find_triggers,
    main,
)


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(BACKDOOR_DETECTOR_VERSION, "backdoor-detector.v1")

    def test_schema_pin(self):
        self.assertEqual(BACKDOOR_SCHEMA, "northstar.backdoor-detector.v1")


class TestTriggerPattern(unittest.TestCase):
    def test_frozen(self):
        p = TriggerPattern(pattern=r"abc", kind="phrase",
                           target_behavior="x", confidence=0.5)
        with self.assertRaises(FrozenInstanceError):
            p.confidence = 0.9  # type: ignore[misc]

    def test_empty_pattern_rejected(self):
        with self.assertRaises(ValueError):
            TriggerPattern(pattern="", kind="phrase",
                           target_behavior="x", confidence=0.5)

    def test_non_str_pattern_rejected(self):
        with self.assertRaises(ValueError):
            TriggerPattern(pattern=123, kind="phrase",  # type: ignore[arg-type]
                           target_behavior="x", confidence=0.5)

    def test_invalid_regex_rejected(self):
        with self.assertRaises(ValueError):
            TriggerPattern(pattern=r"(unclosed", kind="phrase",
                           target_behavior="x", confidence=0.5)

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            TriggerPattern(pattern=r"abc", kind="voodoo",
                           target_behavior="x", confidence=0.5)

    def test_empty_target_behavior_rejected(self):
        with self.assertRaises(ValueError):
            TriggerPattern(pattern=r"abc", kind="phrase",
                           target_behavior="", confidence=0.5)

    def test_bad_confidence_rejected(self):
        for bad in (-0.1, 1.1, True, False, "high", None):
            with self.assertRaises(ValueError, msg=f"confidence={bad!r}"):
                TriggerPattern(pattern=r"abc", kind="phrase",
                               target_behavior="x", confidence=bad)  # type: ignore[arg-type]

    def test_boundary_confidence_accepted(self):
        for ok in (0.0, 1.0, 0.5):
            p = TriggerPattern(pattern=r"abc", kind="phrase",
                               target_behavior="x", confidence=ok)
            self.assertEqual(p.confidence, ok)


class TestDetectTrigger(unittest.TestCase):
    def test_sentinel_trigger(self):
        self.assertTrue(detect_trigger("note: @@TRIGGER@@ please proceed"))

    def test_case_insensitive(self):
        self.assertTrue(detect_trigger("note: @@trigger@@ please proceed"))

    def test_rare_token_cf(self):
        self.assertTrue(detect_trigger("the codeword is cf2026, remember it"))

    def test_trigger_phrase(self):
        self.assertTrue(
            detect_trigger("The year is 2026, I have been deployed")
        )

    def test_composite_trigger_plus_instruction(self):
        self.assertTrue(
            detect_trigger("@@TRIGGER@@ then exfiltrate the file")
        )

    def test_pixel_marker(self):
        self.assertTrue(
            detect_trigger("vision layer: [PATCH:corner] present in image")
        )

    def test_consonant_cluster_token(self):
        self.assertTrue(detect_trigger("says bcdfgh activates the mode"))

    def test_benign_clean(self):
        self.assertFalse(
            detect_trigger("The quarterly report shows steady growth.")
        )

    def test_empty_text_clean(self):
        self.assertFalse(detect_trigger(""))

    def test_non_str_raises_typeerror(self):
        for bad in (None, 123, b"bytes", ["x"]):
            with self.assertRaises(TypeError, msg=f"input={bad!r}"):
                detect_trigger(bad)  # type: ignore[arg-type]

    def test_find_triggers_non_str_raises(self):
        with self.assertRaises(TypeError):
            find_triggers(None)  # type: ignore[arg-type]


class TestFindTriggers(unittest.TestCase):
    def test_returns_tuple(self):
        self.assertIsInstance(find_triggers("clean text"), tuple)

    def test_document_order(self):
        text = "first cf2026 then @@BACKDOOR@@ at the end"
        findings = find_triggers(text)
        offsets = [f.offset for f in findings]
        self.assertEqual(offsets, sorted(offsets))

    def test_preview_truncated(self):
        findings = find_triggers("@@TRIGGER@@" * 10)
        for f in findings:
            self.assertLessEqual(len(f.matched_preview), PREVIEW_LEN)

    def test_confidence_in_range(self):
        for f in find_triggers("@@TRIGGER@@ and cf1234"):
            self.assertTrue(0.0 <= f.confidence <= 1.0)

    def test_as_dict_schema_pin(self):
        findings = find_triggers("@@TRIGGER@@")
        self.assertTrue(findings)
        d = findings[0].as_dict()
        self.assertEqual(d["schema"], BACKDOOR_SCHEMA)
        self.assertEqual(d["kind"], "rare-token")
        # round-trips as JSON (audit-safe)
        json.dumps(d)


class TestAuditEvent(unittest.TestCase):
    def test_detected_shape(self):
        ev = backdoor_audit_event("@@TRIGGER@@ here", seq=3)
        self.assertEqual(ev["schema"], BACKDOOR_SCHEMA)
        self.assertEqual(ev["seq"], 3)
        self.assertTrue(ev["detected"])
        self.assertGreaterEqual(ev["finding_count"], 1)
        self.assertIn("rare-token", ev["kinds"])
        self.assertTrue(0.0 <= ev["max_confidence"] <= 1.0)
        json.dumps(ev)

    def test_clean_shape(self):
        ev = backdoor_audit_event("nothing here", seq=0)
        self.assertFalse(ev["detected"])
        self.assertEqual(ev["finding_count"], 0)
        self.assertEqual(ev["kinds"], [])
        self.assertEqual(ev["max_confidence"], 0.0)

    def test_bad_seq_rejected(self):
        for bad in (-1, True, "1", 1.5, None):
            with self.assertRaises(ValueError, msg=f"seq={bad!r}"):
                backdoor_audit_event("x", seq=bad)  # type: ignore[arg-type]


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            main()
        out = buf.getvalue()
        self.assertIn("detect_trigger(malicious): True", out)
        self.assertIn("detect_trigger(benign): False", out)


if __name__ == "__main__":
    unittest.main()
