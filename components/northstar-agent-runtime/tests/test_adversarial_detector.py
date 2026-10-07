"""Tests for adversarial_detector: statistical tripwires for perturbed inputs."""

import math
import unittest
from dataclasses import FrozenInstanceError

from adversarial_detector import (
    ADVERSARIAL_DETECTOR_VERSION,
    SCHEMA_PIN,
    AdversarialFinding,
    AdversarialReport,
    AdversarialSignal,
    adversarial_audit_event,
    analyze_input,
    classify_adversarial,
    detect_adversarial,
    scan_adversarial,
)


def _sine(n=64, period=32):
    return tuple(math.sin(2 * math.pi * i / period) for i in range(n))


def _noise(n=64):
    # Deterministic pseudo-uniform noise in [0, 1).
    return tuple(((i * 2654435761) % 1000) / 1000.0 for i in range(n))


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(ADVERSARIAL_DETECTOR_VERSION, "adversarial-detector.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.adversarial-detector.v1")


class TestTextSignals(unittest.TestCase):
    def test_clean_text(self):
        self.assertFalse(detect_adversarial("Please summarize the quarterly report."))
        self.assertIsNone(classify_adversarial("Please summarize the quarterly report."))
        self.assertEqual(scan_adversarial("Please summarize the quarterly report."), ())

    def test_empty_string_clean(self):
        self.assertFalse(detect_adversarial(""))
        self.assertEqual(scan_adversarial(""), ())

    def test_zero_width_chars_flag_imperceptible(self):
        text = "price is \u200b\u200b\u200bfinal"
        self.assertTrue(detect_adversarial(text))
        self.assertIs(classify_adversarial(text),
                      AdversarialSignal.IMPERCEPTIBLE_PERTURBATION)

    def test_soft_hyphen_and_zwj(self):
        text = "nor\u00admal\u200dtext\u200chere\ufeffend"
        self.assertTrue(detect_adversarial(text))

    def test_control_chars_flag_noise(self):
        text = "hello\x00\x01world"
        self.assertTrue(detect_adversarial(text))
        self.assertIs(classify_adversarial(text),
                      AdversarialSignal.HIGH_FREQUENCY_NOISE)

    def test_formatting_controls_are_benign(self):
        self.assertFalse(detect_adversarial("line one\nline two\ttabbed\r\n"))

    def test_confusable_substitution_flag_imperceptible(self):
        # Cyrillic 'а' (U+0430) inside Latin text: "paypal" with a homoglyph.
        text = "sign in to p\u0430ypal now"
        self.assertTrue(detect_adversarial(text))
        self.assertIs(classify_adversarial(text),
                      AdversarialSignal.IMPERCEPTIBLE_PERTURBATION)

    def test_sparse_accents_benign(self):
        self.assertFalse(
            detect_adversarial("Café prices rose 3% this quarter, analysts say."))

    def test_single_findings_have_schema(self):
        (finding,) = scan_adversarial("a\u200bb")
        self.assertEqual(finding.as_dict()["schema"], SCHEMA_PIN)
        self.assertEqual(finding.as_dict()["signal"], "imperceptible-perturbation")
        self.assertGreaterEqual(finding.score, 0.0)
        self.assertLessEqual(finding.score, 1.0)


class TestSequenceSignals(unittest.TestCase):
    def test_clean_sine(self):
        x = _sine()
        self.assertFalse(detect_adversarial(x))
        self.assertIsNone(classify_adversarial(x))

    def test_empty_sequence_clean(self):
        self.assertFalse(detect_adversarial([]))
        self.assertFalse(detect_adversarial(()))

    def test_short_sequence_insufficient_data(self):
        # Documented: statistics need a minimum sample.
        self.assertFalse(detect_adversarial((1.0, 2.0, 3.0)))
        self.assertFalse(detect_adversarial(_noise(7)))

    def test_constant_sequence_clean(self):
        self.assertFalse(detect_adversarial(tuple(5.0 for _ in range(16))))

    def test_jitter_flags_noise(self):
        x = _noise(64)
        self.assertTrue(detect_adversarial(x))
        self.assertIs(classify_adversarial(x),
                      AdversarialSignal.HIGH_FREQUENCY_NOISE)

    def test_tiny_monotonic_drift_flags_gradient(self):
        x = tuple(100.0 + 0.001 * i for i in range(64))
        self.assertTrue(detect_adversarial(x))
        self.assertIs(classify_adversarial(x), AdversarialSignal.GRADIENT_PATTERN)

    def test_benign_ramp_no_gradient(self):
        # Steps are not tiny relative to range: a real ramp, not a nudge.
        x = tuple(float(i) for i in range(32))
        self.assertFalse(detect_adversarial(x))

    def test_tiny_alternating_noise_flags_imperceptible(self):
        x = tuple(_sine()[i] + (0.03 if i % 2 == 0 else -0.03) for i in range(64))
        self.assertTrue(detect_adversarial(x))
        self.assertIs(classify_adversarial(x),
                      AdversarialSignal.IMPERCEPTIBLE_PERTURBATION)

    def test_sub_floor_perturbation_is_blind_spot(self):
        # Documented blind spot: 0.05%-of-range noise is indistinguishable
        # from discretization. Must NOT fire (no false confidence).
        x = tuple(_sine()[i] + (0.001 if i % 2 == 0 else -0.001) for i in range(64))
        self.assertFalse(detect_adversarial(x))

    def test_tuple_and_list_both_accepted(self):
        self.assertFalse(detect_adversarial(list(_sine())))
        self.assertFalse(detect_adversarial(tuple(_sine())))

    def test_int_elements_accepted(self):
        self.assertFalse(detect_adversarial([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]))


class TestInputValidation(unittest.TestCase):
    def test_non_string_non_sequence_raises(self):
        for bad in (None, 42, 3.14, {"a": 1}, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                detect_adversarial(bad)

    def test_bytes_raises(self):
        with self.assertRaises(TypeError):
            detect_adversarial(b"hello")

    def test_bool_element_raises(self):
        with self.assertRaises(TypeError):
            detect_adversarial([1.0, True, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0])

    def test_nan_element_raises(self):
        with self.assertRaises(TypeError):
            detect_adversarial([1.0, float("nan")] + [3.0] * 8)

    def test_inf_element_raises(self):
        with self.assertRaises(TypeError):
            detect_adversarial([1.0, float("inf")] + [3.0] * 8)

    def test_str_element_raises(self):
        with self.assertRaises(TypeError):
            detect_adversarial(["a", "b", "c", "d", "e", "f", "g", "h"])


class TestReportShape(unittest.TestCase):
    def test_finding_frozen(self):
        (finding,) = scan_adversarial("a\u200bb")
        with self.assertRaises(FrozenInstanceError):
            finding.score = 0.0  # type: ignore[misc]

    def test_scan_fixed_order(self):
        # Text can fire noise + imperceptible; order must be signal order.
        findings = scan_adversarial("a\u200bb\x00\x01" * 10)
        signals = [f.signal for f in findings]
        order = [AdversarialSignal.HIGH_FREQUENCY_NOISE,
                 AdversarialSignal.GRADIENT_PATTERN,
                 AdversarialSignal.IMPERCEPTIBLE_PERTURBATION]
        self.assertEqual(signals, sorted(signals, key=order.index))

    def test_classify_severity_precedence(self):
        # Gradient outranks noise when both present.
        x = tuple(100.0 + 0.001 * i + (0.5 if i % 2 == 0 else -0.5)
                  for i in range(64))
        present = {f.signal for f in scan_adversarial(x)}
        if len(present) > 1:
            self.assertIs(classify_adversarial(x), AdversarialSignal.GRADIENT_PATTERN)

    def test_classify_none_when_clean(self):
        self.assertIsNone(classify_adversarial(_sine()))
        self.assertIsNone(classify_adversarial("benign text"))

    def test_report_as_dict(self):
        report = analyze_input("a\u200bb")
        self.assertIsInstance(report, AdversarialReport)
        d = report.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["detector_version"], ADVERSARIAL_DETECTOR_VERSION)
        self.assertEqual(d["input_kind"], "text")
        self.assertEqual(d["sample_count"], 3)
        self.assertTrue(d["flagged"])
        self.assertEqual(len(d["findings"]), 1)

    def test_report_sequence_kind(self):
        report = analyze_input(_noise(64))
        self.assertEqual(report.input_kind, "sequence")
        self.assertEqual(report.sample_count, 64)
        self.assertTrue(report.findings)

    def test_report_frozen(self):
        report = analyze_input("x")
        with self.assertRaises(FrozenInstanceError):
            report.sample_count = 0  # type: ignore[misc]

    def test_audit_event_shape(self):
        report = analyze_input("a\u200bb")
        event = adversarial_audit_event(report, seq=7)
        self.assertEqual(event["event"], "adversarial-scan")
        self.assertEqual(event["seq"], 7)
        self.assertEqual(event["schema"], SCHEMA_PIN)

    def test_audit_event_bad_seq_raises(self):
        report = analyze_input("x")
        for bad in (-1, True, "7", 1.5):
            with self.assertRaises(TypeError):
                adversarial_audit_event(report, seq=bad)

    def test_determinism(self):
        x = _noise(64)
        self.assertEqual(scan_adversarial(x), scan_adversarial(x))
        self.assertEqual(analyze_input("a\u200bb").as_dict(),
                         analyze_input("a\u200bb").as_dict())


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import adversarial_detector as m
        m.main()  # raises AssertionError on self-check failure


if __name__ == "__main__":
    unittest.main()
