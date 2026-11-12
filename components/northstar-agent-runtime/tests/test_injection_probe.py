"""Injection probe tests."""

import importlib.util
import sys
import unittest
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ip = _load("injection_probe")


class InjectionProbeTests(unittest.TestCase):
    def test_probe_corpus_has_attacks_and_benign_controls(self):
        self.assertGreaterEqual(len(ip.PROBES), 7)
        self.assertTrue(any(p.expected_blocked for p in ip.PROBES))
        self.assertTrue(any(not p.expected_blocked for p in ip.PROBES))
        for p in ip.PROBES:
            self.assertTrue(p.probe_id)
            self.assertIs(type(p.expected_blocked), bool)
            self.assertIn(
                p.category, ("direct_harm", "data_theft", "benign_control")
            )

    def test_run_probe_blocked(self):
        result = ip.run_probe(ip.PROBES[0], lambda tool_id, output: True)
        self.assertIs(result.blocked, True)
        self.assertIs(result.passed, True)
        self.assertEqual(result.probe_id, ip.PROBES[0].probe_id)

    def test_run_probe_allowed_is_a_missed_attack(self):
        result = ip.run_probe(ip.PROBES[0], lambda tool_id, output: False)
        self.assertIs(result.blocked, False)
        self.assertIs(result.passed, False)

    def test_gate_exception_is_an_evaluation_error(self):
        def bad_gate(tool_id, output):
            raise ValueError("sensitive exception text is not copied")

        result = ip.run_probe(ip.PROBES[0], bad_gate)
        self.assertIsNone(result.blocked)
        self.assertIsNone(result.passed)
        self.assertIn("ValueError", result.gate_reason)
        self.assertNotIn("sensitive", result.gate_reason)

    def test_non_boolean_gate_decision_is_an_evaluation_error(self):
        result = ip.run_probe(ip.PROBES[0], lambda tool_id, output: "blocked")
        self.assertIsNone(result.blocked)
        self.assertIsNone(result.passed)
        self.assertIn("non-bool", result.gate_reason)

    def test_expected_decision_must_be_boolean(self):
        probe = ip.Probe(
            probe_id="bad-expected",
            category="direct_harm",
            tool_id="read_doc",
            poisoned_output="test fixture",
            description="invalid expected decision",
            expected_blocked=1,
        )
        with self.assertRaises(ip.InjectionProbeError):
            ip.run_probe(probe, lambda tool_id, output: True)

    def test_confusion_metrics_include_benign_controls(self):
        def gate_by_id(tool_id, output):
            for probe in ip.PROBES:
                if probe.poisoned_output == output:
                    return probe.probe_id in ("inj-001", "inj-003", "inj-005")
            return False

        summary = ip.run_all_probes(gate_by_id)
        self.assertEqual(summary["total"], 7)
        self.assertEqual(summary["blocked"], 3)
        self.assertEqual(summary["allowed"], 4)
        self.assertEqual(summary["errors"], 0)
        self.assertAlmostEqual(summary["block_rate"], 3 / 7)
        self.assertEqual(summary["true_positive"], 3)
        self.assertEqual(summary["false_negative"], 2)
        self.assertEqual(summary["true_negative"], 2)
        self.assertEqual(summary["false_positive"], 0)
        self.assertAlmostEqual(summary["attack_block_rate"], 3 / 5)
        self.assertEqual(summary["false_positive_rate"], 0.0)
        self.assertAlmostEqual(summary["accuracy"], 5 / 7)

    def test_blocking_everything_reports_benign_false_positives(self):
        summary = ip.run_all_probes(lambda tool_id, output: True)
        self.assertEqual(summary["true_positive"], 5)
        self.assertEqual(summary["false_positive"], 2)
        self.assertEqual(summary["false_positive_rate"], 1.0)
        self.assertAlmostEqual(summary["accuracy"], 5 / 7)

    def test_gate_errors_cannot_improve_summary_scores(self):
        def broken_gate(tool_id, output):
            raise RuntimeError("test error")

        summary = ip.run_all_probes(broken_gate)
        self.assertEqual(summary["errors"], summary["total"])
        self.assertEqual(summary["total"], 7)
        self.assertEqual(summary["blocked"], 0)
        self.assertEqual(summary["allowed"], 0)
        self.assertEqual(summary["attack_block_rate"], 0.0)
        self.assertEqual(summary["accuracy"], 0.0)

    def test_empty_probe_set_has_defined_metrics(self):
        summary = ip.run_all_probes(lambda tool_id, output: True, probes=[])
        self.assertEqual(summary["total"], 0)
        self.assertEqual(summary["block_rate"], 0.0)
        self.assertEqual(summary["attack_block_rate"], 0.0)
        self.assertEqual(summary["false_positive_rate"], 0.0)
        self.assertEqual(summary["accuracy"], 0.0)

    def test_stdlib_only(self):
        self.assertTrue(ip.stdlib_only())

    def test_version_and_schema_pins(self):
        self.assertEqual(ip.INJECTION_PROBE_VERSION, "injection-probe.v2")
        self.assertEqual(ip.SCHEMA_PIN, "northstar.injection-probe.v2")
