"""Tests for the sample integrity check."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


def _load():
    path = Path(__file__).resolve().parent.parent / "scripts" / "swe_bench_integrity.py"
    spec = importlib.util.spec_from_file_location("swe_bench_integrity", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["swe_bench_integrity"] = module
    spec.loader.exec_module(module)
    return module


class JudgeTests(unittest.TestCase):
    def setUp(self):
        self.mod = _load()

    def test_a_task_that_separates_the_two_patches_is_trustworthy(self):
        judged = self.mod.judge_instance("a", "RESOLVED_FULL", "RESOLVED_NO")
        self.assertEqual(judged.verdict, self.mod.TRUSTWORTHY)
        self.assertTrue(judged.is_trustworthy)

    def test_a_task_that_rejects_the_reference_patch_is_not_trustworthy(self):
        judged = self.mod.judge_instance("a", "RESOLVED_NO", "RESOLVED_NO")
        self.assertEqual(judged.verdict, self.mod.GOLD_REJECTED)
        self.assertFalse(judged.is_trustworthy)

    def test_a_task_that_accepts_the_empty_patch_is_not_trustworthy(self):
        judged = self.mod.judge_instance("a", "RESOLVED_FULL", "RESOLVED_FULL")
        self.assertEqual(judged.verdict, self.mod.EMPTY_ACCEPTED)
        self.assertFalse(judged.is_trustworthy)

    def test_a_missing_verdict_is_inconclusive_not_broken(self):
        judged = self.mod.judge_instance("a", None, "RESOLVED_NO")
        self.assertEqual(judged.verdict, self.mod.INCONCLUSIVE)
        self.assertFalse(judged.is_trustworthy)
        self.assertIn("gold", judged.detail)

    def test_a_partial_resolution_is_not_a_pass(self):
        judged = self.mod.judge_instance("a", "RESOLVED_PARTIAL", "RESOLVED_NO")
        self.assertEqual(judged.verdict, self.mod.GOLD_REJECTED)

    def test_the_verdict_survives_a_change_of_case(self):
        judged = self.mod.judge_instance("a", "resolved_full", "resolved_no")
        self.assertEqual(judged.verdict, self.mod.TRUSTWORTHY)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.mod = _load()

    def test_the_report_counts_what_it_found(self):
        report = self.mod.report_from_probes([
            ("a", "RESOLVED_FULL", "RESOLVED_NO"),
            ("b", "RESOLVED_FULL", "RESOLVED_NO"),
            ("c", "RESOLVED_NO", "RESOLVED_NO"),
            ("d", "RESOLVED_FULL", "RESOLVED_FULL"),
            ("e", None, None),
        ])
        summary = report.summary()
        self.assertEqual(summary["instances"], 5)
        self.assertEqual(summary["trustworthy"], 2)
        self.assertEqual(summary["untrustworthy"], 3)
        self.assertEqual(summary["verdicts"][self.mod.TRUSTWORTHY], 2)
        self.assertEqual(summary["verdicts"][self.mod.INCONCLUSIVE], 1)

    def test_the_trustworthy_ids_are_listed(self):
        report = self.mod.report_from_probes([
            ("a", "RESOLVED_FULL", "RESOLVED_NO"),
            ("b", "RESOLVED_NO", "RESOLVED_NO"),
        ])
        self.assertEqual(report.instance_ids(), ["a"])

    def test_an_untrustworthy_task_is_not_dropped_silently(self):
        report = self.mod.report_from_probes([("b", "RESOLVED_NO", "RESOLVED_NO")])
        self.assertEqual(len(report.untrustworthy), 1)
        self.assertEqual(report.untrustworthy[0].instance_id, "b")


if __name__ == "__main__":
    unittest.main()
