"""Tests for the benchmark sample integrity check."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import swe_bench_integrity as mod  # noqa: E402


def _lists(f2p_passed: list[str], f2p_failed: list[str], p2p_passed: list[str], p2p_failed: list[str]):
    """One grader report's worth of test lists."""
    return {
        "FAIL_TO_PASS": {"passed": f2p_passed, "failed": f2p_failed},
        "PASS_TO_PASS": {"passed": p2p_passed, "failed": p2p_failed},
    }


class JudgeTests(unittest.TestCase):
    def test_a_task_that_separates_a_fix_from_a_no_op_is_trustworthy(self):
        gold = _lists(["t::fixed"], [], ["t::kept"], [])
        empty = _lists([], ["t::fixed"], ["t::kept"], [])
        item = mod.judge_instance("i", "RESOLVED_FULL", "RESOLVED_NO", gold, empty)
        self.assertEqual(item.verdict, mod.TRUSTWORTHY)

    def test_a_task_whose_fail_to_pass_already_passes_is_not_trustworthy(self):
        gold = _lists(["t::fixed"], [], [], [])
        empty = _lists(["t::fixed"], [], [], [])
        item = mod.judge_instance("i", "RESOLVED_FULL", "RESOLVED_FULL", gold, empty)
        self.assertEqual(item.verdict, mod.EMPTY_ACCEPTED)
        self.assertIn("without a patch", item.detail)
        self.assertIn("t::fixed", item.fail_to_pass_passing_when_empty)

    def test_a_reference_patch_that_fails_on_tests_which_pass_without_a_patch_is_told_apart(self):
        # The reference patch breaks a test that passes with no patch at
        # all. The task's fail-to-pass list is fine, but the patch itself
        # cannot be judged by that test.
        gold = _lists(["t::fixed"], [], ["t::kept"], ["t::broke"])
        empty = _lists([], ["t::fixed"], ["t::kept", "t::broke"], [])
        item = mod.judge_instance("i", "RESOLVED_PARTIAL", "RESOLVED_NO", gold, empty)
        self.assertEqual(item.verdict, mod.GOLD_PARTIAL)
        self.assertIn("t::broke", item.gold_failures_also_passing_when_empty)

    def test_tests_that_fail_under_both_probes_are_listed(self):
        gold = _lists([], ["t::env"], [], [])
        empty = _lists([], ["t::env"], [], [])
        item = mod.judge_instance("i", "RESOLVED_NO", "RESOLVED_NO", gold, empty)
        self.assertIn("t::env", item.failures_under_both)

    def test_a_probe_without_a_verdict_is_inconclusive_not_broken(self):
        item = mod.judge_instance("i", None, "RESOLVED_NO")
        self.assertEqual(item.verdict, mod.INCONCLUSIVE)
        self.assertIn("gold", item.detail)

    def test_an_untrustworthy_task_is_not_silently_dropped(self):
        report = mod.report_from_probes(
            [("a", "RESOLVED_FULL", "RESOLVED_NO"), ("b", "RESOLVED_NO", "RESOLVED_NO")]
        )
        self.assertEqual(len(report.instances), 2)
        self.assertEqual(report.instance_ids(), ["a"])
        self.assertEqual(len(report.untrustworthy), 1)

    def test_a_partial_resolution_is_not_a_pass(self):
        self.assertFalse(mod._is_pass("RESOLVED_PARTIAL"))
        self.assertTrue(mod._is_pass("RESOLVED_FULL"))

    def test_the_test_lists_are_read_from_the_grader_report(self):
        report = {
            "tests_status": {
                "FAIL_TO_PASS": {"success": ["t::a"], "failure": []},
                "PASS_TO_PASS": {"success": ["t::b"], "failure": ["t::c"]},
            }
        }
        lists = mod._test_lists(report)
        self.assertEqual(lists["FAIL_TO_PASS"]["passed"], ["t::a"])
        self.assertEqual(lists["PASS_TO_PASS"]["failed"], ["t::c"])

    def test_a_report_without_test_lists_is_not_usable(self):
        self.assertIsNone(mod._test_lists({"resolved": True}))
        self.assertIsNone(mod._test_lists("not a report"))


if __name__ == "__main__":
    unittest.main()
