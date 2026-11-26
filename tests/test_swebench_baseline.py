"""Contract tests for the baseline-aware verdict.

The rule under test: a pass-to-pass test that already failed before the
patch was applied must not count against the patch.  The exclusion is
recorded, never silent.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "scripts" / "swebench_baseline.py"


def _module():
    spec = importlib.util.spec_from_file_location("swebench_baseline", MODULE)
    module = importlib.util.module_from_spec(spec)
    sys.modules["swebench_baseline"] = module
    spec.loader.exec_module(module)
    return module


def _entry(f2p_success=(), f2p_failure=(), p2p_success=(), p2p_failure=()):
    return {
        "tests_status": {
            "FAIL_TO_PASS": {"success": list(f2p_success), "failure": list(f2p_failure)},
            "PASS_TO_PASS": {"success": list(p2p_success), "failure": list(p2p_failure)},
        }
    }


class BaselineExclusionTests(unittest.TestCase):
    def setUp(self):
        self.mod = _module()

    def test_a_test_that_failed_at_baseline_is_excluded(self):
        """The case that started this: the fix is right, the network is not."""
        current = _entry(
            f2p_success=["t::fixed"],
            p2p_success=["t::ok"],
            p2p_failure=["t::needs_network"],
        )
        baseline = _entry(p2p_failure=["t::needs_network"])
        verdict = self.mod.rejudge(current, baseline)
        self.assertEqual(verdict["status"], "RESOLVED_FULL")
        self.assertEqual(verdict["excluded_p2p"], ["t::needs_network"])

    def test_without_a_baseline_the_verdict_is_unchanged(self):
        current = _entry(f2p_success=["t::fixed"], p2p_failure=["t::broken"])
        verdict = self.mod.rejudge(current, None)
        self.assertEqual(verdict["status"], "RESOLVED_NO")
        self.assertEqual(verdict["excluded_p2p"], [])

    def test_a_test_the_patch_broke_is_not_excluded(self):
        """It passed at baseline and fails now: that is the patch's doing."""
        current = _entry(f2p_success=["t::fixed"], p2p_failure=["t::broken"])
        baseline = _entry(p2p_success=["t::broken"])
        verdict = self.mod.rejudge(current, baseline)
        self.assertEqual(verdict["status"], "RESOLVED_NO")
        self.assertEqual(verdict["excluded_p2p"], [])

    def test_a_test_the_patch_fixed_is_not_excluded(self):
        """It failed at baseline and passes now; it simply stays a success."""
        current = _entry(f2p_success=["t::fixed"], p2p_success=["t::repaired"])
        baseline = _entry(p2p_failure=["t::repaired"])
        verdict = self.mod.rejudge(current, baseline)
        self.assertEqual(verdict["status"], "RESOLVED_FULL")
        self.assertEqual(verdict["excluded_p2p"], [])

    def test_partial_stays_partial_when_the_remaining_failures_stay(self):
        current = _entry(
            f2p_success=["t::a"], f2p_failure=["t::b"],
            p2p_success=["t::ok"], p2p_failure=["t::needs_network"],
        )
        baseline = _entry(p2p_failure=["t::needs_network"])
        verdict = self.mod.rejudge(current, baseline)
        self.assertEqual(verdict["status"], "RESOLVED_PARTIAL")

    def test_a_missing_baseline_section_excludes_nothing(self):
        """A baseline without a p2p section says nothing about p2p tests."""
        current = _entry(f2p_success=["t::fixed"], p2p_failure=["t::x"])
        verdict = self.mod.rejudge(current, {"tests_status": {}})
        self.assertEqual(verdict["excluded_p2p"], [])
        self.assertEqual(verdict["status"], "RESOLVED_NO")

    def test_an_empty_pass_to_pass_list_does_not_block_a_resolved_verdict(self):
        """The upstream rule: no p2p tests means nothing to maintain."""
        current = _entry(f2p_success=["t::fixed"])
        verdict = self.mod.rejudge(current, _entry())
        self.assertEqual(verdict["status"], "RESOLVED_FULL")

    def test_load_baseline_reads_the_upstream_report_shape(self):
        payload = {
            "psf__requests-1921": {
                "patch_successfully_applied": True,
                "tests_status": {
                    "PASS_TO_PASS": {"success": [], "failure": ["t::x"]},
                },
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = self.mod.load_baseline(path)
        self.assertIn("psf__requests-1921", loaded)
        self.assertEqual(
            self.mod.baseline_p2p_failures(loaded["psf__requests-1921"]), {"t::x"}
        )

    def test_load_baseline_rejects_a_file_that_is_not_a_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(ValueError):
                self.mod.load_baseline(path)


if __name__ == "__main__":
    unittest.main()
