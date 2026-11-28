"""Tests for what a check cost in machine time.

A check over a sample is a run like any other. Its cost is a property of
the tasks, not of the code under test, and knowing it is what makes a later
run comparable.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from swe_bench_runtime import probe_runtimes, runtime_summary  # noqa: E402


def _log(root: Path, probe: str, instance: str, seconds: str) -> None:
    base = root / "logs" / "run_evaluation" / "run1" / probe / instance
    base.mkdir(parents=True, exist_ok=True)
    (base / "run_instance.log").write_text(
        f"INFO - Test runtime: {seconds} seconds\n", encoding="utf-8"
    )


class RuntimeTests(unittest.TestCase):
    def test_the_runtime_of_each_probe_is_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _log(root, "integrity-gold", "a", "60.0")
            _log(root, "integrity-empty", "a", "40.0")
            runtimes = probe_runtimes(root, "run1")
            self.assertEqual(runtimes["a"]["integrity-gold"], 60.0)
            self.assertEqual(runtimes["a"]["integrity-empty"], 40.0)

    def test_a_thousand_separator_in_the_runtime_is_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _log(root, "integrity-gold", "a", "1_871.42")
            runtimes = probe_runtimes(root, "run1")
            self.assertEqual(runtimes["a"]["integrity-gold"], 1871.42)

    def test_a_missing_log_gives_no_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(probe_runtimes(Path(tmp), "run1"), {})

    def test_the_summary_totals_the_time(self):
        runtimes = {
            "a": {"integrity-gold": 60.0, "integrity-empty": 40.0},
            "b": {"integrity-gold": 100.0},
        }
        summary = runtime_summary(runtimes)
        self.assertEqual(summary["probes_completed"], 3)
        self.assertEqual(summary["test_seconds_total"], 200.0)
        # The summary keeps the hours to two decimals.
        self.assertAlmostEqual(summary["test_hours_total"], 0.06, places=2)

    def test_the_summary_says_which_tasks_were_slowest(self):
        runtimes = {
            "a": {"integrity-gold": 60.0},
            "slow": {"integrity-gold": 900.0},
        }
        summary = runtime_summary(runtimes)
        self.assertEqual(summary["slowest_tasks"][0]["instance_id"], "slow")

    def test_the_two_probes_cost_the_same_on_average(self):
        # The time a probe takes is a property of the task's test suite, not
        # of the patch under it, so the two probes should cost alike.
        runtimes = {
            "a": {"integrity-gold": 100.0, "integrity-empty": 100.0},
            "b": {"integrity-gold": 200.0, "integrity-empty": 200.0},
        }
        summary = runtime_summary(runtimes)
        self.assertEqual(summary["by_probe"]["integrity-gold"],
                         summary["by_probe"]["integrity-empty"])


if __name__ == "__main__":
    unittest.main()
