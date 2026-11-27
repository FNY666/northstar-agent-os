"""Tests for the benchmark confidence interval."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


def _load():
    path = Path(__file__).resolve().parent.parent / "scripts" / "swe_bench_confidence.py"
    spec = importlib.util.spec_from_file_location("swe_bench_confidence", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["swe_bench_confidence"] = module
    spec.loader.exec_module(module)
    return module


class IntervalTests(unittest.TestCase):
    def setUp(self):
        self.mod = _load()

    def test_the_interval_contains_the_estimate(self):
        for successes, trials in ((31, 50), (0, 50), (50, 50), (1, 10)):
            low, high = self.mod.wilson_interval(successes, trials)
            self.assertLessEqual(low, successes / trials)
            self.assertGreaterEqual(high, successes / trials)

    def test_the_interval_stays_inside_the_unit_range(self):
        low, high = self.mod.wilson_interval(0, 20)
        self.assertEqual(low, 0.0)
        self.assertLessEqual(high, 1.0)
        low, high = self.mod.wilson_interval(20, 20)
        self.assertGreaterEqual(low, 0.0)
        self.assertLessEqual(high, 1.0)

    def test_the_interval_narrows_as_the_sample_grows(self):
        narrow = self.mod.wilson_interval(500, 1000)
        wide = self.mod.wilson_interval(50, 100)
        self.assertGreater(narrow[1] - narrow[0], 0.0)
        self.assertLess(narrow[1] - narrow[0], wide[1] - wide[0])

    def test_no_trials_gives_no_interval(self):
        low, high = self.mod.wilson_interval(0, 0)
        self.assertEqual((low, high), (0.0, 0.0))

    def test_a_known_value_matches_the_published_formula(self):
        # Wilson interval for 31 of 50, as worked out by hand.
        low, high = self.mod.wilson_interval(31, 50)
        self.assertAlmostEqual(low, 0.4815, places=3)
        self.assertAlmostEqual(high, 0.7414, places=3)

    def test_the_summary_names_its_method(self):
        summary = self.mod.summarise(31, 50)
        self.assertEqual(summary["interval_method"], "wilson")
        self.assertEqual(summary["successes"], 31)
        self.assertEqual(summary["trials"], 50)
        self.assertAlmostEqual(summary["rate"], 0.62, places=4)
        self.assertAlmostEqual(summary["standard_error"], 0.0686, places=4)

    def test_the_standard_error_of_a_half_is_the_well_known_value(self):
        self.assertAlmostEqual(self.mod.standard_error(25, 100), 0.0433, places=4)


if __name__ == "__main__":
    unittest.main()
