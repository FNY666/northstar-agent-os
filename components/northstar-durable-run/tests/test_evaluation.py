import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))

from evaluation import BenchmarkSummary, run_fixture_benchmark  # noqa: E402


class FixtureEvaluationTests(unittest.TestCase):
    def test_ten_fixed_fixtures_report_task_level_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = run_fixture_benchmark(Path(directory), case_count=10)
        self.assertIsInstance(summary, BenchmarkSummary)
        self.assertEqual(summary.total, 10)
        self.assertEqual(summary.verified, 10)
        self.assertEqual(summary.failed, 0)
        self.assertEqual(summary.unknown, 0)
        self.assertEqual(summary.recovered, 3)
        self.assertEqual(summary.duplicate_side_effects, 0)
        self.assertEqual(len(summary.results), 10)
        self.assertEqual(summary.to_dict()["completion_rate"], 1.0)
        self.assertEqual(summary.to_dict()["verification_rate"], 1.0)
        self.assertEqual(summary.to_dict()["recovery_rate"], 1.0)

    def test_evaluation_rejects_unbounded_case_count_and_preserves_failure_class(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                run_fixture_benchmark(Path(directory), case_count=0)
            with self.assertRaises(ValueError):
                run_fixture_benchmark(Path(directory), case_count=101)
            summary = run_fixture_benchmark(Path(directory), case_count=2, fail_case=1)
        self.assertEqual(summary.total, 2)
        self.assertEqual(summary.verified, 1)
        self.assertEqual(summary.failed, 1)
        self.assertEqual(summary.unknown, 0)
        self.assertEqual(summary.results["fixture-001"]["failure_class"], "postcondition")

    def test_evaluation_output_contains_no_prompt_or_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = run_fixture_benchmark(Path(directory), case_count=1)
        rendered = repr(summary.to_dict())
        self.assertNotIn("prompt", rendered.lower())
        self.assertNotIn("secret", rendered.lower())
        self.assertNotIn("fixture request", rendered.lower())


if __name__ == "__main__":
    unittest.main()
