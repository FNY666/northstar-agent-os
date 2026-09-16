"""
Experience statistics query: return structured performance metrics for a fingerprint.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experience_ledger import ExperienceLedger


class ExperienceStatisticsTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.ledger = ExperienceLedger(self.root / "experience.jsonl")

    def tearDown(self):
        self.tempdir.cleanup()

    def test_empty_ledger_returns_zero_statistics(self):
        """Empty ledger returns total_runs=0, success_rate=None, insufficient-data."""
        stats = self.ledger.query_statistics("task-001")
        self.assertEqual(stats.fingerprint, "task-001")
        self.assertEqual(stats.total_runs, 0)
        self.assertEqual(stats.successes, 0)
        self.assertEqual(stats.failures, 0)
        self.assertIsNone(stats.success_rate)
        self.assertEqual(stats.recent_trend, "insufficient-data")
        self.assertEqual(stats.last_n_outcomes, ())
        self.assertFalse(stats.execution_authorized)

    def test_all_success_returns_perfect_rate(self):
        """All successful runs return success_rate=1.0, trend=stable."""
        for i in range(3):
            forecast = self.ledger.forecast(f"task-001")
            self.ledger.settle(
                forecast,
                actual_verdict="verified",
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        stats = self.ledger.query_statistics("task-001")
        self.assertEqual(stats.total_runs, 3)
        self.assertEqual(stats.successes, 3)
        self.assertEqual(stats.failures, 0)
        self.assertEqual(stats.success_rate, 1.0)
        self.assertEqual(stats.recent_trend, "stable")
        self.assertEqual(len(stats.last_n_outcomes), 3)
        self.assertTrue(all(v == "verified" for v in stats.last_n_outcomes))

    def test_all_failure_returns_zero_rate(self):
        """All failed runs return success_rate=0.0, trend=stable."""
        for i in range(3):
            forecast = self.ledger.forecast(f"task-002")
            self.ledger.settle(
                forecast,
                actual_verdict="failed",
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        stats = self.ledger.query_statistics("task-002")
        self.assertEqual(stats.total_runs, 3)
        self.assertEqual(stats.successes, 0)
        self.assertEqual(stats.failures, 3)
        self.assertEqual(stats.success_rate, 0.0)
        self.assertEqual(stats.recent_trend, "stable")

    def test_mixed_history_computes_correct_rate(self):
        """Mixed success/failure computes accurate success_rate."""
        verdicts = ["failed", "verified", "failed", "verified", "verified"]
        for i, verdict in enumerate(verdicts):
            forecast = self.ledger.forecast(f"task-003")
            self.ledger.settle(
                forecast,
                actual_verdict=verdict,
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        stats = self.ledger.query_statistics("task-003")
        self.assertEqual(stats.total_runs, 5)
        self.assertEqual(stats.successes, 3)
        self.assertEqual(stats.failures, 2)
        self.assertAlmostEqual(stats.success_rate, 0.6, places=2)

    def test_recent_improvement_detected(self):
        """Recent successes after failures → trend=improving."""
        verdicts = ["failed", "failed", "failed", "verified", "verified"]
        for i, verdict in enumerate(verdicts):
            forecast = self.ledger.forecast(f"task-004")
            self.ledger.settle(
                forecast,
                actual_verdict=verdict,
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        stats = self.ledger.query_statistics("task-004", recent_window=3)
        self.assertEqual(stats.recent_trend, "improving")

    def test_recent_decline_detected(self):
        """Recent failures after successes → trend=declining."""
        verdicts = ["verified", "verified", "verified", "failed", "failed"]
        for i, verdict in enumerate(verdicts):
            forecast = self.ledger.forecast(f"task-005")
            self.ledger.settle(
                forecast,
                actual_verdict=verdict,
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        stats = self.ledger.query_statistics("task-005", recent_window=3)
        self.assertEqual(stats.recent_trend, "declining")

    def test_last_n_outcomes_ordered_recent_first(self):
        """last_n_outcomes returns recent-first order."""
        verdicts = ["failed", "verified", "verified"]
        for i, verdict in enumerate(verdicts):
            forecast = self.ledger.forecast(f"task-006")
            self.ledger.settle(
                forecast,
                actual_verdict=verdict,
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        stats = self.ledger.query_statistics("task-006", recent_window=5)
        self.assertEqual(stats.last_n_outcomes, ("verified", "verified", "failed"))


if __name__ == "__main__":
    unittest.main()
