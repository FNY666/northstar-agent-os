"""
Experience trend analysis tests.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experience_ledger import ExperienceLedger


class ExperienceTrendAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.experience = ExperienceLedger(self.root / "experience.jsonl")

    def tearDown(self):
        self.tempdir.cleanup()

    def test_improving_trend_detected(self):
        """Improving performance → positive trend."""
        from experience_ledger import analyze_trend
        
        # Build improving history: 0% → 100% success rate
        for i in range(10):
            forecast = self.experience.forecast("task-001")
            verdict = "verified" if i >= 5 else "failed"  # First 5 fail, last 5 succeed
            self.experience.settle(
                forecast,
                actual_verdict=verdict,
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        trend = analyze_trend(self.experience, "task-001")
        
        self.assertEqual(trend.trend_direction, "improving")
        self.assertGreater(trend.trend_strength, 0.5)
        self.assertFalse(trend.has_degradation)

    def test_declining_trend_detected(self):
        """Declining performance → negative trend."""
        from experience_ledger import analyze_trend
        
        # Build declining history: 100% → 0% success rate
        for i in range(10):
            forecast = self.experience.forecast("task-002")
            verdict = "verified" if i < 5 else "failed"  # First 5 succeed, last 5 fail
            self.experience.settle(
                forecast,
                actual_verdict=verdict,
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        trend = analyze_trend(self.experience, "task-002")
        
        self.assertEqual(trend.trend_direction, "declining")
        self.assertGreater(trend.trend_strength, 0.5)
        self.assertTrue(trend.has_degradation)

    def test_stable_trend_detected(self):
        """Consistent performance → stable trend."""
        from experience_ledger import analyze_trend
        
        # Build stable history: always succeed
        for i in range(10):
            forecast = self.experience.forecast("task-003")
            self.experience.settle(
                forecast,
                actual_verdict="verified",
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        trend = analyze_trend(self.experience, "task-003")
        
        self.assertEqual(trend.trend_direction, "stable")
        self.assertLess(trend.recent_volatility, 0.1)

    def test_volatile_trend_detected(self):
        """Erratic performance → volatile trend."""
        from experience_ledger import analyze_trend
        
        # Build volatile history: alternating success/failure
        for i in range(10):
            forecast = self.experience.forecast("task-004")
            verdict = "verified" if i % 2 == 0 else "failed"
            self.experience.settle(
                forecast,
                actual_verdict=verdict,
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        trend = analyze_trend(self.experience, "task-004")
        
        self.assertEqual(trend.trend_direction, "volatile")
        self.assertGreater(trend.recent_volatility, 0.3)

    def test_change_point_detected(self):
        """Sudden change in performance → change point."""
        from experience_ledger import analyze_trend
        
        # Build history with sudden change at index 5
        for i in range(10):
            forecast = self.experience.forecast("task-005")
            verdict = "verified" if i >= 5 else "failed"
            self.experience.settle(
                forecast,
                actual_verdict=verdict,
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        trend = analyze_trend(self.experience, "task-005")
        
        # Should detect change around index 5
        self.assertGreater(len(trend.change_points), 0)
        self.assertIn(5, trend.change_points)

    def test_insufficient_data_returns_insufficient(self):
        """< min_samples → insufficient data."""
        from experience_ledger import analyze_trend
        
        # Only 2 samples
        for i in range(2):
            forecast = self.experience.forecast("task-006")
            self.experience.settle(
                forecast,
                actual_verdict="verified",
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        trend = analyze_trend(self.experience, "task-006", min_samples=5)
        
        self.assertEqual(trend.trend_direction, "insufficient-data")

    def test_prediction_based_on_trend(self):
        """Predict next success rate based on trend."""
        from experience_ledger import analyze_trend
        
        # Build improving history
        for i in range(10):
            forecast = self.experience.forecast("task-007")
            verdict = "verified" if i >= 5 else "failed"
            self.experience.settle(
                forecast,
                actual_verdict=verdict,
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        trend = analyze_trend(self.experience, "task-007")
        
        # Prediction should be high (improving trend)
        self.assertGreater(trend.predicted_next_success_rate, 0.5)


if __name__ == "__main__":
    unittest.main()
