"""
Experience-aware admission policy prototype: demonstrate risk-informed decisions.
"""
import unittest

from experience_ledger import ExperienceStatistics


class ExperienceAdmissionPolicyTests(unittest.TestCase):
    def test_insufficient_data_admits_with_caution(self):
        """Unknown tasks (no history) are admitted with caution, low confidence."""
        from experience_ledger import evaluate_admission
        
        stats = ExperienceStatistics(
            fingerprint="new-task",
            total_runs=0,
            successes=0,
            failures=0,
            success_rate=None,
            recent_trend="insufficient-data",
            last_n_outcomes=(),
        )
        verdict = evaluate_admission(stats)
        self.assertEqual(verdict.state, "admitted-with-caution")
        self.assertIn("insufficient-data", verdict.reason)
        self.assertLess(verdict.confidence, 0.5)
        self.assertTrue(verdict.execution_authorized)

    def test_consistent_failure_blocks_admission(self):
        """Tasks with low success rate and enough samples are blocked."""
        from experience_ledger import evaluate_admission
        
        stats = ExperienceStatistics(
            fingerprint="failing-task",
            total_runs=5,
            successes=1,
            failures=4,
            success_rate=0.2,
            recent_trend="stable",
            last_n_outcomes=("failed", "failed", "failed", "failed", "verified"),
        )
        verdict = evaluate_admission(stats, min_success_rate=0.3, min_sample_size=3)
        self.assertEqual(verdict.state, "blocked")
        self.assertIn("consistent-failure", verdict.reason)
        self.assertFalse(verdict.execution_authorized)

    def test_good_standing_admits(self):
        """Tasks with acceptable success rate are admitted."""
        from experience_ledger import evaluate_admission
        
        stats = ExperienceStatistics(
            fingerprint="decent-task",
            total_runs=10,
            successes=7,
            failures=3,
            success_rate=0.7,
            recent_trend="stable",
            last_n_outcomes=("verified", "failed", "verified", "verified", "verified"),
        )
        verdict = evaluate_admission(stats, min_success_rate=0.5)
        self.assertEqual(verdict.state, "admitted")
        self.assertGreater(verdict.confidence, 0.7)
        self.assertTrue(verdict.execution_authorized)

    def test_declining_trend_blocks_when_enabled(self):
        """Declining performance can block admission if flag set."""
        from experience_ledger import evaluate_admission
        
        stats = ExperienceStatistics(
            fingerprint="declining-task",
            total_runs=6,
            successes=3,
            failures=3,
            success_rate=0.5,
            recent_trend="declining",
            last_n_outcomes=("failed", "failed", "failed", "verified", "verified", "verified"),
        )
        verdict = evaluate_admission(stats, decline_is_blocking=True, min_sample_size=5)
        self.assertEqual(verdict.state, "blocked")
        self.assertIn("declining", verdict.reason)
        self.assertFalse(verdict.execution_authorized)

    def test_declining_trend_admits_with_warning_when_not_blocking(self):
        """Declining performance warns but admits if flag disabled."""
        from experience_ledger import evaluate_admission
        
        stats = ExperienceStatistics(
            fingerprint="declining-task",
            total_runs=6,
            successes=3,
            failures=3,
            success_rate=0.5,
            recent_trend="declining",
            last_n_outcomes=("failed", "failed", "failed", "verified", "verified", "verified"),
        )
        verdict = evaluate_admission(stats, decline_is_blocking=False, min_success_rate=0.3)
        self.assertEqual(verdict.state, "admitted-with-caution")
        self.assertIn("declining", verdict.reason)
        self.assertTrue(verdict.execution_authorized)

    def test_excellent_standing_admits_high_confidence(self):
        """Tasks with excellent track record get high confidence admission."""
        from experience_ledger import evaluate_admission
        
        stats = ExperienceStatistics(
            fingerprint="star-task",
            total_runs=12,
            successes=11,
            failures=1,
            success_rate=0.92,
            recent_trend="stable",
            last_n_outcomes=("verified", "verified", "verified", "verified", "verified"),
        )
        verdict = evaluate_admission(stats)
        self.assertEqual(verdict.state, "admitted")
        self.assertGreater(verdict.confidence, 0.9)
        self.assertTrue(verdict.execution_authorized)

    def test_small_sample_low_confidence(self):
        """Small sample size reduces confidence even when admitted."""
        from experience_ledger import evaluate_admission
        
        stats = ExperienceStatistics(
            fingerprint="new-ish-task",
            total_runs=2,
            successes=2,
            failures=0,
            success_rate=1.0,
            recent_trend="insufficient-data",
            last_n_outcomes=("verified", "verified"),
        )
        verdict = evaluate_admission(stats, min_sample_size=3)
        self.assertEqual(verdict.state, "admitted-with-caution")
        self.assertLess(verdict.confidence, 0.5)
        self.assertTrue(verdict.execution_authorized)


if __name__ == "__main__":
    unittest.main()
