"""
Generation 8: Enhanced admission policy with multi-dimensional evaluation.

Tests for evaluate_admission_v2() with:
- Multi-dimensional scoring (standing + trend + conflicts + data_quality)
- Adaptive thresholds based on global statistics
- Policy modes: conservative / balanced / aggressive
"""
import tempfile
import time
import unittest
from pathlib import Path

from experience_ledger import (
    AdmissionLedger,
    ExperienceLedger,
    ExperienceStatistics,
    evaluate_admission_v2,
)


class AdmissionPolicyV2Tests(unittest.TestCase):
    """Test enhanced multi-dimensional admission policy."""

    def setUp(self):
        """Create temp ledgers for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.ledger_path = Path(self.temp_dir) / "experience.jsonl"
        self.admission_path = Path(self.temp_dir) / "admission.jsonl"
        self.ledger = ExperienceLedger(self.ledger_path)
        self.admission_ledger = AdmissionLedger(self.admission_path)

    def test_no_evidence_admits_with_tofu_balanced_mode(self):
        """No history → admit with TOFU (Trust On First Use), low confidence."""
        verdict = evaluate_admission_v2(
            self.ledger,
            "new-fingerprint",
            policy_mode="balanced",
            admission_ledger=self.admission_ledger,
        )
        
        self.assertEqual(verdict.state, "admitted")
        self.assertEqual(verdict.reason, "no-evidence-tofu")
        self.assertLess(verdict.confidence, 0.3)
        self.assertTrue(verdict.execution_authorized)

    def test_consistent_failure_blocks_all_modes(self):
        """Consistent failure with high confidence blocks in all modes."""
        # Build history: 5 failures
        for i in range(5):
            forecast = self.ledger.forecast("failing-task")
            self.ledger.settle(
                forecast,
                actual_verdict="failed",
                run_id=f"run-{i}",
                run_digest=f"digest-{i}",
                event_head=f"event-{i}",
            )
        
        for mode in ["conservative", "balanced", "aggressive"]:
            verdict = evaluate_admission_v2(
                self.ledger,
                "failing-task",
                policy_mode=mode,
                admission_ledger=self.admission_ledger,
            )
            
            self.assertEqual(verdict.state, "blocked", f"Failed for mode {mode}")
            self.assertIn("consistent-failure", verdict.reason)
            self.assertFalse(verdict.execution_authorized)

    def test_degradation_with_strong_trend_raises_caution(self):
        """Degrading performance (was good, now failing) → caution."""
        # Build history: 5 successes, then 3 failures
        for i in range(5):
            forecast = self.ledger.forecast("degrading-task")
            self.ledger.settle(
                forecast,
                actual_verdict="verified",
                run_id=f"run-success-{i}",
                run_digest=f"digest-{i}",
                event_head=f"event-{i}",
            )
        
        for i in range(3):
            forecast = self.ledger.forecast("degrading-task")
            self.ledger.settle(
                forecast,
                actual_verdict="failed",
                run_id=f"run-fail-{i}",
                run_digest=f"digest-fail-{i}",
                event_head=f"event-fail-{i}",
            )
        
        verdict = evaluate_admission_v2(
            self.ledger,
            "degrading-task",
            policy_mode="balanced",
            admission_ledger=self.admission_ledger,
        )
        
        self.assertEqual(verdict.state, "admitted-with-caution")
        self.assertIn("degradation", verdict.reason)
        self.assertTrue(verdict.execution_authorized)

    def test_conflicts_raise_caution(self):
        """High conflict count in admission history → caution."""
        # Create conflicting admission records
        stats = ExperienceStatistics(
            fingerprint="conflicted-task",
            total_runs=5,
            successes=3,
            failures=2,
            success_rate=0.6,
            recent_trend="stable",
            last_n_outcomes=("verified", "failed", "verified", "verified", "failed"),
        )
        
        # Record admit → block → admit (creates conflicts)
        from experience_ledger import AdmissionVerdict
        
        verdict1 = AdmissionVerdict("admitted", "good-standing", 0.8, True)
        self.admission_ledger.record(
            "conflicted-task", verdict1, stats, {}, int(time.time())
        )
        
        verdict2 = AdmissionVerdict("blocked", "test-block", 0.8, False)
        self.admission_ledger.record(
            "conflicted-task", verdict2, stats, {}, int(time.time()) + 1
        )
        
        verdict3 = AdmissionVerdict("admitted", "override", 0.8, True)
        self.admission_ledger.record(
            "conflicted-task", verdict3, stats, {}, int(time.time()) + 2
        )
        
        # Now evaluate with conflicts present
        # (Need some experience history too)
        for i in range(5):
            forecast = self.ledger.forecast("conflicted-task")
            verdict_type = "verified" if i < 3 else "failed"
            self.ledger.settle(
                forecast,
                actual_verdict=verdict_type,
                run_id=f"run-{i}",
                run_digest=f"digest-{i}",
                event_head=f"event-{i}",
            )
        
        verdict = evaluate_admission_v2(
            self.ledger,
            "conflicted-task",
            policy_mode="balanced",
            admission_ledger=self.admission_ledger,
        )
        
        self.assertEqual(verdict.state, "admitted-with-caution")
        self.assertIn("conflicts", verdict.reason)

    def test_data_quality_unverifiable_raises_caution(self):
        """Contradicted standing → data quality unverifiable → caution."""
        # Build contradicted history: success then failure
        forecast1 = self.ledger.forecast("contradicted-task")
        self.ledger.settle(
            forecast1,
            actual_verdict="verified",
            run_id="run-success",
            run_digest="digest-success",
            event_head="event-success",
        )
        
        forecast2 = self.ledger.forecast("contradicted-task")
        self.ledger.settle(
            forecast2,
            actual_verdict="failed",
            run_id="run-fail",
            run_digest="digest-fail",
            event_head="event-fail",
        )
        
        verdict = evaluate_admission_v2(
            self.ledger,
            "contradicted-task",
            policy_mode="balanced",
            admission_ledger=self.admission_ledger,
        )
        
        self.assertEqual(verdict.state, "admitted-with-caution")
        self.assertIn("unverifiable", verdict.reason)

    def test_conservative_mode_stricter_thresholds(self):
        """Conservative mode blocks more aggressively than balanced."""
        # Build marginal history: 5 runs, 60% success
        for i in range(3):
            forecast = self.ledger.forecast("marginal-task")
            self.ledger.settle(
                forecast,
                actual_verdict="verified",
                run_id=f"run-success-{i}",
                run_digest=f"digest-{i}",
                event_head=f"event-{i}",
            )
        
        for i in range(2):
            forecast = self.ledger.forecast("marginal-task")
            self.ledger.settle(
                forecast,
                actual_verdict="failed",
                run_id=f"run-fail-{i}",
                run_digest=f"digest-fail-{i}",
                event_head=f"event-fail-{i}",
            )
        
        verdict_conservative = evaluate_admission_v2(
            self.ledger,
            "marginal-task",
            policy_mode="conservative",
            admission_ledger=self.admission_ledger,
        )
        
        verdict_balanced = evaluate_admission_v2(
            self.ledger,
            "marginal-task",
            policy_mode="balanced",
            admission_ledger=self.admission_ledger,
        )
        
        # Conservative should be more restrictive
        # (blocked or at least lower confidence/caution)
        if verdict_conservative.state == "blocked":
            self.assertNotEqual(verdict_balanced.state, "blocked")
        else:
            # If both admit, conservative should have lower confidence
            self.assertLessEqual(
                verdict_conservative.confidence, verdict_balanced.confidence
            )

    def test_aggressive_mode_more_permissive(self):
        """Aggressive mode admits more readily than balanced."""
        # Build minimal history: 2 runs, 1 success, 1 failure
        forecast1 = self.ledger.forecast("risky-task")
        self.ledger.settle(
            forecast1,
            actual_verdict="verified",
            run_id="run-1",
            run_digest="digest-1",
            event_head="event-1",
        )
        
        forecast2 = self.ledger.forecast("risky-task")
        self.ledger.settle(
            forecast2,
            actual_verdict="failed",
            run_id="run-2",
            run_digest="digest-2",
            event_head="event-2",
        )
        
        verdict_aggressive = evaluate_admission_v2(
            self.ledger,
            "risky-task",
            policy_mode="aggressive",
            admission_ledger=self.admission_ledger,
        )
        
        verdict_balanced = evaluate_admission_v2(
            self.ledger,
            "risky-task",
            policy_mode="balanced",
            admission_ledger=self.admission_ledger,
        )
        
        # Aggressive should admit or have higher confidence
        if verdict_balanced.state == "blocked":
            self.assertNotEqual(verdict_aggressive.state, "blocked")
        elif verdict_balanced.state == "admitted-with-caution":
            # Aggressive might upgrade to admitted
            self.assertIn(verdict_aggressive.state, ["admitted", "admitted-with-caution"])

    def test_excellent_standing_high_confidence_all_modes(self):
        """Excellent track record → admitted with high confidence in all modes."""
        # Build excellent history: 10 successes
        for i in range(10):
            forecast = self.ledger.forecast("star-task")
            self.ledger.settle(
                forecast,
                actual_verdict="verified",
                run_id=f"run-{i}",
                run_digest=f"digest-{i}",
                event_head=f"event-{i}",
            )
        
        for mode in ["conservative", "balanced", "aggressive"]:
            verdict = evaluate_admission_v2(
                self.ledger,
                "star-task",
                policy_mode=mode,
                admission_ledger=self.admission_ledger,
            )
            
            self.assertEqual(verdict.state, "admitted", f"Failed for mode {mode}")
            self.assertGreater(verdict.confidence, 0.85, f"Low confidence for {mode}")
            self.assertTrue(verdict.execution_authorized)

    def test_confidence_increases_with_sample_size(self):
        """More data → higher confidence (capped at 1.0)."""
        # Test with different sample sizes
        for n in [3, 5, 10, 15]:
            fp = f"task-{n}-samples"
            for i in range(n):
                forecast = self.ledger.forecast(fp)
                self.ledger.settle(
                    forecast,
                    actual_verdict="verified",
                    run_id=f"run-{i}",
                    run_digest=f"digest-{i}",
                    event_head=f"event-{i}",
                )
            
            verdict = evaluate_admission_v2(
                self.ledger, fp, policy_mode="balanced"
            )
            
            # Confidence should grow with sample size (roughly n/10, capped at 1.0)
            expected_min = min(0.9, n / 10.0 - 0.1)
            self.assertGreater(verdict.confidence, expected_min)


if __name__ == "__main__":
    unittest.main()
