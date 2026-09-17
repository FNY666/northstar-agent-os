"""
End-to-end integration test for Phase 3 (runtime ↔ experience).

Tests the complete flow:
1. Create real ExperienceLedger with historical data
2. Call admit_with_experience_check()
3. Verify ExperienceState correctly reflects history
4. Verify admission logic unaffected by experience query
"""
import unittest
import tempfile
from pathlib import Path
from continuation_admission import ContinuationPolicy
from autonomy_checkpoint_store import AutonomyCheckpointStore
from experience_integration import derive_fingerprint
from loop import AgentRuntime, RuntimeConfig
from sessions import SessionStore


class Phase3IntegrationTests(unittest.TestCase):
    """End-to-end tests with real experience_ledger module."""
    
    def setUp(self):
        """Check if experience_ledger is available."""
        try:
            from experience_ledger import ExperienceLedger, project_state
            self.experience_available = True
        except ImportError:
            self.experience_available = False
    
    def test_consistent_success_history(self):
        """Consistent success history → high confidence standing."""
        if not self.experience_available:
            self.skipTest("experience_ledger module not available")
        
        from experience_ledger import ExperienceLedger
        
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            
            # Setup runtime
            sessions = SessionStore(root, session_id="success-test")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="success-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            # Setup checkpoint
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            goal = {"objective": "test-success"}
            result = runtime.persist_continuation_checkpoint(store, goal=goal, observed_at=1000)
            
            # Create experience with success history
            experience = ExperienceLedger(root / "experience.jsonl")
            fingerprint = derive_fingerprint(goal)
            
            # Record 5 successful runs
            for i in range(5):
                forecast = experience.forecast(fingerprint)
                experience.settle(
                    forecast,
                    actual_verdict="verified",
                    run_id=f"run-{i}",
                    run_digest=None,
                    event_head=None,
                )
            
            # Admit with experience check
            policy = ContinuationPolicy(max_age_seconds=60)
            admission, exp_state = runtime.admit_with_experience_check(
                store, experience, goal=goal, policy=policy, now=1010,
                expected_record_digest=result.record_digest,
            )
            
            # Verify admission successful
            self.assertEqual(admission.state, "admit-continuation")
            
            # Verify experience state
            self.assertEqual(exp_state.fingerprint, fingerprint)
            self.assertEqual(exp_state.standing, "consistent-success")
            self.assertGreater(exp_state.confidence, 0.4)  # 5 samples → 0.5 confidence
            self.assertEqual(exp_state.data_quality, "verified")
    
    def test_consistent_failure_history(self):
        """Consistent failure history → low standing (advisory)."""
        if not self.experience_available:
            self.skipTest("experience_ledger module not available")
        
        from experience_ledger import ExperienceLedger
        
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            
            sessions = SessionStore(root, session_id="failure-test")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="failure-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            goal = {"objective": "test-failure"}
            result = runtime.persist_continuation_checkpoint(store, goal=goal, observed_at=1000)
            
            experience = ExperienceLedger(root / "experience.jsonl")
            fingerprint = derive_fingerprint(goal)
            
            # Record 5 failed runs
            for i in range(5):
                forecast = experience.forecast(fingerprint)
                experience.settle(
                    forecast,
                    actual_verdict="failed",
                    run_id=f"run-{i}",
                    run_digest=None,
                    event_head=None,
                )
            
            policy = ContinuationPolicy(max_age_seconds=60)
            admission, exp_state = runtime.admit_with_experience_check(
                store, experience, goal=goal, policy=policy, now=1010,
                expected_record_digest=result.record_digest,
            )
            
            # Admission still succeeds (advisory mode, not blocking)
            self.assertEqual(admission.state, "admit-continuation")
            
            # But experience shows consistent failure
            self.assertEqual(exp_state.standing, "consistent-failure")
    
    def test_no_history_tofu(self):
        """No history → no-evidence standing (TOFU)."""
        if not self.experience_available:
            self.skipTest("experience_ledger module not available")
        
        from experience_ledger import ExperienceLedger
        
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            
            sessions = SessionStore(root, session_id="tofu-test")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="tofu-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            goal = {"objective": "test-tofu"}
            result = runtime.persist_continuation_checkpoint(store, goal=goal, observed_at=1000)
            
            # Empty experience ledger
            experience = ExperienceLedger(root / "experience.jsonl")
            
            policy = ContinuationPolicy(max_age_seconds=60)
            admission, exp_state = runtime.admit_with_experience_check(
                store, experience, goal=goal, policy=policy, now=1010,
                expected_record_digest=result.record_digest,
            )
            
            # Admission succeeds
            self.assertEqual(admission.state, "admit-continuation")
            
            # Experience shows no evidence
            self.assertEqual(exp_state.standing, "no-evidence")
            self.assertEqual(exp_state.confidence, 0.0)
    
    def test_contradicted_history(self):
        """Mixed success/failure → contradicted standing."""
        if not self.experience_available:
            self.skipTest("experience_ledger module not available")
        
        from experience_ledger import ExperienceLedger
        
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            
            sessions = SessionStore(root, session_id="contradicted-test")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="contradicted-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            goal = {"objective": "test-contradicted"}
            result = runtime.persist_continuation_checkpoint(store, goal=goal, observed_at=1000)
            
            experience = ExperienceLedger(root / "experience.jsonl")
            fingerprint = derive_fingerprint(goal)
            
            # Record mixed results (3 success, 2 failure)
            for i in range(5):
                forecast = experience.forecast(fingerprint)
                verdict = "verified" if i < 3 else "failed"
                experience.settle(
                    forecast,
                    actual_verdict=verdict,
                    run_id=f"run-{i}",
                    run_digest=None,
                    event_head=None,
                )
            
            policy = ContinuationPolicy(max_age_seconds=60)
            admission, exp_state = runtime.admit_with_experience_check(
                store, experience, goal=goal, policy=policy, now=1010,
                expected_record_digest=result.record_digest,
            )
            
            # Admission succeeds
            self.assertEqual(admission.state, "admit-continuation")
            
            # Experience shows contradiction
            self.assertEqual(exp_state.standing, "contradicted")
    
    def test_experience_query_failure_degrades_gracefully(self):
        """Experience query failure → degraded state, admission proceeds."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            
            sessions = SessionStore(root, session_id="fail-open-test")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="fail-open-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            goal = {"objective": "test-fail-open"}
            result = runtime.persist_continuation_checkpoint(store, goal=goal, observed_at=1000)
            
            # Pass invalid experience ledger (will cause query failure)
            invalid_experience = None
            
            policy = ContinuationPolicy(max_age_seconds=60)
            admission, exp_state = runtime.admit_with_experience_check(
                store, invalid_experience, goal=goal, policy=policy, now=1010,
                expected_record_digest=result.record_digest,
            )
            
            # Admission succeeds (fail-open)
            self.assertEqual(admission.state, "admit-continuation")
            
            # Experience state degraded
            self.assertEqual(exp_state.data_quality, "unverifiable")


if __name__ == "__main__":
    unittest.main()
