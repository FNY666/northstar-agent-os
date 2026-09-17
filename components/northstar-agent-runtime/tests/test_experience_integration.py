"""
Test experience-aware admission integration (Phase 3 MVP).
"""
import unittest
import tempfile
from pathlib import Path
from continuation_admission import ContinuationPolicy
from autonomy_checkpoint_store import AutonomyCheckpointStore
from experience_integration import derive_fingerprint
from loop import AgentRuntime, RuntimeConfig
from sessions import SessionStore


class MockExperienceLedger:
    """Mock experience ledger for testing."""
    def __init__(self):
        self.queries = []
    
    def query_called_with(self, fingerprint):
        self.queries.append(fingerprint)
        return True


class MockExperienceState:
    """Mock ExperienceState for testing."""
    def __init__(self, fingerprint: str, standing: str = "no-evidence"):
        self.fingerprint = fingerprint
        self.standing = standing
        self.confidence = 0.0
        self.recent_trend = "insufficient-data"
        self.last_admission = None
        self.conflict_count = 0
        self.data_quality = "verified"


def mock_project_state(ledger, fingerprint, **kwargs):
    """Mock project_state function."""
    ledger.query_called_with(fingerprint)
    return MockExperienceState(fingerprint)


class ExperienceIntegrationTests(unittest.TestCase):
    def test_derive_fingerprint_deterministic(self):
        """Same goal produces same fingerprint."""
        goal1 = {"objective": "test", "value": 42}
        goal2 = {"value": 42, "objective": "test"}  # Different order
        
        fp1 = derive_fingerprint(goal1)
        fp2 = derive_fingerprint(goal2)
        
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 64)  # SHA256 hex
    
    def test_admit_with_experience_check_returns_both_values(self):
        """admit_with_experience_check returns (admission, exp_state) tuple."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="exp-test")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="exp-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            result = runtime.persist_continuation_checkpoint(
                store, goal={"objective": "test"}, observed_at=1000
            )
            
            experience = MockExperienceLedger()
            policy = ContinuationPolicy(max_age_seconds=60)
            
            admission, exp_state = runtime.admit_with_experience_check(
                store,
                experience,
                goal={"objective": "test"},
                policy=policy,
                now=1010,
            )
            
            # Verify both values returned
            self.assertIsNotNone(admission)
            self.assertIsNotNone(exp_state)
            # Experience state should have expected fields
            self.assertIsNotNone(exp_state.fingerprint)
            self.assertIsNotNone(exp_state.standing)
            self.assertIsNotNone(exp_state.data_quality)
    
    def test_admit_with_experience_no_fingerprint_auto_derives(self):
        """When fingerprint not provided, auto-derive from goal."""
        goal = {"objective": "auto-derive"}
        expected_fp = derive_fingerprint(goal)
        
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="auto-fp")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="auto-fp", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            runtime.persist_continuation_checkpoint(store, goal=goal, observed_at=1000)
            
            experience = MockExperienceLedger()
            policy = ContinuationPolicy(max_age_seconds=60)
            
            admission, exp_state = runtime.admit_with_experience_check(
                store, experience, goal=goal, policy=policy, now=1010
            )
            
            # Verify fingerprint was derived and used
            self.assertEqual(exp_state.fingerprint, expected_fp)
    
    def test_admission_logic_unchanged(self):
        """Admission logic works same as before (backward compatible)."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="compat")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="compat", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            result = runtime.persist_continuation_checkpoint(
                store, goal={"objective": "test"}, observed_at=1000
            )
            
            experience = MockExperienceLedger()
            policy = ContinuationPolicy(max_age_seconds=60)
            
            admission, exp_state = runtime.admit_with_experience_check(
                store, experience, goal={"objective": "test"}, 
                policy=policy, now=1010,
                expected_record_digest=result.record_digest,
            )
            
            # Admission should be successful (same logic as before)
            self.assertEqual(admission.state, "admit-continuation")


if __name__ == "__main__":
    unittest.main()
