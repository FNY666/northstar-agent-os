"""
Test admission simulation without side effects (generation 17).
"""
import unittest
import tempfile
from pathlib import Path
from continuation_admission import ContinuationPolicy
from autonomy_checkpoint_store import AutonomyCheckpointStore
from admission_ledger import AdmissionLedger
from loop import AgentRuntime, RuntimeConfig
from sessions import SessionStore


class AdmissionSimulationTests(unittest.TestCase):
    def test_simulate_admission_returns_admission(self):
        """Simulate admission returns ContinuationAdmission."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="sim-test")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="sim-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            goal = {"objective": "test"}
            result = runtime.persist_continuation_checkpoint(store, goal=goal, observed_at=1000)
            
            policy = ContinuationPolicy(max_age_seconds=60)
            admission = runtime.simulate_admission(
                store, goal=goal, policy=policy, now=1010,
                expected_record_digest=result.record_digest,
            )
            
            # Returns admission
            self.assertIsNotNone(admission)
            self.assertEqual(admission.state, "admit-continuation")
    
    def test_simulate_admission_no_ledger_entry(self):
        """Simulate admission never writes to ledger."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="no-record")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="no-record", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            goal = {"objective": "test"}
            result = runtime.persist_continuation_checkpoint(store, goal=goal, observed_at=1000)
            
            ledger = AdmissionLedger(root / "admissions.jsonl")
            policy = ContinuationPolicy(max_age_seconds=60)
            
            # Simulate (should not record)
            runtime.simulate_admission(
                store, goal=goal, policy=policy, now=1010,
                expected_record_digest=result.record_digest,
            )
            
            # Verify no ledger entry
            records = ledger.query("no-record")
            self.assertEqual(len(records), 0)
    
    def test_real_admit_creates_ledger_entry(self):
        """Real admit creates ledger entry (contrast with simulate)."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="real-record")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="real-record", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            goal = {"objective": "test"}
            result = runtime.persist_continuation_checkpoint(store, goal=goal, observed_at=1000)
            
            ledger = AdmissionLedger(root / "admissions.jsonl")
            policy = ContinuationPolicy(max_age_seconds=60)
            
            # Real admit (should record)
            runtime.admit_persisted_continuation_checkpoint(
                store, goal=goal, policy=policy, now=1010,
                expected_record_digest=result.record_digest,
                admission_ledger=ledger,
            )
            
            # Verify ledger entry created
            records = ledger.query("real-record")
            self.assertEqual(len(records), 1)
    
    def test_simulate_then_admit_only_one_record(self):
        """Simulate then admit → only real admit recorded."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="sim-then-real")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="sim-then-real", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            goal = {"objective": "test"}
            result = runtime.persist_continuation_checkpoint(store, goal=goal, observed_at=1000)
            
            ledger = AdmissionLedger(root / "admissions.jsonl")
            policy = ContinuationPolicy(max_age_seconds=60)
            
            # Simulate first
            sim_admission = runtime.simulate_admission(
                store, goal=goal, policy=policy, now=1010,
                expected_record_digest=result.record_digest,
            )
            
            # Then real admit
            real_admission = runtime.admit_persisted_continuation_checkpoint(
                store, goal=goal, policy=policy, now=1010,
                expected_record_digest=result.record_digest,
                admission_ledger=ledger,
            )
            
            # Both return admissions
            self.assertEqual(sim_admission.state, "admit-continuation")
            self.assertEqual(real_admission.state, "admit-continuation")
            
            # Only one ledger entry
            records = ledger.query("sim-then-real")
            self.assertEqual(len(records), 1)
    
    def test_simulate_with_no_checkpoint_blocks(self):
        """Simulate with no checkpoint → blocked state."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="no-checkpoint")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="no-checkpoint", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            # No checkpoint persisted
            
            policy = ContinuationPolicy(max_age_seconds=60)
            admission = runtime.simulate_admission(
                store, goal={"objective": "test"}, policy=policy, now=1010,
            )
            
            # Should be blocked or unknown
            self.assertIn(admission.state, ["unknown", "blocked-no-checkpoint"])
    
    def test_simulate_with_stale_checkpoint_blocks(self):
        """Simulate with stale checkpoint → blocked state."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="stale-test")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="stale-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            goal = {"objective": "test"}
            result = runtime.persist_continuation_checkpoint(store, goal=goal, observed_at=1000)
            
            policy = ContinuationPolicy(max_age_seconds=60)
            # Simulate after max_age expires
            admission = runtime.simulate_admission(
                store, goal=goal, policy=policy, now=2000,  # 1000s later
                expected_record_digest=result.record_digest,
            )
            
            # Should be blocked (stale)
            self.assertTrue(admission.state.startswith("blocked"))


if __name__ == "__main__":
    unittest.main()
