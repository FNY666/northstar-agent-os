"""
Test that runtime integrates with admission ledger.
"""
import unittest
import tempfile
from pathlib import Path
from continuation_admission import ContinuationPolicy
from autonomy_checkpoint_store import AutonomyCheckpointStore
from admission_ledger import AdmissionLedger
from loop import AgentRuntime, RuntimeConfig
from sessions import SessionStore


class RuntimeAdmissionLedgerTests(unittest.TestCase):
    def test_admit_records_to_ledger(self):
        """admit_persisted_continuation_checkpoint records to ledger when provided."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="ledger-test")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="ledger-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            result = runtime.persist_continuation_checkpoint(
                store, goal={"objective": "test"}, observed_at=1000
            )
            
            ledger = AdmissionLedger(root / "admissions.jsonl")
            policy = ContinuationPolicy(max_age_seconds=60, authorize_resume=False)
            
            admission = runtime.admit_persisted_continuation_checkpoint(
                store,
                goal={"objective": "test"},
                now=1010,
                policy=policy,
                expected_record_digest=result.record_digest,
                admission_ledger=ledger,
            )
            
            # Verify admission was recorded
            records = ledger.query("ledger-test")
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].admission_digest, admission.admission_digest)
            self.assertEqual(records[0].state, "admit-continuation")
    
    def test_resume_if_authorized_records_to_ledger(self):
        """resume_if_authorized_continuation records admission to ledger."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="resume-ledger-test")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="resume-ledger-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            result = runtime.persist_continuation_checkpoint(
                store, goal={"objective": "test"}, observed_at=1000
            )
            
            ledger = AdmissionLedger(root / "admissions.jsonl")
            policy = ContinuationPolicy(
                max_age_seconds=60,
                require_pinned_checkpoint=True,
                authorize_resume=False,
            )
            
            admission, report = runtime.resume_if_authorized_continuation(
                store,
                goal={"objective": "test"},
                policy=policy,
                now=1010,
                expected_record_digest=result.record_digest,
                expected_head_digest=runtime.continuation_objective_history(store).head_digest,
                admission_ledger=ledger,
            )
            
            # Verify admission was recorded
            records = ledger.query("resume-ledger-test")
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].admission_digest, admission.admission_digest)
    
    def test_multiple_admissions_accumulate(self):
        """Multiple admission calls accumulate in ledger."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="multi-test")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="multi-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            runtime.persist_continuation_checkpoint(store, goal={"objective": "test"}, observed_at=1000)
            
            ledger = AdmissionLedger(root / "admissions.jsonl")
            policy = ContinuationPolicy(max_age_seconds=60)
            
            # First admission
            runtime.admit_persisted_continuation_checkpoint(
                store, goal={"objective": "test"}, now=1010, policy=policy, admission_ledger=ledger
            )
            
            # Second admission (same checkpoint, different time)
            runtime.admit_persisted_continuation_checkpoint(
                store, goal={"objective": "test"}, now=1020, policy=policy, admission_ledger=ledger
            )
            
            # Both should be recorded
            records = ledger.query("multi-test")
            self.assertEqual(len(records), 2)


if __name__ == "__main__":
    unittest.main()
