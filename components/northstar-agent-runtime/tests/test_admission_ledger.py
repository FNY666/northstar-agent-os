"""
Test that admission decisions can be persisted to an auditable ledger.
"""
import unittest
import tempfile
from pathlib import Path
from continuation_admission import ContinuationPolicy, ContinuationAdmission
from autonomy_checkpoint_store import AutonomyCheckpointStore
from loop import AgentRuntime, RuntimeConfig
from sessions import SessionStore


class AdmissionLedgerTests(unittest.TestCase):
    def test_record_and_query_admission(self):
        """Recording an admission allows querying it later."""
        from admission_ledger import AdmissionLedger
        
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "admissions.jsonl")
            
            # Create a mock admission
            admission = ContinuationAdmission(
                state="admit-continuation",
                reasons=(),
                unresolved=(),
                policy_digest="test-policy-digest",
                checkpoint_digest="test-checkpoint-digest",
                age_seconds=10,
                verdict_state="current-pinned",
                execution_authorized=False,
                admission_digest="test-admission-digest",
            )
            
            # Record it
            record = ledger.record(
                session_id="test-session",
                admission=admission,
                observed_at=1000
            )
            
            self.assertIsNotNone(record.sequence)
            self.assertEqual(record.session_id, "test-session")
            self.assertEqual(record.admission_digest, "test-admission-digest")
            
            # Query it back
            results = ledger.query(session_id="test-session")
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].admission_digest, "test-admission-digest")
    
    def test_multiple_admissions_chronological_order(self):
        """Multiple admissions are returned in chronological order."""
        from admission_ledger import AdmissionLedger
        
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "admissions.jsonl")
            
            admission1 = ContinuationAdmission(
                "admit-continuation", (), (), "p1", "c1", 5, "current-pinned", False, "a1"
            )
            admission2 = ContinuationAdmission(
                "blocked-continuation-stale", ("stale",), (), "p2", "c2", 100, "stale", False, "a2"
            )
            
            ledger.record("session-1", admission1, observed_at=1000)
            ledger.record("session-1", admission2, observed_at=1010)
            
            results = ledger.query(session_id="session-1")
            self.assertEqual(len(results), 2)
            self.assertEqual(results[0].admission_digest, "a1")
            self.assertEqual(results[1].admission_digest, "a2")
            self.assertLess(results[0].observed_at, results[1].observed_at)
    
    def test_no_ledger_backward_compatible(self):
        """Runtime admission works without ledger (backward compatible)."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sessions = SessionStore(root, session_id="compat-test")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="compat-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            result = runtime.persist_continuation_checkpoint(
                store, goal={"objective": "test"}, observed_at=1000
            )
            
            policy = ContinuationPolicy(max_age_seconds=60, authorize_resume=False)
            
            # No admission_ledger parameter provided
            admission = runtime.admit_persisted_continuation_checkpoint(
                store,
                goal={"objective": "test"},
                now=1010,
                policy=policy,
                expected_record_digest=result.record_digest,
            )
            
            # Should still work
            self.assertEqual(admission.state, "admit-continuation")
    
    def test_concurrent_writes(self):
        """Concurrent admission records are both preserved."""
        from admission_ledger import AdmissionLedger
        import threading
        
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "admissions.jsonl")
            
            admission1 = ContinuationAdmission(
                "admit-continuation", (), (), "p1", "c1", 5, "current-pinned", False, "a1"
            )
            admission2 = ContinuationAdmission(
                "admit-continuation", (), (), "p2", "c2", 10, "current-pinned", False, "a2"
            )
            
            results = []
            
            def record_admission(adm, sess):
                rec = ledger.record(sess, adm, observed_at=1000)
                results.append(rec)
            
            t1 = threading.Thread(target=record_admission, args=(admission1, "s1"))
            t2 = threading.Thread(target=record_admission, args=(admission2, "s2"))
            
            t1.start()
            t2.start()
            t1.join()
            t2.join()
            
            # Both should be recorded
            all_records = ledger.query("s1") + ledger.query("s2")
            self.assertEqual(len(all_records), 2)
            digests = {r.admission_digest for r in all_records}
            self.assertEqual(digests, {"a1", "a2"})
    
    def test_corrupted_ledger_fails_closed(self):
        """Corrupted ledger raises error on query."""
        from admission_ledger import AdmissionLedger, AdmissionLedgerError
        
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger_path = root / "admissions.jsonl"
            
            # Write corrupted JSON
            ledger_path.write_text('{"sequence": 1, "invalid\n')
            
            ledger = AdmissionLedger(ledger_path)
            
            with self.assertRaises(AdmissionLedgerError) as cm:
                ledger.query("any-session")
            
            self.assertIn("corrupted", str(cm.exception).lower())
    
    def test_missing_ledger_returns_empty(self):
        """Querying non-existent ledger returns empty list."""
        from admission_ledger import AdmissionLedger
        
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "does-not-exist.jsonl")
            
            results = ledger.query("any-session")
            self.assertEqual(results, [])
    
    def test_same_admission_recorded_twice_preserved(self):
        """Recording same admission twice creates two entries (not deduped)."""
        from admission_ledger import AdmissionLedger
        
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "admissions.jsonl")
            
            admission = ContinuationAdmission(
                "admit-continuation", (), (), "p1", "c1", 5, "current-pinned", False, "a1"
            )
            
            ledger.record("session-1", admission, observed_at=1000)
            ledger.record("session-1", admission, observed_at=1001)
            
            results = ledger.query("session-1")
            self.assertEqual(len(results), 2)
            self.assertEqual(results[0].admission_digest, "a1")
            self.assertEqual(results[1].admission_digest, "a1")
            # Different sequence numbers
            self.assertNotEqual(results[0].sequence, results[1].sequence)


if __name__ == "__main__":
    unittest.main()
