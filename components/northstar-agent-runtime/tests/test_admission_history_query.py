"""
Test admission history query by fingerprint (generation 19).
"""
import unittest
import tempfile
from pathlib import Path
from continuation_admission import ContinuationPolicy, ContinuationAdmission, evaluate_continuation_admission
from autonomy_checkpoint_store import AutonomyCheckpointStore
from admission_ledger import AdmissionLedger
from experience_integration import derive_fingerprint
from loop import AgentRuntime, RuntimeConfig
from sessions import SessionStore


# Test fingerprints (valid SHA256 hex format)
TEST_FP_1 = "a" * 64  # Valid 64-char hex
TEST_FP_2 = "b" * 64
TEST_FP_3 = "c" * 64


class AdmissionHistoryQueryTests(unittest.TestCase):
    """Test query_by_fingerprint method."""
    
    def test_empty_ledger_returns_empty(self):
        """Empty ledger returns empty list for any fingerprint."""
        with tempfile.TemporaryDirectory() as root:
            ledger = AdmissionLedger(Path(root) / "ledger.jsonl")
            
            results = ledger.query_by_fingerprint(TEST_FP_1)
            
            self.assertEqual(results, [])
    
    def test_no_matches_returns_empty(self):
        """Fingerprint with no admissions returns empty list."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "ledger.jsonl")
            
            # Record admission for different goal
            sessions = SessionStore(root, session_id="test")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            goal1 = {"objective": "goal-1"}
            runtime.persist_continuation_checkpoint(store, goal=goal1, observed_at=1000)
            
            policy = ContinuationPolicy(max_age_seconds=60)
            admission = runtime.admit_persisted_continuation_checkpoint(
                store, goal=goal1, now=1010, policy=policy
            )
            ledger.record("test", admission, observed_at=1010, goal_fingerprint=derive_fingerprint(goal1))
            
            # Query for different fingerprint
            goal2 = {"objective": "goal-2"}
            fp2 = derive_fingerprint(goal2)
            
            results = ledger.query_by_fingerprint(fp2)
            
            self.assertEqual(results, [])
    
    def test_single_match_returns_one_record(self):
        """Single admission for fingerprint returns that record."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "ledger.jsonl")
            
            sessions = SessionStore(root, session_id="single")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="single", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            goal = {"objective": "single-test"}
            result = runtime.persist_continuation_checkpoint(store, goal=goal, observed_at=1000)
            
            policy = ContinuationPolicy(max_age_seconds=60)
            admission = runtime.admit_persisted_continuation_checkpoint(
                store, goal=goal, now=1010, policy=policy,
                expected_record_digest=result.record_digest
            )
            ledger.record("single", admission, observed_at=1010, goal_fingerprint=derive_fingerprint(goal))
            
            fp = derive_fingerprint(goal)
            results = ledger.query_by_fingerprint(fp)
            
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].session_id, "single")
            self.assertEqual(results[0].state, "admit-continuation")
    
    def test_multiple_sessions_same_fingerprint(self):
        """Returns records from all sessions with same fingerprint."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "ledger.jsonl")
            goal = {"objective": "shared-goal"}
            
            # Session 1
            sessions1 = SessionStore(root, session_id="session-1")
            runtime1 = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="session-1", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions1,
            )
            store1 = AutonomyCheckpointStore(root / "checkpoints-1.jsonl")
            runtime1.persist_continuation_checkpoint(store1, goal=goal, observed_at=1000)
            policy = ContinuationPolicy(max_age_seconds=60)
            admission1 = runtime1.admit_persisted_continuation_checkpoint(
                store1, goal=goal, now=1010, policy=policy
            )
            ledger.record("session-1", admission1, observed_at=1010, goal_fingerprint=derive_fingerprint(goal))
            
            # Session 2
            sessions2 = SessionStore(root, session_id="session-2")
            runtime2 = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="session-2", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions2,
            )
            store2 = AutonomyCheckpointStore(root / "checkpoints-2.jsonl")
            runtime2.persist_continuation_checkpoint(store2, goal=goal, observed_at=2000)
            admission2 = runtime2.admit_persisted_continuation_checkpoint(
                store2, goal=goal, now=2010, policy=policy
            )
            ledger.record("session-2", admission2, observed_at=2010, goal_fingerprint=derive_fingerprint(goal))
            
            fp = derive_fingerprint(goal)
            results = ledger.query_by_fingerprint(fp)
            
            self.assertEqual(len(results), 2)
            session_ids = {r.session_id for r in results}
            self.assertEqual(session_ids, {"session-1", "session-2"})
    
    def test_session_filter(self):
        """session_id parameter filters to single session."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "ledger.jsonl")
            goal = {"objective": "filter-test"}
            policy = ContinuationPolicy(max_age_seconds=60)
            
            # Record for session-1
            sessions1 = SessionStore(root, session_id="session-1")
            runtime1 = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="session-1", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions1,
            )
            store1 = AutonomyCheckpointStore(root / "checkpoints-1.jsonl")
            runtime1.persist_continuation_checkpoint(store1, goal=goal, observed_at=1000)
            admission1 = runtime1.admit_persisted_continuation_checkpoint(
                store1, goal=goal, now=1010, policy=policy
            )
            ledger.record("session-1", admission1, observed_at=1010, goal_fingerprint=derive_fingerprint(goal))
            
            # Record for session-2
            sessions2 = SessionStore(root, session_id="session-2")
            runtime2 = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="session-2", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions2,
            )
            store2 = AutonomyCheckpointStore(root / "checkpoints-2.jsonl")
            runtime2.persist_continuation_checkpoint(store2, goal=goal, observed_at=2000)
            admission2 = runtime2.admit_persisted_continuation_checkpoint(
                store2, goal=goal, now=2010, policy=policy
            )
            ledger.record("session-2", admission2, observed_at=2010, goal_fingerprint=derive_fingerprint(goal))
            
            fp = derive_fingerprint(goal)
            results = ledger.query_by_fingerprint(fp, session_id="session-1")
            
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].session_id, "session-1")
    
    def test_time_window_filtering(self):
        """since and until parameters filter by observed_at."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "ledger.jsonl")
            goal = {"objective": "time-test"}
            policy = ContinuationPolicy(max_age_seconds=600)
            
            sessions = SessionStore(root, session_id="time-session")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="time-session", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            
            # Record 3 admissions at different times
            for t in [1000, 2000, 3000]:
                runtime.persist_continuation_checkpoint(store, goal=goal, observed_at=t)
                admission = runtime.admit_persisted_continuation_checkpoint(
                    store, goal=goal, now=t + 10, policy=policy
                )
                ledger.record("time-session", admission, observed_at=t + 10, goal_fingerprint=derive_fingerprint(goal))
            
            fp = derive_fingerprint(goal)
            
            # Query with since filter
            results_since = ledger.query_by_fingerprint(fp, since=1500)
            self.assertEqual(len(results_since), 2)
            self.assertTrue(all(r.observed_at >= 1500 for r in results_since))
            
            # Query with until filter
            results_until = ledger.query_by_fingerprint(fp, until=2500)
            self.assertEqual(len(results_until), 2)
            self.assertTrue(all(r.observed_at <= 2500 for r in results_until))
            
            # Query with both filters
            results_both = ledger.query_by_fingerprint(fp, since=1500, until=2500)
            self.assertEqual(len(results_both), 1)
            self.assertEqual(results_both[0].observed_at, 2010)
    
    def test_chronological_order(self):
        """Results sorted by observed_at ascending."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "ledger.jsonl")
            goal = {"objective": "order-test"}
            policy = ContinuationPolicy(max_age_seconds=600)
            
            sessions = SessionStore(root, session_id="order-session")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="order-session", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            
            # Record in non-chronological order
            for t in [3000, 1000, 2000]:
                runtime.persist_continuation_checkpoint(store, goal=goal, observed_at=t)
                admission = runtime.admit_persisted_continuation_checkpoint(
                    store, goal=goal, now=t + 10, policy=policy
                )
                ledger.record("order-session", admission, observed_at=t + 10, goal_fingerprint=derive_fingerprint(goal))
            
            fp = derive_fingerprint(goal)
            results = ledger.query_by_fingerprint(fp)
            
            self.assertEqual(len(results), 3)
            observed_times = [r.observed_at for r in results]
            self.assertEqual(observed_times, sorted(observed_times))
    
    def test_invalid_fingerprint_format_rejected(self):
        """Invalid fingerprint format raises error."""
        with tempfile.TemporaryDirectory() as root:
            ledger = AdmissionLedger(Path(root) / "ledger.jsonl")
            
            with self.assertRaises(ValueError) as ctx:
                ledger.query_by_fingerprint("")
            
            self.assertIn("fingerprint", str(ctx.exception).lower())


class RuntimeAdmissionHistoryTests(unittest.TestCase):
    """Test runtime adapter for admission history queries."""
    
    def test_query_admission_history_by_goal(self):
        """Runtime provides convenience method for goal-based queries."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "ledger.jsonl")
            goal = {"objective": "runtime-query"}
            
            sessions = SessionStore(root, session_id="runtime-test")
            runtime = AgentRuntime(
                provider=lambda **kw: None,
                config=RuntimeConfig(session_id="runtime-test", workspace=str(root), max_budget_usd=1.0),
                sessions=sessions,
            )
            
            store = AutonomyCheckpointStore(root / "checkpoints.jsonl")
            runtime.persist_continuation_checkpoint(store, goal=goal, observed_at=1000)
            
            policy = ContinuationPolicy(max_age_seconds=60)
            admission = runtime.admit_persisted_continuation_checkpoint(
                store, goal=goal, now=1010, policy=policy
            )
            ledger.record("runtime-test", admission, observed_at=1010, goal_fingerprint=derive_fingerprint(goal))
            
            # Query through runtime adapter
            results = runtime.query_admission_history_by_goal(ledger, goal=goal)
            
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].session_id, "runtime-test")


if __name__ == "__main__":
    unittest.main()
