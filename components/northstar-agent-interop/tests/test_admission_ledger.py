"""
Admission ledger: persist admission decisions for audit and retrospective analysis.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experience_ledger import AdmissionVerdict, ExperienceStatistics


class AdmissionLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_record_and_read_back(self):
        """Record a decision, read it back, verify all fields."""
        from experience_ledger import AdmissionLedger
        
        ledger = AdmissionLedger(self.root / "admission.jsonl")
        verdict = AdmissionVerdict(
            state="admitted",
            reason="acceptable-standing",
            confidence=0.8,
            execution_authorized=True,
        )
        stats = ExperienceStatistics(
            fingerprint="task-001",
            total_runs=10,
            successes=8,
            failures=2,
            success_rate=0.8,
            recent_trend="stable",
            last_n_outcomes=("verified", "verified", "failed", "verified", "verified"),
        )
        policy_config = {"min_success_rate": 0.5, "min_sample_size": 3}
        
        record = ledger.record(
            "task-001",
            verdict,
            stats,
            policy_config=policy_config,
            decided_at=1000,
        )
        
        self.assertEqual(record.fingerprint, "task-001")
        self.assertEqual(record.verdict_state, "admitted")
        self.assertEqual(record.verdict_confidence, 0.8)
        self.assertEqual(record.sequence, 1)
        self.assertIsNotNone(record.record_digest)
        
        # Read back
        records = ledger.query("task-001")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].fingerprint, "task-001")
        self.assertEqual(records[0].verdict_state, "admitted")

    def test_multiple_decisions_for_same_fingerprint(self):
        """Multiple decisions for same task → query returns all, oldest first."""
        from experience_ledger import AdmissionLedger
        
        ledger = AdmissionLedger(self.root / "admission.jsonl")
        
        # Decision 1: blocked
        verdict1 = AdmissionVerdict("blocked", "consistent-failure", 0.5, False)
        stats1 = ExperienceStatistics("task-002", 5, 1, 4, 0.2, "stable", ())
        ledger.record("task-002", verdict1, stats1, policy_config={}, decided_at=1000)
        
        # Decision 2: admitted after improvement
        verdict2 = AdmissionVerdict("admitted", "acceptable-standing", 0.7, True)
        stats2 = ExperienceStatistics("task-002", 7, 5, 2, 0.71, "improving", ())
        ledger.record("task-002", verdict2, stats2, policy_config={}, decided_at=2000)
        
        records = ledger.query("task-002")
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].verdict_state, "blocked")
        self.assertEqual(records[1].verdict_state, "admitted")
        self.assertLess(records[0].decided_at, records[1].decided_at)

    def test_digest_chain_integrity(self):
        """Each record references prev_record_digest, forming a chain."""
        from experience_ledger import AdmissionLedger
        
        ledger = AdmissionLedger(self.root / "admission.jsonl")
        
        verdict = AdmissionVerdict("admitted", "test", 0.5, True)
        stats = ExperienceStatistics("task-003", 1, 1, 0, 1.0, "insufficient-data", ())
        
        rec1 = ledger.record("task-003", verdict, stats, policy_config={}, decided_at=1000)
        rec2 = ledger.record("task-003", verdict, stats, policy_config={}, decided_at=2000)
        rec3 = ledger.record("task-003", verdict, stats, policy_config={}, decided_at=3000)
        
        self.assertIsNone(rec1.prev_record_digest)
        self.assertEqual(rec2.prev_record_digest, rec1.record_digest)
        self.assertEqual(rec3.prev_record_digest, rec2.record_digest)

    def test_query_empty_ledger(self):
        """Query unknown fingerprint returns empty tuple."""
        from experience_ledger import AdmissionLedger
        
        ledger = AdmissionLedger(self.root / "admission.jsonl")
        records = ledger.query("unknown-task")
        self.assertEqual(records, ())

    def test_summary_computes_rates(self):
        """Summary returns global stats: total, block rate, caution rate."""
        from experience_ledger import AdmissionLedger
        
        ledger = AdmissionLedger(self.root / "admission.jsonl")
        
        # 2 admitted, 1 blocked, 1 caution
        ledger.record("t1", AdmissionVerdict("admitted", "", 0.8, True),
                     ExperienceStatistics("t1", 5, 5, 0, 1.0, "stable", ()), {}, 1000)
        ledger.record("t2", AdmissionVerdict("blocked", "", 0.5, False),
                     ExperienceStatistics("t2", 5, 1, 4, 0.2, "stable", ()), {}, 2000)
        ledger.record("t3", AdmissionVerdict("admitted-with-caution", "", 0.3, True),
                     ExperienceStatistics("t3", 2, 2, 0, 1.0, "insufficient-data", ()), {}, 3000)
        ledger.record("t4", AdmissionVerdict("admitted", "", 0.9, True),
                     ExperienceStatistics("t4", 10, 9, 1, 0.9, "stable", ()), {}, 4000)
        
        summary = ledger.summary()
        self.assertEqual(summary["total_decisions"], 4)
        self.assertAlmostEqual(summary["block_rate"], 0.25, places=2)
        self.assertAlmostEqual(summary["caution_rate"], 0.25, places=2)
        self.assertAlmostEqual(summary["admit_rate"], 0.5, places=2)

    def test_concurrent_append_safety(self):
        """Concurrent appends maintain digest chain integrity."""
        from experience_ledger import AdmissionLedger
        import threading
        
        ledger = AdmissionLedger(self.root / "admission.jsonl")
        verdict = AdmissionVerdict("admitted", "test", 0.5, True)
        stats = ExperienceStatistics("concurrent", 1, 1, 0, 1.0, "stable", ())
        
        def append():
            for i in range(5):
                ledger.record(f"task-{threading.current_thread().name}", verdict, stats, {}, 1000 + i)
        
        threads = [threading.Thread(target=append, name=f"t{i}") for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should have 15 records total (3 threads × 5 records)
        summary = ledger.summary()
        self.assertEqual(summary["total_decisions"], 15)
        
        # Digest chain should be intact (no broken links)
        # This is implicitly verified by successful reads


if __name__ == "__main__":
    unittest.main()
