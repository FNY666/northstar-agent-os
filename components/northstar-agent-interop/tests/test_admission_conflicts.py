"""
Admission conflict detection: identify contradictory decisions for audit.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experience_ledger import (
    AdmissionLedger,
    AdmissionVerdict,
    ExperienceStatistics,
)


class AdmissionConflictDetectionTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.ledger = AdmissionLedger(self.root / "admission.jsonl")

    def tearDown(self):
        self.tempdir.cleanup()

    def test_no_conflicts_in_empty_ledger(self):
        """Empty ledger returns no conflicts."""
        from experience_ledger import detect_conflicts
        
        conflicts = detect_conflicts(self.ledger)
        self.assertEqual(conflicts, ())

    def test_no_conflicts_for_single_decision(self):
        """Single decision cannot conflict with itself."""
        from experience_ledger import detect_conflicts
        
        verdict = AdmissionVerdict("admitted", "test", 0.8, True)
        stats = ExperienceStatistics("task-001", 10, 8, 2, 0.8, "stable", ())
        self.ledger.record("task-001", verdict, stats, {}, 1000)
        
        conflicts = detect_conflicts(self.ledger)
        self.assertEqual(conflicts, ())

    def test_admit_then_block_detected(self):
        """Admitted → Blocked is a conflict."""
        from experience_ledger import detect_conflicts
        
        stats = ExperienceStatistics("task-002", 5, 3, 2, 0.6, "stable", ())
        
        # First: admitted
        verdict1 = AdmissionVerdict("admitted", "acceptable", 0.6, True)
        self.ledger.record("task-002", verdict1, stats, {}, 1000)
        
        # Later: blocked (same stats!)
        verdict2 = AdmissionVerdict("blocked", "consistent-failure", 0.6, False)
        self.ledger.record("task-002", verdict2, stats, {}, 1300)
        
        conflicts = detect_conflicts(self.ledger)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].conflict_type, "admit-vs-block")
        self.assertEqual(conflicts[0].earlier.verdict_state, "admitted")
        self.assertEqual(conflicts[0].later.verdict_state, "blocked")
        self.assertEqual(conflicts[0].time_delta, 300)

    def test_block_then_admit_detected(self):
        """Blocked → Admitted is a conflict (could be override)."""
        from experience_ledger import detect_conflicts
        
        stats1 = ExperienceStatistics("task-003", 5, 1, 4, 0.2, "stable", ())
        stats2 = ExperienceStatistics("task-003", 7, 5, 2, 0.71, "improving", ())
        
        # First: blocked
        verdict1 = AdmissionVerdict("blocked", "consistent-failure", 0.5, False)
        self.ledger.record("task-003", verdict1, stats1, {}, 1000)
        
        # Later: admitted (improved stats)
        verdict2 = AdmissionVerdict("admitted", "acceptable", 0.7, True)
        self.ledger.record("task-003", verdict2, stats2, {}, 2000)
        
        conflicts = detect_conflicts(self.ledger)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].conflict_type, "block-vs-admit")

    def test_state_change_detected(self):
        """Any state change is flagged (admitted ↔ caution)."""
        from experience_ledger import detect_conflicts
        
        stats = ExperienceStatistics("task-004", 3, 3, 0, 1.0, "insufficient-data", ())
        
        verdict1 = AdmissionVerdict("admitted-with-caution", "insufficient-data", 0.3, True)
        self.ledger.record("task-004", verdict1, stats, {}, 1000)
        
        verdict2 = AdmissionVerdict("admitted", "acceptable", 0.5, True)
        self.ledger.record("task-004", verdict2, stats, {}, 1500)
        
        conflicts = detect_conflicts(self.ledger)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].conflict_type, "state-change")

    def test_no_conflict_for_different_tasks(self):
        """Different fingerprints don't conflict."""
        from experience_ledger import detect_conflicts
        
        verdict = AdmissionVerdict("blocked", "test", 0.5, False)
        stats = ExperienceStatistics("task-A", 5, 1, 4, 0.2, "stable", ())
        self.ledger.record("task-A", verdict, stats, {}, 1000)
        
        stats2 = ExperienceStatistics("task-B", 5, 1, 4, 0.2, "stable", ())
        self.ledger.record("task-B", verdict, stats2, {}, 1100)
        
        conflicts = detect_conflicts(self.ledger)
        self.assertEqual(conflicts, ())

    def test_window_filter_excludes_old_conflicts(self):
        """Window filter only returns recent conflicts."""
        from experience_ledger import detect_conflicts
        
        stats = ExperienceStatistics("task-005", 5, 3, 2, 0.6, "stable", ())
        
        # Old conflict (2000 seconds ago)
        verdict1 = AdmissionVerdict("admitted", "test", 0.6, True)
        self.ledger.record("task-005", verdict1, stats, {}, 1000)
        verdict2 = AdmissionVerdict("blocked", "test", 0.6, False)
        self.ledger.record("task-005", verdict2, stats, {}, 3000)
        
        # Recent conflict (100 seconds ago)
        verdict3 = AdmissionVerdict("admitted", "test", 0.6, True)
        self.ledger.record("task-005", verdict3, stats, {}, 3100)
        
        # Only recent conflicts (within 500 seconds)
        conflicts = detect_conflicts(self.ledger, window_seconds=500)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].time_delta, 100)


if __name__ == "__main__":
    unittest.main()
