"""
Test that admission ledger can detect conflicts between decisions.
"""
import unittest
import tempfile
from pathlib import Path
from continuation_admission import ContinuationAdmission
from admission_ledger import AdmissionLedger


class AdmissionConflictTests(unittest.TestCase):
    def test_admit_then_block_detected(self):
        """Admitting then blocking same checkpoint is detected as conflict."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "admissions.jsonl")
            
            # First: admit
            admit = ContinuationAdmission(
                "admit-continuation", (), (), "p1", "checkpoint-1", 5, "current-pinned", False, "a1"
            )
            ledger.record("session-1", admit, observed_at=1000)
            
            # Later: block same checkpoint
            block = ContinuationAdmission(
                "blocked-continuation-stale", ("stale",), (), "p2", "checkpoint-1", 100, "stale", False, "a2"
            )
            ledger.record("session-1", block, observed_at=1100)
            
            # Detect conflicts
            conflicts = ledger.detect_conflicts("session-1")
            
            self.assertEqual(len(conflicts), 1)
            self.assertEqual(conflicts[0].checkpoint_digest, "checkpoint-1")
            self.assertEqual(conflicts[0].conflict_type, "admit-vs-block")
            self.assertEqual(conflicts[0].earlier_state, "admit-continuation")
            self.assertEqual(conflicts[0].later_state, "blocked-continuation-stale")
    
    def test_block_then_admit_detected(self):
        """Blocking then admitting same checkpoint is detected (policy loosened)."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "admissions.jsonl")
            
            block = ContinuationAdmission(
                "blocked-continuation-age", ("expired",), (), "p1", "checkpoint-2", 100, "stale", False, "b1"
            )
            ledger.record("session-2", block, observed_at=2000)
            
            admit = ContinuationAdmission(
                "admit-continuation", (), (), "p2", "checkpoint-2", 10, "current-pinned", False, "a1"
            )
            ledger.record("session-2", admit, observed_at=2100)
            
            conflicts = ledger.detect_conflicts("session-2")
            
            self.assertEqual(len(conflicts), 1)
            self.assertEqual(conflicts[0].conflict_type, "block-vs-admit")
    
    def test_different_checkpoints_no_conflict(self):
        """Different checkpoints do not conflict."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "admissions.jsonl")
            
            admit1 = ContinuationAdmission(
                "admit-continuation", (), (), "p1", "checkpoint-A", 5, "current-pinned", False, "a1"
            )
            ledger.record("session-3", admit1, observed_at=3000)
            
            block2 = ContinuationAdmission(
                "blocked-continuation-stale", ("stale",), (), "p2", "checkpoint-B", 100, "stale", False, "b1"
            )
            ledger.record("session-3", block2, observed_at=3100)
            
            conflicts = ledger.detect_conflicts("session-3")
            
            self.assertEqual(len(conflicts), 0)
    
    def test_same_admit_state_change_detected(self):
        """Two admits with different reasons is a state-change conflict."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "admissions.jsonl")
            
            admit1 = ContinuationAdmission(
                "admit-continuation", (), (), "p1", "checkpoint-C", 5, "current-pinned", False, "a1"
            )
            ledger.record("session-4", admit1, observed_at=4000)
            
            admit2 = ContinuationAdmission(
                "admit-continuation-unpinned", (), ("unpinned",), "p2", "checkpoint-C", 10, "current-unpinned", False, "a2"
            )
            ledger.record("session-4", admit2, observed_at=4100)
            
            conflicts = ledger.detect_conflicts("session-4")
            
            self.assertEqual(len(conflicts), 1)
            self.assertEqual(conflicts[0].conflict_type, "state-change")
    
    def test_window_filter(self):
        """Window parameter limits conflicts to recent decisions."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "admissions.jsonl")
            
            # Old admission
            admit_old = ContinuationAdmission(
                "admit-continuation", (), (), "p1", "checkpoint-D", 5, "current-pinned", False, "a1"
            )
            ledger.record("session-5", admit_old, observed_at=5000)
            
            # Recent block (1000s later)
            block_recent = ContinuationAdmission(
                "blocked-continuation-stale", ("stale",), (), "p2", "checkpoint-D", 100, "stale", False, "b1"
            )
            ledger.record("session-5", block_recent, observed_at=6000)
            
            # Without window: conflict detected
            conflicts_all = ledger.detect_conflicts("session-5")
            self.assertEqual(len(conflicts_all), 1)
            
            # With window=500: no conflict (delta=1000 > window)
            conflicts_windowed = ledger.detect_conflicts("session-5", window_seconds=500)
            self.assertEqual(len(conflicts_windowed), 0)
    
    def test_single_admission_no_conflict(self):
        """Single admission has no conflicts."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "admissions.jsonl")
            
            admit = ContinuationAdmission(
                "admit-continuation", (), (), "p1", "checkpoint-E", 5, "current-pinned", False, "a1"
            )
            ledger.record("session-6", admit, observed_at=6000)
            
            conflicts = ledger.detect_conflicts("session-6")
            self.assertEqual(len(conflicts), 0)
    
    def test_empty_ledger_no_conflict(self):
        """Empty ledger returns no conflicts."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            ledger = AdmissionLedger(root / "empty.jsonl")
            
            conflicts = ledger.detect_conflicts("any-session")
            self.assertEqual(len(conflicts), 0)


if __name__ == "__main__":
    unittest.main()
