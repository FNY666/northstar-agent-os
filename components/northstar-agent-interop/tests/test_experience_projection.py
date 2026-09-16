"""
Experience state projection: unified view for integration with broader evidence layers.
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
    ExperienceLedger,
    ExperienceStatistics,
)


class ExperienceStateProjectionTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.experience = ExperienceLedger(self.root / "experience.jsonl")
        self.admission = AdmissionLedger(self.root / "admission.jsonl")

    def tearDown(self):
        self.tempdir.cleanup()

    def test_empty_experience_projects_insufficient_data(self):
        """Empty experience projects to insufficient-data state."""
        from experience_ledger import project_state
        
        state = project_state(self.experience, "task-001")
        self.assertEqual(state.fingerprint, "task-001")
        self.assertEqual(state.standing, "no-evidence")
        self.assertEqual(state.confidence, 0.0)
        self.assertEqual(state.recent_trend, "insufficient-data")
        self.assertIsNone(state.last_admission)
        self.assertEqual(state.conflict_count, 0)
        self.assertEqual(state.data_quality, "insufficient-data")

    def test_consistent_success_projects_verified(self):
        """Consistent success with sufficient samples → verified."""
        from experience_ledger import project_state
        
        # Build experience: 10 successes
        for i in range(10):
            forecast = self.experience.forecast("task-002")
            self.experience.settle(
                forecast,
                actual_verdict="verified",
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        state = project_state(self.experience, "task-002")
        self.assertEqual(state.standing, "consistent-success")
        self.assertGreater(state.confidence, 0.9)
        self.assertEqual(state.recent_trend, "stable")
        self.assertEqual(state.data_quality, "verified")

    def test_with_admission_ledger_populates_last_admission(self):
        """When admission ledger provided, last_admission is populated."""
        from experience_ledger import project_state
        
        # Build experience
        for i in range(5):
            forecast = self.experience.forecast("task-003")
            self.experience.settle(
                forecast,
                actual_verdict="verified",
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        # Record admission decisions
        stats = ExperienceStatistics("task-003", 5, 5, 0, 1.0, "stable", ())
        verdict1 = AdmissionVerdict("admitted", "test", 0.8, True)
        self.admission.record("task-003", verdict1, stats, {}, 1000)
        verdict2 = AdmissionVerdict("blocked", "test", 0.5, False)
        self.admission.record("task-003", verdict2, stats, {}, 2000)
        
        state = project_state(self.experience, "task-003", admission_ledger=self.admission)
        self.assertEqual(state.last_admission, "blocked")  # Most recent

    def test_conflicts_affect_data_quality(self):
        """Detected conflicts downgrade data_quality to unverifiable."""
        from experience_ledger import project_state
        
        # Build experience
        for i in range(5):
            forecast = self.experience.forecast("task-004")
            self.experience.settle(
                forecast,
                actual_verdict="verified",
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        # Create conflicting admission decisions
        stats = ExperienceStatistics("task-004", 5, 5, 0, 1.0, "stable", ())
        verdict1 = AdmissionVerdict("admitted", "test", 0.8, True)
        self.admission.record("task-004", verdict1, stats, {}, 1000)
        verdict2 = AdmissionVerdict("blocked", "test", 0.5, False)
        self.admission.record("task-004", verdict2, stats, {}, 1100)
        
        state = project_state(self.experience, "task-004", admission_ledger=self.admission)
        self.assertEqual(state.conflict_count, 1)
        self.assertEqual(state.data_quality, "unverifiable")

    def test_contradicted_standing_marks_unverifiable(self):
        """Contradicted experience standing → unverifiable data quality."""
        from experience_ledger import project_state
        
        # Create contradicted experience (1 success, 1 failure)
        forecast1 = self.experience.forecast("task-005")
        self.experience.settle(
            forecast1,
            actual_verdict="verified",
            run_id="run-1",
            run_digest=None,
            event_head=None,
        )
        forecast2 = self.experience.forecast("task-005")
        self.experience.settle(
            forecast2,
            actual_verdict="failed",
            run_id="run-2",
            run_digest=None,
            event_head=None,
        )
        
        state = project_state(self.experience, "task-005")
        self.assertEqual(state.standing, "contradicted")
        self.assertEqual(state.data_quality, "unverifiable")

    def test_insufficient_samples_marks_insufficient_data(self):
        """< 3 samples → insufficient-data quality even if consistent."""
        from experience_ledger import project_state
        
        # Only 2 samples
        for i in range(2):
            forecast = self.experience.forecast("task-006")
            self.experience.settle(
                forecast,
                actual_verdict="verified",
                run_id=f"run-{i}",
                run_digest=None,
                event_head=None,
            )
        
        state = project_state(self.experience, "task-006")
        self.assertLess(state.confidence, 0.5)
        self.assertEqual(state.data_quality, "insufficient-data")


if __name__ == "__main__":
    unittest.main()
