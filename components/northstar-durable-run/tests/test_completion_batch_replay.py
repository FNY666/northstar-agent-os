import json
import shutil
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from completion_batch_replay import (  # noqa: E402
    default_context,
    load_spec,
    observed_milestones,
    replay_archive,
    replay_archive_task,
    summarize,
)
from completion_batch_replay import _events  # noqa: E402


ARCHIVE_ROOT = Path("/var/minis/shared/northstar-live-runs")
SPEC_PATH = ROOT / "replay" / "archive-replay-spec.json"
EVALUATOR = ROOT / "completion_contract_v2.py"


class BatchReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ARCHIVE_ROOT.is_dir():
            raise unittest.SkipTest("archived runs are not available")
        cls.specs = load_spec(SPEC_PATH)
        cls.context = default_context(ARCHIVE_ROOT, EVALUATOR)

    def spec(self, run_name, task_id):
        for run in self.specs:
            if run.run != run_name:
                continue
            for task in run.tasks:
                if task.task_id == task_id:
                    return run, task
        raise AssertionError(f"spec not found: {run_name}/{task_id}")

    def test_spec_covers_every_archived_task(self):
        declared = {(run.run, task.task_id) for run in self.specs for task in run.tasks}
        self.assertEqual(len(declared), 5)
        for run in self.specs:
            self.assertTrue((ARCHIVE_ROOT / run.run / run.report).is_file())
            for task in run.tasks:
                self.assertTrue((ARCHIVE_ROOT / run.run / task.fixture).is_file())
                self.assertTrue((ARCHIVE_ROOT / run.run / task.evidence).is_file())
                for archived in task.artifacts.values():
                    self.assertTrue((ARCHIVE_ROOT / run.run / archived).is_file())

    def test_digest_mode_verifies_every_archived_completion(self):
        outcomes = replay_archive(self.context, self.specs, modes=("digest",))
        self.assertEqual(len(outcomes), 5)
        for outcome in outcomes:
            self.assertEqual(outcome.verdict, "verified", f"{outcome.run}/{outcome.task_id}")
            self.assertTrue(outcome.artifact_bound)

    def test_semantic_mode_verifies_machine_checkable_deliverables(self):
        run, task = self.spec("2026-09-11-action-failure-recovery", "live-transient-write-recovery-v1")
        outcome = replay_archive_task(self.context, run, task, mode="semantic")
        self.assertEqual(outcome.verdict, "verified")
        self.assertEqual(outcome.declared_fields, 3)

    def test_prose_only_deliverable_fails_closed(self):
        """A deliverable with no machine-readable statements must not pass silently."""
        run, task = self.spec("2026-09-11-multi-task", "live-release-note-v2")
        outcome = replay_archive_task(self.context, run, task, mode="semantic")
        self.assertEqual(outcome.verdict, "insufficient_information")
        self.assertIn("semantic_fields_undeclared:out/release-note.md", outcome.errors)

    def test_tampered_artifact_is_not_bound_to_evidence(self):
        run, task = self.spec("2026-09-11-action-failure-recovery", "live-transient-write-recovery-v1")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ARCHIVE_ROOT / run.run, root / run.run)
            target = root / run.run / "deliverables" / "recovery.md"
            target.write_text(target.read_text() + "EXTRA\n", encoding="utf-8")
            context = replace(self.context, archive_root=root)
            outcome = replay_archive_task(context, run, task, mode="digest")
        self.assertEqual(outcome.verdict, "insufficient_information")
        self.assertEqual(outcome.errors, ("artifact_not_bound_to_final_evidence",))
        self.assertFalse(outcome.artifact_bound)

    def test_discarded_round_one_artifact_is_not_bound(self):
        """The wrong-path artifact committed in round 1 must not count as the deliverable."""
        run, task = self.spec("2026-09-10-first-live-run", "live-column-report")
        discarded = replace(task, artifacts={"out/report.md": "deliverable/round1-wrong-path-report.md"})
        outcome = replay_archive_task(self.context, run, discarded, mode="digest")
        self.assertEqual(outcome.verdict, "insufficient_information")
        self.assertEqual(outcome.errors, ("artifact_not_bound_to_final_evidence",))

    def test_report_self_claim_does_not_change_verdict(self):
        """The archived report self-reports ok/verified; rewriting those must not matter."""
        run, task = self.spec("2026-09-10-first-live-run", "live-column-report")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ARCHIVE_ROOT / run.run, root / run.run)
            report_path = root / run.run / "report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["ok"] = False
            report["verification"] = {"verdict": "failed", "checked": [], "failures": ["out/report.md"]}
            report_path.write_text(json.dumps(report), encoding="utf-8")
            context = replace(self.context, archive_root=root)
            outcome = replay_archive_task(context, run, task, mode="digest")
        self.assertEqual(outcome.verdict, "verified")

    def test_missing_evidence_yields_unknown(self):
        run, task = self.spec("2026-09-11-action-failure-recovery", "live-transient-write-recovery-v1")
        broken = replace(task, evidence="evidence/round-9.evidence.jsonl")
        outcome = replay_archive_task(self.context, run, broken, mode="digest")
        self.assertEqual(outcome.verdict, "unknown")
        self.assertEqual(outcome.errors, ("evidence_terminal_state_unavailable",))

    def test_observed_milestones_come_from_journal_not_prose(self):
        run, task = self.spec("2026-09-11-multi-task", "live-score-audit-v2")
        events = _events(ARCHIVE_ROOT / run.run / task.evidence)
        self.assertEqual(observed_milestones(events, task.milestone_labels), ("list", "read", "write"))

    def test_observed_milestones_collapse_repeated_labels(self):
        run, task = self.spec("2026-09-10-first-live-run", "live-column-report")
        events = _events(ARCHIVE_ROOT / run.run / task.evidence)
        self.assertEqual(observed_milestones(events, task.milestone_labels), ("read", "write"))

    def test_summarize_names_every_non_verified_task(self):
        summary = summarize(replay_archive(self.context, self.specs))
        self.assertEqual(summary["modes"]["digest"]["counts"], {"verified": 5})
        self.assertEqual(summary["modes"]["digest"]["non_verified"], [])
        self.assertEqual(summary["modes"]["digest"]["artifact_bound"], 5)
        semantic = summary["modes"]["semantic"]
        self.assertEqual(semantic["counts"], {"insufficient_information": 1, "verified": 4})
        self.assertEqual(len(semantic["non_verified"]), 1)
        self.assertEqual(semantic["non_verified"][0]["task_id"], "live-release-note-v2")


if __name__ == "__main__":
    unittest.main()
