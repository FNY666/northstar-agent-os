"""Tests for resuming an interrupted ``northstar code`` run.

The resume path must continue a run without weakening any guarantee the
original run had: the same isolated worktree, the same starting commit, the
same declared checks, and — above all — no replay of a tool effect whose
completion receipt was never written.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from code_resume import (
    RESUMABLE_PHASES,
    prepare_code_resume,
    restore_phase_machine,
    write_resume_receipt,
)
from code_task import (
    CodePhaseMachine,
    CodeTask,
    CodeTaskError,
    IsolatedCodeWorkspace,
    reconcile_code_evidence,
)


def git(root: Path, *arguments: str) -> str:
    process = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return process.stdout.strip()


class ResumeFixture(unittest.TestCase):
    """Build a real evidence directory that looks like an interrupted run."""

    def make_repository(self, parent: Path, name: str = "repo") -> Path:
        root = parent / name
        root.mkdir(exist_ok=True)
        git(root, "init")
        git(root, "config", "user.email", "northstar-tests@example.invalid")
        git(root, "config", "user.name", "Northstar Tests")
        (root / "app.py").write_text("value = 1\n", encoding="utf-8")
        git(root, "add", "app.py")
        git(root, "commit", "-m", "initial")
        return root

    def prepared_run(self, parent: Path, name: str = "repo") -> tuple[IsolatedCodeWorkspace, Path]:
        source = self.make_repository(parent, name)
        isolated = IsolatedCodeWorkspace(
            source, evidence_root=parent / f"evidence-{name}"
        ).prepare()
        assert isolated.worktree is not None
        assert isolated.evidence_dir is not None
        isolated.record_task(
            CodeTask(goal="change the value", workspace=str(source), checks=("printf 42",))
        )
        return isolated, source

    def write_session_transcript(self, evidence_dir: Path, session_id: str = "sess-1") -> Path:
        """Write a transcript the runtime would accept: chained and checkpointed.

        A resume forks the parent transcript at a checkpoint, and the runtime
        refuses to read an unsealed transcript, so the fixture has to be a real
        one rather than a stand-in.
        """
        from audit_chain import chain_records

        sessions = evidence_dir / "sessions"
        sessions.mkdir(parents=True, exist_ok=True)
        path = sessions / f"{session_id}.jsonl"
        records = [
            {"type": "session_start", "data": {"session_id": session_id}},
            {"type": "user_prompt", "content": "change the value"},
            {
                "type": "checkpoint",
                "index": 3,
                "record_index": 3,
                "transcript_len": 2,
                "transcript_digest": "0" * 64,
                "turns": 1,
                "tool_calls": 0,
                "cost_usd": 0.0,
                "usage": {},
            },
        ]
        sealed = chain_records(records, component="northstar-agent-runtime", session_id=session_id)
        path.write_text(
            "".join(json.dumps(record, sort_keys=True) + "\n" for record in sealed),
            encoding="utf-8",
        )
        return path


class PrepareResumeTests(ResumeFixture):
    def test_reconcile_reports_that_a_phase_can_be_resumed(self):
        """The reconcile report must state the truth about phase resume."""
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            isolated, _source = self.prepared_run(parent)
            machine = CodePhaseMachine(
                run_id=isolated.run_id,
                evidence_dir=isolated.evidence_dir,
                plan_only=False,
            )
            machine.start()
            isolated.record_phases(machine)
            report = reconcile_code_evidence(isolated.evidence_dir)
            self.assertTrue(
                report["phase_resume_supported"],
                "the report must not claim a phase resume is impossible",
            )

    def test_interrupted_run_in_understanding_is_resumable(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            isolated, _source = self.prepared_run(parent)
            phases = CodePhaseMachine(
                run_id=isolated.run_id,
                evidence_dir=isolated.evidence_dir,
                worktree=isolated.worktree,
                start_commit=isolated.start_commit,
            )
            phases.start()
            isolated.record_phases(phases)
            self.write_session_transcript(isolated.evidence_dir)

            report = prepare_code_resume(isolated.evidence_dir)
            self.assertTrue(report["resumable"], report)
            self.assertEqual(report["state"], "understanding")
            self.assertEqual(report["session_id"], "sess-1")
            self.assertEqual(report["start_commit"], isolated.start_commit)

    def test_every_active_phase_is_resumable(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            for target in ("understanding", "planned", "executing", "verifying"):
                isolated, _source = self.prepared_run(parent, f"repo-{target}")
                phases = CodePhaseMachine(
                    run_id=isolated.run_id,
                    evidence_dir=isolated.evidence_dir,
                    worktree=isolated.worktree,
                    start_commit=isolated.start_commit,
                )
                phases.start()
                if target in {"planned", "executing", "verifying"}:
                    phases.submit_plan({"files": ["app.py"], "steps": [], "risks": []})
                if target in {"executing", "verifying"}:
                    phases.begin_execution(tool="ApplyPatch", call_id="c1")
                    phases.complete_execution("effect-1", status="completed")
                if target == "verifying":
                    phases.begin_verification()
                isolated.record_phases(phases)
                self.write_session_transcript(isolated.evidence_dir)
                report = prepare_code_resume(isolated.evidence_dir)
                self.assertTrue(report["resumable"], (target, report))
                self.assertEqual(report["state"], target)

    def test_terminal_run_is_not_resumable(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            isolated, _source = self.prepared_run(parent)
            phases = CodePhaseMachine(
                run_id=isolated.run_id,
                evidence_dir=isolated.evidence_dir,
                worktree=isolated.worktree,
                start_commit=isolated.start_commit,
            )
            phases.start()
            phases.finish("error_during_execution", reason="test")
            isolated.record_phases(phases)
            self.write_session_transcript(isolated.evidence_dir)

            report = prepare_code_resume(isolated.evidence_dir)
            self.assertFalse(report["resumable"])
            self.assertEqual(report["reason"], "already_terminal")

    def test_unreceipted_effect_blocks_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            isolated, _source = self.prepared_run(parent)
            phases = CodePhaseMachine(
                run_id=isolated.run_id,
                evidence_dir=isolated.evidence_dir,
                worktree=isolated.worktree,
                start_commit=isolated.start_commit,
            )
            phases.start()
            phases.submit_plan({"files": ["app.py"], "steps": [], "risks": []})
            # An effect that started but never completed: the side effect may
            # already have happened, so a resume would replay it.
            phases.begin_execution(tool="ApplyPatch", call_id="c1")
            isolated.record_phases(phases)
            self.write_session_transcript(isolated.evidence_dir)

            report = prepare_code_resume(isolated.evidence_dir)
            self.assertFalse(report["resumable"])
            self.assertEqual(report["reason"], "unresolved_side_effects")
            self.assertEqual(len(report["unresolved_effects"]), 1)

    def test_unknown_effect_blocks_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            isolated, _source = self.prepared_run(parent)
            phases = CodePhaseMachine(
                run_id=isolated.run_id,
                evidence_dir=isolated.evidence_dir,
                worktree=isolated.worktree,
                start_commit=isolated.start_commit,
            )
            phases.start()
            phases.submit_plan({"files": ["app.py"], "steps": [], "risks": []})
            effect_id = phases.begin_execution(tool="ApplyPatch", call_id="c1")
            phases.complete_execution(effect_id, status="unknown", error_class="RuntimeError")
            isolated.record_phases(phases)
            self.write_session_transcript(isolated.evidence_dir)

            report = prepare_code_resume(isolated.evidence_dir)
            self.assertFalse(report["resumable"])
            self.assertEqual(report["reason"], "unresolved_side_effects")

    def test_receipted_failure_allows_resume(self):
        """A failed effect carries a receipt: the runtime knows what happened."""
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            isolated, _source = self.prepared_run(parent)
            phases = CodePhaseMachine(
                run_id=isolated.run_id,
                evidence_dir=isolated.evidence_dir,
                worktree=isolated.worktree,
                start_commit=isolated.start_commit,
            )
            phases.start()
            phases.submit_plan({"files": ["app.py"], "steps": [], "risks": []})
            effect_id = phases.begin_execution(tool="ApplyPatch", call_id="c1")
            phases.complete_execution(effect_id, status="failed", error_class="ValueError")
            isolated.record_phases(phases)
            self.write_session_transcript(isolated.evidence_dir)

            report = prepare_code_resume(isolated.evidence_dir)
            self.assertTrue(report["resumable"], report)
            self.assertEqual(len(report["receipted_failures"]), 1)
            self.assertEqual(report["unresolved_effects"], [])

    def test_missing_worktree_blocks_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            isolated, _source = self.prepared_run(parent)
            phases = CodePhaseMachine(
                run_id=isolated.run_id,
                evidence_dir=isolated.evidence_dir,
                worktree=isolated.worktree,
                start_commit=isolated.start_commit,
            )
            phases.start()
            isolated.record_phases(phases)
            self.write_session_transcript(isolated.evidence_dir)
            import shutil

            shutil.rmtree(isolated.worktree)

            report = prepare_code_resume(isolated.evidence_dir)
            self.assertFalse(report["resumable"])
            self.assertEqual(report["reason"], "worktree_missing")

    def test_missing_transcript_blocks_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            isolated, _source = self.prepared_run(parent)
            phases = CodePhaseMachine(
                run_id=isolated.run_id,
                evidence_dir=isolated.evidence_dir,
                worktree=isolated.worktree,
                start_commit=isolated.start_commit,
            )
            phases.start()
            isolated.record_phases(phases)

            report = prepare_code_resume(isolated.evidence_dir)
            self.assertFalse(report["resumable"])
            self.assertEqual(report["reason"], "no_session_transcript")

    def test_tampered_evidence_blocks_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            isolated, _source = self.prepared_run(parent)
            phases = CodePhaseMachine(
                run_id=isolated.run_id,
                evidence_dir=isolated.evidence_dir,
                worktree=isolated.worktree,
                start_commit=isolated.start_commit,
            )
            phases.start()
            isolated.record_phases(phases)
            self.write_session_transcript(isolated.evidence_dir)
            # Rewrite the recorded task after the manifest sealed its digest.
            (isolated.evidence_dir / "task.json").write_text(
                json.dumps({"goal": "tampered"}) + "\n", encoding="utf-8"
            )

            report = prepare_code_resume(isolated.evidence_dir)
            self.assertFalse(report["resumable"])
            self.assertEqual(report["reason"], "evidence_integrity_failed")
            self.assertTrue(report["integrity_errors"])


class RestorePhaseMachineTests(ResumeFixture):
    def test_restore_rebuilds_state_plan_and_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            isolated, _source = self.prepared_run(parent)
            phases = CodePhaseMachine(
                run_id=isolated.run_id,
                evidence_dir=isolated.evidence_dir,
                worktree=isolated.worktree,
                start_commit=isolated.start_commit,
            )
            phases.start()
            phases.submit_plan({"files": ["app.py"], "steps": ["edit"], "risks": []})
            effect_id = phases.begin_execution(tool="ApplyPatch", call_id="c1")
            phases.complete_execution(effect_id, status="completed")
            isolated.record_phases(phases)

            restored = restore_phase_machine(
                isolated.evidence_dir,
                worktree=isolated.worktree,
                start_commit=isolated.start_commit,
            )
            self.assertEqual(restored.state, "executing")
            self.assertEqual(restored.run_id, isolated.run_id)
            self.assertTrue(restored.plan_submitted)
            self.assertEqual(restored.as_dict()["plan"]["steps"], ["edit"])
            effects = restored.as_dict()["effects"]
            self.assertEqual(len(effects), 1)
            self.assertEqual(effects[0]["status"], "completed")
            self.assertEqual(effects[0]["tool"], "ApplyPatch")

    def test_restore_refuses_a_terminal_journal(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            isolated, _source = self.prepared_run(parent)
            phases = CodePhaseMachine(
                run_id=isolated.run_id,
                evidence_dir=isolated.evidence_dir,
                worktree=isolated.worktree,
                start_commit=isolated.start_commit,
            )
            phases.start()
            phases.finish("error_during_execution", reason="test")
            isolated.record_phases(phases)

            with self.assertRaises(CodeTaskError):
                restore_phase_machine(isolated.evidence_dir)

    def test_restore_keeps_the_phase_journal_consistent(self):
        """A restored machine must still satisfy the reconcile integrity rules."""
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            isolated, _source = self.prepared_run(parent)
            phases = CodePhaseMachine(
                run_id=isolated.run_id,
                evidence_dir=isolated.evidence_dir,
                worktree=isolated.worktree,
                start_commit=isolated.start_commit,
            )
            phases.start()
            phases.submit_plan({"files": ["app.py"], "steps": [], "risks": []})
            isolated.record_phases(phases)

            restore_phase_machine(
                isolated.evidence_dir,
                worktree=isolated.worktree,
                start_commit=isolated.start_commit,
            )
            receipt = reconcile_code_evidence(isolated.evidence_dir)
            self.assertEqual(receipt["integrity_errors"], [])
            self.assertEqual(receipt["state"], "planned")


class ResumeReceiptTests(ResumeFixture):
    def test_receipt_is_written_into_the_evidence_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            isolated, _source = self.prepared_run(parent)
            phases = CodePhaseMachine(
                run_id=isolated.run_id,
                evidence_dir=isolated.evidence_dir,
                worktree=isolated.worktree,
                start_commit=isolated.start_commit,
            )
            phases.start()
            isolated.record_phases(phases)
            self.write_session_transcript(isolated.evidence_dir)

            report = prepare_code_resume(isolated.evidence_dir)
            path = write_resume_receipt(isolated.evidence_dir, report)
            self.assertTrue(path.is_file())
            stored = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(stored["schema"], "northstar.code-resume.v1")
            self.assertTrue(stored["resumable"])


if __name__ == "__main__":
    unittest.main()
