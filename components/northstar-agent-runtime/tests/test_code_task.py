from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from code_task import (
    CodePhaseMachine,
    CodeTask,
    CodeTaskError,
    IsolatedCodeWorkspace,
    audit_delivery_patch,
    reconcile_code_evidence,
)


def git(root: Path, *args: str) -> str:
    process = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return process.stdout.strip()


class IsolatedCodeWorkspaceTests(unittest.TestCase):
    def make_repository(self, parent: Path) -> Path:
        root = parent / "repo"
        root.mkdir()
        git(root, "init")
        git(root, "config", "user.email", "northstar-tests@example.invalid")
        git(root, "config", "user.name", "Northstar Tests")
        (root / "app.py").write_text("value = 1\n", encoding="utf-8")
        git(root, "add", "app.py")
        git(root, "commit", "-m", "initial")
        return root

    def test_task_requires_a_goal(self):
        with self.assertRaises(CodeTaskError):
            CodeTask(goal="")

    def test_patch_contains_tracked_and_untracked_changes_without_touching_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            source = self.make_repository(parent)
            evidence = parent / "evidence"
            isolated = IsolatedCodeWorkspace(source, evidence_root=evidence).prepare()
            assert isolated.worktree is not None
            snapshot_path = isolated.evidence_dir / "repository-snapshot.json"
            self.assertTrue(snapshot_path.is_file())
            self.assertIn("app.py", snapshot_path.read_text(encoding="utf-8"))
            task_path = isolated.record_task(
                CodeTask(goal="change the value", workspace=str(source), checks=("python -m unittest",))
            )
            verification_path = isolated.record_verification(
                ({"declared": 1, "passed": 1, "failed": 0, "ok": True},)
            )
            original = (source / "app.py").read_text(encoding="utf-8")
            (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
            (isolated.worktree / "new.py").write_text("created = True\n", encoding="utf-8")

            patch_path = isolated.capture(exit_code=0, terminal="success")
            patch_text = patch_path.read_text(encoding="utf-8")
            self.assertIn("value = 2", patch_text)
            self.assertIn("new.py", patch_text)
            self.assertEqual((source / "app.py").read_text(encoding="utf-8"), original)
            self.assertFalse((source / "new.py").exists())

            isolated.cleanup()
            self.assertFalse(isolated.worktree.exists())
            self.assertTrue(patch_path.exists())
            self.assertTrue(task_path.exists())
            self.assertTrue(verification_path.exists())

    def test_failed_run_can_preserve_worktree(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            source = self.make_repository(parent)
            isolated = IsolatedCodeWorkspace(
                source, evidence_root=parent / "evidence"
            ).prepare()
            assert isolated.worktree is not None
            isolated.preserve(reason="verification failed")
            self.assertTrue(isolated.worktree.is_dir())
            # Test teardown is responsible for scratch worktrees it intentionally kept.
            isolated.cleanup()

    def test_subdirectory_workspace_and_dirty_source_are_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            source = self.make_repository(parent)
            (source / "pkg").mkdir()
            (source / "pkg" / "module.py").write_text("answer = 1\n", encoding="utf-8")
            git(source, "add", "pkg/module.py")
            git(source, "commit", "-m", "package")
            (source / "local-only.txt").write_text("dirty\n", encoding="utf-8")

            isolated = IsolatedCodeWorkspace(
                source / "pkg", evidence_root=parent / "evidence"
            ).prepare()
            self.assertEqual(isolated.source_relative, "pkg")
            self.assertEqual(isolated.execution_root, isolated.worktree / "pkg")
            self.assertTrue(any("local-only.txt" in row for row in isolated.source_status))
            isolated.cleanup()

    def test_evidence_setup_failure_removes_registered_worktree(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            source = self.make_repository(parent)
            evidence = parent / "evidence"
            (evidence / "fixed-run").mkdir(parents=True)
            with self.assertRaises(FileExistsError):
                IsolatedCodeWorkspace(
                    source, evidence_root=evidence, run_id="fixed-run"
                ).prepare()
            worktrees = git(source, "worktree", "list", "--porcelain")
            self.assertEqual(worktrees.count("worktree "), 1)

    def test_phase_machine_requires_plan_before_effects_and_persists_every_step(self):
        with tempfile.TemporaryDirectory() as directory:
            phases = CodePhaseMachine(
                run_id="code-phase-test",
                evidence_dir=directory,
            )
            phases.start()
            with self.assertRaises(CodeTaskError):
                phases.begin_execution(tool="Write", call_id="before-plan")
            phases.submit_plan(
                {
                    "summary": "make one change",
                    "files": ["app.py"],
                    "steps": ["edit"],
                    "risks": [],
                    "check_indices": [0],
                }
            )
            effect_id = phases.begin_execution(tool="Write", call_id="write-1")
            phases.complete_execution(effect_id, status="completed")
            phases.begin_verification()
            phases.finish("success")

            persisted = json.loads(Path(directory, "phases.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted["state"], "success")
            self.assertEqual(persisted["outcome"], "success")
            self.assertEqual(
                [row["to"] for row in persisted["transitions"]],
                ["understanding", "planned", "executing", "verifying", "success"],
            )
            self.assertEqual(persisted["effects"][0]["status"], "completed")

    def test_phase_machine_refuses_verification_while_effect_is_in_flight(self):
        with tempfile.TemporaryDirectory() as directory:
            phases = CodePhaseMachine(run_id="unknown-effect", evidence_dir=directory)
            phases.start()
            phases.submit_plan(
                {
                    "summary": "change one file",
                    "files": ["app.py"],
                    "steps": ["edit"],
                    "risks": [],
                    "check_indices": [],
                }
            )
            phases.begin_execution(tool="Write", call_id="write-unknown")
            with self.assertRaisesRegex(CodeTaskError, "lacking completion receipts"):
                phases.begin_verification()

    def test_reconcile_never_replays_an_effect_without_a_completion_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = self.make_repository(parent)
            isolated = IsolatedCodeWorkspace(
                source, evidence_root=parent / "evidence"
            ).prepare()
            assert isolated.evidence_dir is not None
            phases = CodePhaseMachine(
                run_id=isolated.run_id,
                evidence_dir=isolated.evidence_dir,
            )
            phases.start()
            phases.submit_plan(
                {
                    "summary": "change app",
                    "files": ["app.py"],
                    "steps": ["edit"],
                    "risks": [],
                    "check_indices": [],
                }
            )
            phases.begin_execution(tool="Write", call_id="write-interrupted")

            receipt = reconcile_code_evidence(isolated.evidence_dir)
            self.assertEqual(receipt["classification"], "manual_review_required")
            self.assertFalse(receipt["automatic_tool_replay"])
            self.assertEqual(
                receipt["unknown_side_effects"][0]["call_id"],
                "write-interrupted",
            )
            self.assertTrue((isolated.evidence_dir / "reconcile.json").is_file())
            isolated.cleanup()

    def test_raised_handler_keeps_partial_effect_for_manual_review(self):
        from loop import AgentRuntime, RuntimeConfig
        from providers.scripted import ScriptedProvider
        from tools import ToolContext, ToolSandbox, ToolSpec

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            phases = CodePhaseMachine(run_id="partial-effect", evidence_dir=evidence)
            phases.start()
            phases.submit_plan({"files": ["partial.txt"], "steps": ["write"]})
            (evidence / "manifest.json").write_text(
                json.dumps({"schema": "northstar.code-evidence.v1", "run_id": phases.run_id}),
                encoding="utf-8",
            )

            def partial_write(payload, context):
                (root / "partial.txt").write_text("changed", encoding="utf-8")
                raise RuntimeError("failed after the write")

            runtime = AgentRuntime(
                provider=ScriptedProvider([{"text": "unused"}]),
                config=RuntimeConfig(workspace=root, code_phase_machine=phases),
            )
            spec = ToolSpec(
                name="PartialWrite", description="partial write", kind="edit",
                input_schema={"type": "object"}, handler=partial_write,
            )
            with self.assertRaisesRegex(RuntimeError, "after the write"):
                runtime._execute_tool_handler(
                    spec, {}, ToolContext(sandbox=ToolSandbox(root)), call_id="partial-1"
                )
            self.assertEqual((root / "partial.txt").read_text(encoding="utf-8"), "changed")
            self.assertEqual(phases.as_dict()["effects"][0]["status"], "unknown")
            with self.assertRaises(CodeTaskError):
                phases.begin_verification()
            receipt = reconcile_code_evidence(evidence)
            self.assertEqual(receipt["classification"], "manual_review_required")
            self.assertEqual(receipt["unknown_side_effects"][0]["error_class"], "RuntimeError")

    def test_missing_or_inconsistent_journal_cannot_claim_safe_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            phases = CodePhaseMachine(run_id="journal-test", evidence_dir=root)
            phases.start()
            (root / "manifest.json").write_text(
                json.dumps({"schema": "northstar.code-evidence.v1", "run_id": phases.run_id}),
                encoding="utf-8",
            )
            journal = phases.as_dict()
            del journal["effect_journal_version"]
            (root / "phases.json").write_text(json.dumps(journal), encoding="utf-8")
            receipt = reconcile_code_evidence(root)
            self.assertEqual(receipt["classification"], "insufficient_effect_evidence")
            self.assertFalse(receipt["safe_restart_from_start_commit"])

            journal = phases.as_dict()
            journal["transitions"][0]["from"] = "executing"
            (root / "phases.json").write_text(json.dumps(journal), encoding="utf-8")
            receipt = reconcile_code_evidence(root)
            self.assertEqual(receipt["classification"], "invalid_evidence")
            self.assertFalse(receipt["safe_restart_from_start_commit"])

    def test_failed_completion_persistence_keeps_in_flight_state(self):
        with tempfile.TemporaryDirectory() as directory:
            phases = CodePhaseMachine(run_id="persist-test", evidence_dir=directory)
            phases.start()
            phases.submit_plan({"files": ["app.py"], "steps": ["edit"]})
            effect = phases.begin_execution(tool="Write", call_id="persist-1")
            with patch("code_task._atomic_write", side_effect=OSError("disk full")):
                with self.assertRaisesRegex(OSError, "disk full"):
                    phases.complete_execution(effect, status="completed")
            self.assertEqual(phases.as_dict()["effects"][0]["status"], "in_flight")
            persisted = json.loads(phases.path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["effects"][0]["status"], "in_flight")

    def test_reconcile_detects_corruption_in_sealed_task_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = self.make_repository(parent)
            isolated = IsolatedCodeWorkspace(source, evidence_root=parent / "evidence").prepare()
            try:
                isolated.record_task(CodeTask(goal="inspect app"))
                phases = CodePhaseMachine(run_id=isolated.run_id, evidence_dir=isolated.evidence_dir)
                phases.start()
                assert isolated.evidence_dir is not None
                (isolated.evidence_dir / "task.json").write_text("{}", encoding="utf-8")
                receipt = reconcile_code_evidence(isolated.evidence_dir)
                self.assertEqual(receipt["classification"], "invalid_evidence")
                self.assertIn("task digest does not match the manifest", receipt["integrity_errors"])
            finally:
                isolated.cleanup()

    def test_delegated_mutating_tool_inherits_the_parent_phase_gate(self):
        from loop import AgentRuntime, RuntimeConfig
        from providers.scripted import ScriptedProvider
        from tools import build_code_registry

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            phases = CodePhaseMachine(run_id="delegated-before-plan", evidence_dir=root / "evidence")
            phases.start()
            runtime = AgentRuntime(
                provider=ScriptedProvider([
                    {"tool": {"name": "Task", "input": {"agent": "general", "prompt": "write a file"}}},
                    {"tool": {"name": "Write", "input": {"path": "too-early.txt", "content": "no"}}},
                    {"text": "child done"},
                    {"tool": {"name": "SubmitPlan", "input": {
                        "summary": "inspect only", "files": [], "steps": ["inspect"],
                        "risks": [], "check_indices": [],
                    }}},
                    {"text": "parent done"},
                ]),
                tools=build_code_registry(),
                config=RuntimeConfig(
                    workspace=root, code_phase_machine=phases,
                    permission_mode="acceptEdits", allowed_tools=("Task", "Write"),
                ),
            )
            report = runtime.run_collect("inspect repository")
            self.assertEqual(report.subtype, "success")
            self.assertFalse((root / "too-early.txt").exists())
            self.assertEqual(phases.state, "verifying")
            self.assertEqual(phases.as_dict()["effects"], [])

    def test_reconcile_distinguishes_pre_effect_and_receipted_interruptions(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = self.make_repository(parent)

            before = IsolatedCodeWorkspace(
                source, evidence_root=parent / "evidence-before"
            ).prepare()
            assert before.evidence_dir is not None
            phases = CodePhaseMachine(run_id=before.run_id, evidence_dir=before.evidence_dir)
            phases.start()
            self.assertEqual(
                reconcile_code_evidence(before.evidence_dir)["classification"],
                "interrupted_before_effects",
            )
            before.cleanup()

            after = IsolatedCodeWorkspace(
                source, evidence_root=parent / "evidence-after"
            ).prepare()
            assert after.evidence_dir is not None
            phases = CodePhaseMachine(run_id=after.run_id, evidence_dir=after.evidence_dir)
            phases.start()
            phases.submit_plan(
                {
                    "summary": "change app",
                    "files": ["app.py"],
                    "steps": ["edit"],
                    "risks": [],
                    "check_indices": [],
                }
            )
            effect = phases.begin_execution(tool="Write", call_id="write-complete")
            phases.complete_execution(effect, status="completed")
            self.assertEqual(
                reconcile_code_evidence(after.evidence_dir)["classification"],
                "interrupted_after_receipted_effects",
            )
            after.cleanup()

    def test_delivery_audit_rejects_governance_changes_and_new_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = self.make_repository(parent)
            (source / ".northstar").mkdir()
            (source / ".northstar" / "config.toml").write_text(
                'permission_mode = "bypassPermissions"\n', encoding="utf-8"
            )
            (source / "secret.txt").write_text(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8"
            )
            receipt = audit_delivery_patch(source, evidence_dir=parent / "evidence")
            self.assertFalse(receipt["ok"])
            self.assertEqual(
                {item["code"] for item in receipt["findings"]},
                {"governance_path_changed", "private_key"},
            )


if __name__ == "__main__":
    unittest.main()
