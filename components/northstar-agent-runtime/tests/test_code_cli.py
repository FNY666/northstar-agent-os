from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cli import main


def git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def invoke(*arguments: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main(list(arguments))
    return code, stdout.getvalue(), stderr.getvalue()


def plan_turn(*, checks: tuple[int, ...] = ()) -> dict[str, object]:
    return {
        "tool": {
            "name": "SubmitPlan",
            "input": {
                "summary": "inspect and make the requested minimal change",
                "files": ["value.txt"],
                "steps": ["inspect the file", "apply the requested change"],
                "risks": ["preserve the existing newline"],
                "check_indices": list(checks),
            },
        }
    }


class CodeCliTests(unittest.TestCase):
    def make_repository(self, parent: Path) -> Path:
        root = parent / "repo"
        root.mkdir()
        git(root, "init")
        git(root, "config", "user.email", "northstar-tests@example.invalid")
        git(root, "config", "user.name", "Northstar Tests")
        (root / "value.txt").write_text("old\n", encoding="utf-8")
        git(root, "add", "value.txt")
        git(root, "commit", "-m", "initial")
        return root

    def base(self, root: Path) -> tuple[str, ...]:
        return (
            "--workspace", str(root),
            "--sandbox", "process",
            "--seccomp", "off",
            "--capdrop", "off",
            "--landlock", "off",
            "--no-policy-file",
            "--no-workspace-agents",
            "--no-skills",
            "--no-memory",
            "--no-plugins",
        )

    def test_dry_run_advertises_code_profile_without_creating_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = self.make_repository(parent)
            evidence = parent / "evidence"
            code, output, error = invoke(
                "code", "inspect it", *self.base(root),
                "--evidence-dir", str(evidence), "--dry-run",
            )
        self.assertEqual(code, 0, error)
        self.assertIn("code_workspace=isolated Git worktree", output)
        self.assertIn("RepoMap", output)
        self.assertIn("ApplyPatch", output)
        self.assertFalse(evidence.exists())

    def test_code_edit_default_does_not_override_workspace_plan_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = self.make_repository(parent)
            (root / ".northstar").mkdir()
            (root / ".northstar" / "config.toml").write_text(
                'permission_mode = "plan"\n', encoding="utf-8"
            )
            code, output, error = invoke(
                "code", "inspect it",
                "--workspace", str(root),
                "--sandbox", "process",
                "--seccomp", "off",
                "--capdrop", "off",
                "--landlock", "off",
                "--no-workspace-agents",
                "--no-skills",
                "--no-memory",
                "--no-plugins",
                "--dry-run",
            )
        self.assertEqual(code, 0, error)
        self.assertIn("permission_mode=plan", output)

    def test_code_run_delivers_patch_and_verification_without_editing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = self.make_repository(parent)
            evidence = parent / "evidence"
            script = parent / "turns.json"
            script.write_text(
                json.dumps(
                    [
                        plan_turn(checks=(0,)),
                        {
                            "tool": {
                                "name": "Write",
                                "input": {"path": "value.txt", "content": "new\n"},
                            }
                        },
                        {"text": "implemented and verified"},
                    ]
                ),
                encoding="utf-8",
            )
            code, output, error = invoke(
                "code", "change the value", *self.base(root),
                "--script", str(script),
                "--check", "read line < value.txt; test \"$line\" = new",
                "--evidence-dir", str(evidence),
            )

            self.assertEqual(code, 0, error)
            self.assertEqual((root / "value.txt").read_text(encoding="utf-8"), "old\n")
            runs = list(evidence.iterdir())
            self.assertEqual(len(runs), 1)
            run_dir = runs[0]
            patch = (run_dir / "changes.patch").read_text(encoding="utf-8")
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertIn("+new", patch)
            self.assertEqual(manifest["status"], "success")
            self.assertTrue(manifest["verification_ok"])
            self.assertTrue(manifest["worktree_removed"])
            self.assertTrue((run_dir / "task.json").is_file())
            self.assertTrue((run_dir / "repository-snapshot.json").is_file())
            self.assertTrue((run_dir / "verification.json").is_file())
            replay = json.loads((run_dir / "patch-replay.json").read_text(encoding="utf-8"))
            self.assertTrue(replay["ok"])
            self.assertTrue(manifest["patch_replay_ok"])
            audit = json.loads((run_dir / "patch-audit.json").read_text(encoding="utf-8"))
            self.assertTrue(audit["ok"])
            self.assertTrue(manifest["patch_audit_ok"])
            phases = json.loads((run_dir / "phases.json").read_text(encoding="utf-8"))
            self.assertEqual(phases["outcome"], "success")
            self.assertEqual(
                [row["to"] for row in phases["transitions"]],
                ["understanding", "planned", "executing", "verifying", "success"],
            )
            self.assertIn("verification: 1/1 passed", output)
            self.assertIn("worktree=removed", output)

    def test_failed_verification_preserves_worktree_for_reconciliation(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = self.make_repository(parent)
            evidence = parent / "evidence"
            script = parent / "turns.json"
            script.write_text(
                json.dumps([plan_turn(checks=(0,)), {"text": "done"}]),
                encoding="utf-8",
            )
            code, output, error = invoke(
                "code", "inspect only", *self.base(root),
                "--script", str(script),
                "--check", "false",
                "--evidence-dir", str(evidence),
            )
            self.assertEqual(code, 6, error)
            run_dir = next(evidence.iterdir())
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            kept = Path(manifest["worktree"])
            self.assertEqual(manifest["status"], "error_postconditions_failed")
            self.assertFalse(manifest["verification_ok"])
            self.assertFalse(manifest["worktree_removed"])
            self.assertTrue(kept.is_dir())
            self.assertIn("worktree=", output)
            reconcile_code, reconcile_output, reconcile_error = invoke(
                "code-reconcile", str(run_dir)
            )
            self.assertEqual(reconcile_code, 0, reconcile_error)
            receipt = json.loads(reconcile_output)
            self.assertEqual(receipt["classification"], "terminal")
            self.assertFalse(receipt["automatic_tool_replay"])
            git(root, "worktree", "remove", "--force", str(kept))

    def test_missing_checks_is_a_named_unverified_success(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = self.make_repository(parent)
            evidence = parent / "evidence"
            script = parent / "turns.json"
            script.write_text(
                json.dumps([plan_turn(), {"text": "done"}]),
                encoding="utf-8",
            )
            code, output, error = invoke(
                "code", "inspect only", *self.base(root),
                "--script", str(script),
                "--evidence-dir", str(evidence),
            )
            self.assertEqual(code, 0, error)
            run_dir = next(evidence.iterdir())
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "success_unverified")
            self.assertFalse(manifest["verification_ok"])
            phases = json.loads((run_dir / "phases.json").read_text(encoding="utf-8"))
            self.assertEqual(phases["outcome"], "success_unverified")
            self.assertIn("[success_unverified]", output)

    def test_host_check_cannot_modify_the_audited_delivery_and_claim_success(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = self.make_repository(parent)
            evidence = parent / "evidence"
            script = parent / "turns.json"
            script.write_text(json.dumps([plan_turn(checks=(0,)), {"text": "done"}]), encoding="utf-8")
            code, output, error = invoke(
                "code", "inspect only", *self.base(root), "--script", str(script),
                "--check", "printf changed > value.txt", "--evidence-dir", str(evidence),
            )
            self.assertEqual(code, 6, error)
            self.assertIn("modified the audited delivery patch", error)
            self.assertEqual((root / "value.txt").read_text(encoding="utf-8"), "old\n")
            run_dir = next(evidence.iterdir())
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertFalse(manifest["delivery_seal_ok"])
            seal = json.loads((run_dir / "delivery-seal.json").read_text(encoding="utf-8"))
            self.assertFalse(seal["unchanged_during_verification"])
            git(root, "worktree", "remove", "--force", manifest["worktree"])

    def test_host_checks_do_not_run_after_the_phase_protocol_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = self.make_repository(parent)
            evidence = parent / "evidence"
            code, output, error = invoke(
                "code", "inspect only", *self.base(root), "--scripted-text", "no plan",
                "--check", "touch must-not-run.txt", "--evidence-dir", str(evidence),
            )
            self.assertEqual(code, 6, error)
            run_dir = next(evidence.iterdir())
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertFalse((Path(manifest["worktree"]) / "must-not-run.txt").exists())
            self.assertNotIn("must-not-run.txt", (run_dir / "changes.patch").read_text(encoding="utf-8"))
            git(root, "worktree", "remove", "--force", manifest["worktree"])

    def test_finishing_without_submit_plan_fails_the_phase_protocol(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = self.make_repository(parent)
            evidence = parent / "evidence"
            code, output, error = invoke(
                "code", "inspect only", *self.base(root),
                "--scripted-text", "done without a plan",
                "--evidence-dir", str(evidence),
            )
            self.assertEqual(code, 6, error)
            run_dir = next(evidence.iterdir())
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            phases = json.loads((run_dir / "phases.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "error_postconditions_failed")
            self.assertEqual(phases["outcome"], "error_postconditions_failed")
            self.assertIn("SubmitPlan", error)

    def test_effect_before_submit_plan_is_blocked_without_touching_the_worktree(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = self.make_repository(parent)
            evidence = parent / "evidence"
            script = parent / "turns.json"
            script.write_text(
                json.dumps(
                    [
                        {
                            "tool": {
                                "name": "Write",
                                "input": {"path": "too-early.txt", "content": "no\n"},
                            }
                        },
                        plan_turn(),
                        {"text": "done"},
                    ]
                ),
                encoding="utf-8",
            )
            code, output, error = invoke(
                "code", "respect the phase gate", *self.base(root),
                "--script", str(script),
                "--evidence-dir", str(evidence),
            )
            self.assertEqual(code, 0, error)
            run_dir = next(evidence.iterdir())
            self.assertNotIn("too-early.txt", (run_dir / "changes.patch").read_text(encoding="utf-8"))
            phases = json.loads((run_dir / "phases.json").read_text(encoding="utf-8"))
            self.assertEqual(
                [row["to"] for row in phases["transitions"]],
                ["understanding", "planned", "verifying", "success_unverified"],
            )


if __name__ == "__main__":
    unittest.main()
