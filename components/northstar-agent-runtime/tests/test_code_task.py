from __future__ import annotations

import json
import hashlib
import os
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
    build_delivery_dissent,
    find_orphan_dissents,
    load_delivery_dissent,
    reconcile_code_evidence,
    write_delivery_dissent,
    validate_check_inputs,
    validate_check_exclusions,
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


class CheckInputPinningTests(unittest.TestCase):
    """The delivery seal must bind the check's inputs, not just the patch.

    A patch that rewrites the check script (or a helper/fixture the check
    reads) to exit 0 must fail verification even though the rewritten check
    itself reports success. These tests drive the real phase machine over a
    real Git worktree and assert both halves: the tampered check passes, and
    verification still refuses it.
    """

    CHECK_INPUTS = ("checks/run_check.py", "checks/helper.py")

    def make_check_repository(self, parent: Path) -> Path:
        root = parent / "repo"
        root.mkdir()
        git(root, "init")
        git(root, "config", "user.email", "northstar-tests@example.invalid")
        git(root, "config", "user.name", "Northstar Tests")
        (root / "app.py").write_text("value = 1\n", encoding="utf-8")
        (root / "checks").mkdir()
        (root / "checks" / "helper.py").write_text("EXPECTED = 2\n", encoding="utf-8")
        (root / "checks" / "run_check.py").write_text(
            "import sys\n\n"
            'sys.path.insert(0, "checks")\n'
            "from helper import EXPECTED\n\n"
            'text = open("app.py", encoding="utf-8").read()\n'
            'sys.exit(0 if f"value = {EXPECTED}" in text else 1)\n',
            encoding="utf-8",
        )
        git(root, "add", "app.py", "checks/helper.py", "checks/run_check.py")
        git(root, "commit", "-m", "initial with host check")
        return root

    def _setup(self, parent: Path, check_inputs=CHECK_INPUTS):
        source = self.make_check_repository(parent)
        isolated = IsolatedCodeWorkspace(
            source, evidence_root=parent / "evidence"
        ).prepare()
        assert isolated.worktree is not None
        assert isolated.evidence_dir is not None
        phases = CodePhaseMachine(
            run_id=isolated.run_id,
            evidence_dir=isolated.evidence_dir,
            worktree=isolated.worktree,
            start_commit=isolated.start_commit,
            check_inputs=check_inputs,
        )
        return source, isolated, phases

    def _drive_to_verifying(self, phases: CodePhaseMachine) -> None:
        phases.start()
        phases.submit_plan(
            {
                "summary": "change app",
                "files": ["app.py"],
                "steps": ["edit"],
                "risks": [],
                "check_indices": [0],
            }
        )

    def test_dissent_artifact_and_forward_sealing(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            _, isolated, phases = self._setup(parent, check_inputs=())
            try:
                assert isolated.worktree is not None and isolated.evidence_dir is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                phases.start()
                phases.submit_plan({"files": ["app.py"], "steps": ["edit"]})
                phases.begin_verification()
                phases.seal_verification()
                seal_path = isolated.evidence_dir / "delivery-seal.json"
                seal_bytes = seal_path.read_bytes()
                seal = json.loads(seal_bytes)
                self.assertEqual(seal["verifier_rule"], phases.verifier_rule)
                self.assertEqual(seal["verifier_rule_version"], "v1")
                self.assertEqual(seal["verifier_rule_hash"], hashlib.sha256(phases.verifier_rule.encode()).hexdigest())
                self.assertEqual(seal["verifier_set"], [])

                with self.assertRaises(CodeTaskError):
                    build_delivery_dissent(seal_path=seal_path, dissenter="reviewer", rule_hash="", rule_version="v1", corpus_hash="a" * 64, verdict="pin_disputed", reason="missing rule")
                with self.assertRaises(CodeTaskError):
                    build_delivery_dissent(seal_path=seal_path, dissenter="reviewer", rule_hash="a" * 64, rule_version="v1", corpus_hash="", verdict="pin_disputed", reason="missing corpus")
                dissent = build_delivery_dissent(
                    seal_path=seal_path, dissenter="reviewer", rule_hash="a" * 64,
                    rule_version="v1", corpus_hash="b" * 64, verdict="pin_disputed",
                    reason="the declared check inputs omitted a helper",
                )
                dissent_path = write_delivery_dissent(isolated.evidence_dir, dissent)
                loaded = load_delivery_dissent(dissent_path)
                self.assertEqual(loaded["seal_sha256"], hashlib.sha256(seal_bytes).hexdigest())
                self.assertEqual(seal_path.read_bytes(), seal_bytes)
                self.assertEqual(json.loads(seal_path.read_bytes())["ok"], seal["ok"])
                self.assertEqual(seal["dissents_pinned"], [])

                later = CodePhaseMachine(
                    run_id="later", evidence_dir=parent / "later-evidence",
                    worktree=isolated.worktree, start_commit=isolated.start_commit,
                    prior_dissents=(dissent_path,),
                    verifiers=(("reviewer", "https://example.invalid/dissent-feed"),),
                )
                (isolated.worktree / "app.py").write_text("value = 3\n", encoding="utf-8")
                later.start()
                later.submit_plan({"files": ["app.py"], "steps": ["edit"]})
                later.begin_verification()
                later.seal_verification()
                later_seal = json.loads((parent / "later-evidence" / "delivery-seal.json").read_text())
                self.assertEqual(later_seal["verifier_set"], [{"id": "reviewer", "dissent_feed": "https://example.invalid/dissent-feed"}])
                digest = hashlib.sha256(dissent_path.read_bytes()).hexdigest()
                self.assertEqual(later_seal["dissents_pinned"][0]["dissent_sha256"], digest)
                records = [{"dissent_sha256": digest}, {"dissent_sha256": "c" * 64}]
                self.assertEqual(find_orphan_dissents(records, [later_seal]), [records[1]])
            finally:
                isolated.cleanup()

    def test_malformed_dissent_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dissent.json"
            for value in (
                {"schema": "wrong"},
                {"schema": "northstar.delivery-dissent.v1"},
                {"schema": "northstar.delivery-dissent.v1", "seal_sha256": "z" * 64,
                 "dissenter": "x", "rule_hash": "a" * 64, "rule_version": "v1",
                 "corpus_hash": "b" * 64, "verdict": "no", "reason": "bad hash"},
            ):
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(CodeTaskError):
                    load_delivery_dissent(path)

    def _run_check(self, worktree: Path) -> int:
        # PYTHONDONTWRITEBYTECODE keeps the run from leaving __pycache__
        # artifacts in the worktree, which the delivery audit would flag.
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        process = subprocess.run(
            [sys.executable, "checks/run_check.py"],
            cwd=str(worktree),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        return process.returncode

    def test_validate_check_inputs_rejects_bad_paths(self):
        self.assertEqual(validate_check_inputs(("a.py", "checks/b.py")), ("a.py", "checks/b.py"))
        for bad in (
            ("",),
            ("  a.py",),
            ("/abs/path.py",),
            ("../escape.py",),
            ("a/../b.py",),
            ("a/./b.py",),
            ("a//b.py",),
            ("a:b.py",),
            ("a.py", "a.py"),
        ):
            with self.assertRaises(CodeTaskError, msg=str(bad)):
                validate_check_inputs(bad)
        with self.assertRaises(CodeTaskError):
            validate_check_inputs(tuple(f"f{n}.py" for n in range(65)))

    def test_task_records_check_inputs(self):
        task = CodeTask(goal="change app", check_inputs=self.CHECK_INPUTS)
        self.assertEqual(task.as_dict()["check_inputs"], list(self.CHECK_INPUTS))
        with self.assertRaises(CodeTaskError):
            CodeTask(goal="change app", check_inputs=("../escape.py",))

    def test_honest_patch_passes_with_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            _, isolated, phases = self._setup(parent)
            try:
                assert isolated.worktree is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                self.assertEqual(self._run_check(isolated.worktree), 0)
                self._drive_to_verifying(phases)
                phases.begin_verification()
                phases.seal_verification()
                phases.finish("success")

                seal = json.loads(
                    (isolated.evidence_dir / "delivery-seal.json").read_text(encoding="utf-8")
                )
                self.assertTrue(seal["ok"])
                self.assertTrue(seal["check_inputs_pinned"])
                self.assertTrue(seal["check_inputs_unchanged"])
                self.assertEqual(
                    [pin["path"] for pin in seal["check_input_pins"]],
                    list(self.CHECK_INPUTS),
                )
                self.assertTrue(all(pin["unchanged"] for pin in seal["check_input_pins"]))
                persisted = json.loads(
                    (isolated.evidence_dir / "phases.json").read_text(encoding="utf-8")
                )
                self.assertEqual(
                    [pin["path"] for pin in persisted["check_input_pins"]],
                    list(self.CHECK_INPUTS),
                )
            finally:
                isolated.cleanup()

    def test_patch_rewriting_check_script_fails_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            _, isolated, phases = self._setup(parent)
            try:
                assert isolated.worktree is not None
                # The honest check fails: app.py still holds value 1.
                self.assertEqual(self._run_check(isolated.worktree), 1)
                # The attack: rewrite the check script itself to exit 0.
                (isolated.worktree / "checks" / "run_check.py").write_text(
                    "import sys\nsys.exit(0)\n", encoding="utf-8"
                )
                self.assertEqual(self._run_check(isolated.worktree), 0)
                self._drive_to_verifying(phases)
                with self.assertRaisesRegex(
                    CodeTaskError, r"pinned check inputs: checks/run_check\.py"
                ):
                    phases.begin_verification()
            finally:
                isolated.cleanup()

    def test_patch_tampering_helper_fails_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated, phases = self._setup(parent)
            try:
                assert isolated.worktree is not None
                self.assertEqual(self._run_check(isolated.worktree), 1)
                # The attack: the check script is byte-identical, but the
                # helper it reads now agrees with the broken app.
                (isolated.worktree / "checks" / "helper.py").write_text(
                    "EXPECTED = 1\n", encoding="utf-8"
                )
                self.assertEqual(
                    (isolated.worktree / "checks" / "run_check.py").read_bytes(),
                    subprocess.run(
                        [
                            "git", "-C", str(source), "show",
                            f"{isolated.start_commit}:checks/run_check.py",
                        ],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).stdout,
                )
                self.assertEqual(self._run_check(isolated.worktree), 0)
                self._drive_to_verifying(phases)
                with self.assertRaisesRegex(
                    CodeTaskError, r"pinned check inputs: checks/helper\.py"
                ):
                    phases.begin_verification()
            finally:
                isolated.cleanup()

    def test_seal_rejects_input_changed_during_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            _, isolated, phases = self._setup(parent)
            try:
                assert isolated.worktree is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                self._drive_to_verifying(phases)
                phases.begin_verification()
                # A pinned input is rewritten after the precheck: the seal
                # must name it instead of validating.
                (isolated.worktree / "checks" / "helper.py").write_text(
                    "EXPECTED = 1\n", encoding="utf-8"
                )
                with self.assertRaisesRegex(
                    CodeTaskError,
                    r"pinned check inputs changed during verification: checks/helper\.py",
                ):
                    phases.seal_verification()
                seal = json.loads(
                    (isolated.evidence_dir / "delivery-seal.json").read_text(encoding="utf-8")
                )
                self.assertFalse(seal["ok"])
                self.assertFalse(seal["check_inputs_unchanged"])
            finally:
                isolated.cleanup()

    def test_verification_is_repeatable(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            _, isolated, phases = self._setup(parent)
            try:
                assert isolated.worktree is not None
                assert isolated.evidence_dir is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                self._drive_to_verifying(phases)
                phases.begin_verification()
                second = CodePhaseMachine(
                    run_id=isolated.run_id,
                    evidence_dir=parent / "evidence-second",
                    worktree=isolated.worktree,
                    start_commit=isolated.start_commit,
                    check_inputs=self.CHECK_INPUTS,
                )
                self._drive_to_verifying(second)
                second.begin_verification()
                self.assertEqual(
                    phases.as_dict()["check_input_pins"],
                    second.as_dict()["check_input_pins"],
                )
                phases.seal_verification()
                first_seal = (isolated.evidence_dir / "delivery-seal.json").read_bytes()
                phases.seal_verification()
                self.assertEqual(
                    first_seal,
                    (isolated.evidence_dir / "delivery-seal.json").read_bytes(),
                )
            finally:
                isolated.cleanup()

    def test_missing_baseline_input_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            _, isolated, phases = self._setup(
                parent, check_inputs=("checks/run_check.py", "checks/missing.py")
            )
            try:
                self._drive_to_verifying(phases)
                with self.assertRaisesRegex(
                    CodeTaskError, r"missing at the starting commit: checks/missing\.py"
                ):
                    phases.begin_verification()
            finally:
                isolated.cleanup()

    def test_no_declared_inputs_behaves_as_before(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            _, isolated, phases = self._setup(parent, check_inputs=())
            try:
                assert isolated.worktree is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                self._drive_to_verifying(phases)
                phases.begin_verification()
                phases.seal_verification()
                phases.finish("success")
                seal = json.loads(
                    (isolated.evidence_dir / "delivery-seal.json").read_text(encoding="utf-8")
                )
                self.assertTrue(seal["ok"])
                self.assertFalse(seal["check_inputs_pinned"])
                self.assertEqual(seal["check_input_pins"], [])
            finally:
                isolated.cleanup()


class DeliverySealV2Tests(unittest.TestCase):
    """Tests for delivery seal v2: tree hash and check exclusions."""

    def make_check_repository(self, parent: Path) -> Path:
        root = parent / "repo"
        root.mkdir()
        git(root, "init")
        git(root, "config", "user.email", "northstar-tests@example.invalid")
        git(root, "config", "user.name", "Northstar Tests")
        (root / "app.py").write_text("value = 1\n", encoding="utf-8")
        (root / "checks").mkdir()
        (root / "checks" / "helper.py").write_text("EXPECTED = 2\n", encoding="utf-8")
        (root / "checks" / "run_check.py").write_text(
            "import sys\nsys.exit(0)\n", encoding="utf-8"
        )
        (root / "docs").mkdir()
        (root / "docs" / "readme.md").write_text("# README\n", encoding="utf-8")
        git(root, "add", "app.py", "checks/helper.py", "checks/run_check.py", "docs/readme.md")
        git(root, "commit", "-m", "initial")
        return root

    def test_seal_includes_tree_hash(self):
        """Tree hash in the seal equals git rev-parse <start_commit>^{tree}."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = self.make_check_repository(parent)
            isolated = IsolatedCodeWorkspace(
                source, evidence_root=parent / "evidence"
            ).prepare()
            try:
                assert isolated.worktree is not None
                assert isolated.evidence_dir is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")

                phases = CodePhaseMachine(
                    run_id=isolated.run_id,
                    evidence_dir=isolated.evidence_dir,
                    worktree=isolated.worktree,
                    start_commit=isolated.start_commit,
                    check_inputs=("checks/run_check.py",),
                )
                phases.start()
                phases.submit_plan({"files": ["app.py"], "steps": ["edit"], "check_indices": [0]})
                phases.begin_verification()
                phases.seal_verification()

                seal = json.loads(
                    (isolated.evidence_dir / "delivery-seal.json").read_text(encoding="utf-8")
                )
                expected_tree_hash = git(isolated.worktree, "rev-parse", f"{isolated.start_commit}^{{tree}}")
                self.assertEqual(seal["start_tree_hash"], expected_tree_hash)
            finally:
                isolated.cleanup()

    def test_seal_schema_is_v2(self):
        """Seal schema field is northstar.delivery-seal.v2."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = self.make_check_repository(parent)
            isolated = IsolatedCodeWorkspace(
                source, evidence_root=parent / "evidence"
            ).prepare()
            try:
                assert isolated.worktree is not None
                assert isolated.evidence_dir is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")

                phases = CodePhaseMachine(
                    run_id=isolated.run_id,
                    evidence_dir=isolated.evidence_dir,
                    worktree=isolated.worktree,
                    start_commit=isolated.start_commit,
                )
                phases.start()
                phases.submit_plan({"files": ["app.py"], "steps": ["edit"]})
                phases.begin_verification()
                phases.seal_verification()

                seal = json.loads(
                    (isolated.evidence_dir / "delivery-seal.json").read_text(encoding="utf-8")
                )
                self.assertEqual(seal["schema"], "northstar.delivery-seal.v2")
            finally:
                isolated.cleanup()

    def test_empty_exclusion_list_is_explicit(self):
        """Seal with empty exclusion list records explicit empty list."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = self.make_check_repository(parent)
            isolated = IsolatedCodeWorkspace(
                source, evidence_root=parent / "evidence"
            ).prepare()
            try:
                assert isolated.worktree is not None
                assert isolated.evidence_dir is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")

                phases = CodePhaseMachine(
                    run_id=isolated.run_id,
                    evidence_dir=isolated.evidence_dir,
                    worktree=isolated.worktree,
                    start_commit=isolated.start_commit,
                    check_exclusions=(),
                )
                phases.start()
                phases.submit_plan({"files": ["app.py"], "steps": ["edit"]})
                phases.begin_verification()
                phases.seal_verification()

                seal = json.loads(
                    (isolated.evidence_dir / "delivery-seal.json").read_text(encoding="utf-8")
                )
                self.assertIn("check_exclusions", seal)
                self.assertEqual(seal["check_exclusions"], [])
            finally:
                isolated.cleanup()

    def test_exclusion_list_round_trips(self):
        """Exclusion list round-trips path + reason into the seal."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = self.make_check_repository(parent)
            isolated = IsolatedCodeWorkspace(
                source, evidence_root=parent / "evidence"
            ).prepare()
            try:
                assert isolated.worktree is not None
                assert isolated.evidence_dir is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")

                exclusions = (
                    ("docs/readme.md", "documentation not pinned"),
                    ("checks/helper.py", "test data varies"),
                )
                phases = CodePhaseMachine(
                    run_id=isolated.run_id,
                    evidence_dir=isolated.evidence_dir,
                    worktree=isolated.worktree,
                    start_commit=isolated.start_commit,
                    check_inputs=("checks/run_check.py",),
                    check_exclusions=exclusions,
                )
                phases.start()
                phases.submit_plan({"files": ["app.py"], "steps": ["edit"]})
                phases.begin_verification()
                phases.seal_verification()

                seal = json.loads(
                    (isolated.evidence_dir / "delivery-seal.json").read_text(encoding="utf-8")
                )
                self.assertEqual(len(seal["check_exclusions"]), 2)
                self.assertEqual(seal["check_exclusions"][0]["path"], "docs/readme.md")
                self.assertEqual(seal["check_exclusions"][0]["reason"], "documentation not pinned")
                self.assertEqual(seal["check_exclusions"][1]["path"], "checks/helper.py")
                self.assertEqual(seal["check_exclusions"][1]["reason"], "test data varies")
            finally:
                isolated.cleanup()

    def test_exclusion_overlapping_check_input_fails(self):
        """Exclusion overlapping a pinned check input fails closed."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = self.make_check_repository(parent)
            with self.assertRaisesRegex(
                CodeTaskError, "is also a declared check input"
            ):
                CodePhaseMachine(
                    run_id="test",
                    evidence_dir=parent / "evidence",
                    worktree=source,
                    start_commit="HEAD",
                    check_inputs=("checks/run_check.py",),
                    check_exclusions=(("checks/run_check.py", "contradiction"),),
                )

    def test_exclusion_missing_at_start_fails(self):
        """Exclusion naming a path missing at the start commit fails closed."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = self.make_check_repository(parent)
            isolated = IsolatedCodeWorkspace(
                source, evidence_root=parent / "evidence"
            ).prepare()
            try:
                assert isolated.worktree is not None
                assert isolated.evidence_dir is not None

                phases = CodePhaseMachine(
                    run_id=isolated.run_id,
                    evidence_dir=isolated.evidence_dir,
                    worktree=isolated.worktree,
                    start_commit=isolated.start_commit,
                    check_exclusions=(("missing.txt", "does not exist"),),
                )
                phases.start()
                phases.submit_plan({"files": ["app.py"], "steps": ["edit"]})
                with self.assertRaisesRegex(
                    CodeTaskError, "check exclusion is missing at the starting commit: missing.txt"
                ):
                    phases.begin_verification()
            finally:
                isolated.cleanup()

    def test_exclusion_naming_directory_fails(self):
        """Exclusion naming a directory/tree (not a file) fails closed."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = self.make_check_repository(parent)
            isolated = IsolatedCodeWorkspace(
                source, evidence_root=parent / "evidence"
            ).prepare()
            try:
                assert isolated.worktree is not None
                assert isolated.evidence_dir is not None

                phases = CodePhaseMachine(
                    run_id=isolated.run_id,
                    evidence_dir=isolated.evidence_dir,
                    worktree=isolated.worktree,
                    start_commit=isolated.start_commit,
                    check_exclusions=(("checks", "directory not allowed"),),
                )
                phases.start()
                phases.submit_plan({"files": ["app.py"], "steps": ["edit"]})
                with self.assertRaisesRegex(
                    CodeTaskError, "check exclusion is not a file at the starting commit: checks"
                ):
                    phases.begin_verification()
            finally:
                isolated.cleanup()


if __name__ == "__main__":
    unittest.main()
