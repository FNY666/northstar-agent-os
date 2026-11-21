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

import code_task
from code_task import (
    CodePhaseMachine,
    CodeTask,
    CodeTaskError,
    IsolatedCodeWorkspace,
    audit_delivery_patch,
    build_delivery_dissent,
    find_orphan_dissents,
    load_delivery_dissent,
    pin_dissents,
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


class PhaseMachineInputGuardTests(unittest.TestCase):
    """The phase machine's constructor guards must reject both halves.

    Each guard in ``CodePhaseMachine.__init__`` is a double check joined by
    ``or``: a *type* half (``not isinstance(x, str)``) and an *emptiness*
    half (``not x.strip()``).  The original suite drove only the type half,
    so a planted fault that swapped the connective (``or`` -> ``and``)
    left it green: with ``and`` the emptiness half is never reached for a
    well-typed value, so a blank run id, a blank verifier rule and a blank
    verifier rule version all slip through.

    The behaviour was correct throughout; the evidence was missing.  These
    tests drive the second half of each guard -- the blank/whitespace value
    -- and assert that the failure is the declared ``CodeTaskError`` rather
    than an incidental ``AttributeError``.
    """

    def _machine(self, evidence_dir: Path, **kwargs) -> CodePhaseMachine:
        return CodePhaseMachine(run_id="guard-test", evidence_dir=evidence_dir, **kwargs)

    def test_blank_run_id_is_rejected(self):
        # The second half of the run-id guard: a string that is empty or only
        # whitespace carries no identity for the run.
        with tempfile.TemporaryDirectory() as directory:
            for run_id in ("", "   ", "\t\n"):
                with self.subTest(run_id=run_id):
                    with self.assertRaisesRegex(CodeTaskError, "needs a run id"):
                        CodePhaseMachine(run_id=run_id, evidence_dir=directory)

    def test_non_text_run_id_is_rejected(self):
        # The first half of the same guard, asserted to fail as the
        # DECLARED error rather than by an AttributeError from ``.strip()``
        # on a non-string.  A guard that short-circuits past the type check
        # must still not reach ``.strip()`` with a non-string value.
        with tempfile.TemporaryDirectory() as directory:
            for run_id in (None, 123, 1.5, ["run"], b"run"):
                with self.subTest(run_id=run_id):
                    with self.assertRaisesRegex(CodeTaskError, "needs a run id"):
                        CodePhaseMachine(run_id=run_id, evidence_dir=directory)

    def test_blank_verifier_rule_is_rejected(self):
        # The second half of the verifier-rule guard: the rule is hashed and
        # recorded in the seal, so a blank rule would be an unverifiable
        # rule pinned into the evidence.
        with tempfile.TemporaryDirectory() as directory:
            for rule in ("", "   ", "\n"):
                with self.subTest(rule=rule):
                    with self.assertRaisesRegex(CodeTaskError, "verifier rule must be"):
                        self._machine(Path(directory), verifier_rule=rule)

    def test_non_text_verifier_rule_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for rule in (None, 42, ["rule"]):
                with self.subTest(rule=rule):
                    with self.assertRaisesRegex(CodeTaskError, "verifier rule must be"):
                        self._machine(Path(directory), verifier_rule=rule)

    def test_blank_verifier_rule_version_is_rejected(self):
        # The second half of the verifier-rule-version guard.
        with tempfile.TemporaryDirectory() as directory:
            for version in ("", "   ", "\t"):
                with self.subTest(version=version):
                    with self.assertRaisesRegex(
                        CodeTaskError, "verifier rule version must be"
                    ):
                        self._machine(Path(directory), verifier_rule_version=version)

    def test_non_text_verifier_rule_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for version in (None, 7, ["v1"]):
                with self.subTest(version=version):
                    with self.assertRaisesRegex(
                        CodeTaskError, "verifier rule version must be"
                    ):
                        self._machine(Path(directory), verifier_rule_version=version)

    def test_non_blank_verifier_rule_is_accepted(self):
        # The other side of the guard: a real rule and version must be
        # accepted, so the tests above are not passing by accident.
        with tempfile.TemporaryDirectory() as directory:
            phases = self._machine(
                Path(directory), verifier_rule="the declared check inputs", verifier_rule_version="v2"
            )
            self.assertEqual(phases.verifier_rule, "the declared check inputs")
            self.assertEqual(phases.verifier_rule_version, "v2")


class CheckInputPinPayloadTests(unittest.TestCase):
    """The persisted phase payload must carry the pinned check inputs.

    ``_payload`` writes the pins as ``[dict(pin) for pin in
    (self._check_input_pins or ())]``.  That ``or`` has two halves: the
    machine has no pins yet (``None`` -> empty list), and the machine has
    pins (the tuple -> the pins themselves).  A planted fault that swapped
    the connective (``or`` -> ``and``) made the pinned case silently
    publish an EMPTY list, so the persisted evidence stopped recording
    which inputs the check was bound to -- and the unpinned case crashed
    outright on ``for pin in None``.

    These tests drive both halves.
    """

    def make_check_repository(self, parent: Path) -> Path:
        root = parent / "repo"
        root.mkdir()
        git(root, "init")
        git(root, "config", "user.email", "northstar-tests@example.invalid")
        git(root, "config", "user.name", "Northstar Tests")
        (root / "app.py").write_text("value = 1\n", encoding="utf-8")
        (root / "checks").mkdir()
        (root / "checks" / "run_check.py").write_text("import sys\nsys.exit(0)\n", encoding="utf-8")
        git(root, "add", "app.py", "checks/run_check.py")
        git(root, "commit", "-m", "initial with host check")
        return root

    def test_unpinned_machine_persists_an_empty_pin_list(self):
        # The falsy half: before any check input is pinned, the payload
        # carries an empty list -- not a crash on a missing value.
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(run_id="unpinned", evidence_dir=parent / "evidence")
            persisted = json.loads(
                (parent / "evidence" / "phases.json").read_text(encoding="utf-8")
            )
            self.assertEqual(persisted["check_input_pins"], [])
            self.assertEqual(phases.as_dict()["check_input_pins"], [])

    def test_pinned_machine_persists_every_pin(self):
        # The truthy half: once the check inputs are pinned, the persisted
        # payload must record them, one record per declared input.  A
        # payload that silently dropped them would let the seal claim a
        # binding the evidence does not contain.
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = self.make_check_repository(parent)
            isolated = IsolatedCodeWorkspace(
                source, evidence_root=parent / "evidence"
            ).prepare()
            try:
                assert isolated.worktree is not None and isolated.evidence_dir is not None
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

                persisted = json.loads(
                    (isolated.evidence_dir / "phases.json").read_text(encoding="utf-8")
                )
                self.assertEqual(
                    [pin["path"] for pin in persisted["check_input_pins"]],
                    ["checks/run_check.py"],
                )
                self.assertEqual(
                    [pin["path"] for pin in phases.as_dict()["check_input_pins"]],
                    ["checks/run_check.py"],
                )
            finally:
                isolated.cleanup()


class CodeTaskSecondHalfGuardTests(unittest.TestCase):
    """Drive the missing arm of every guard that ``code_task`` still defends.

    The census (``b173-mutant.py`` over this module) reported 33
    surviving planted faults.  Every one of them is a *second half* of a two-armed
    conditional, or one conjunct of a conjunction, that the slice's own
    suite never drove:

      or@288   ``_state != "verifying"`` | ``_outcome is not None``
      or@335   ``worktree is None`` | ``not start_commit``
      or@398   ``worktree is None`` | ``_check_input_pins is None``
      or@452   ``receipt.get("diagnostic")`` | the fallback message
      or@480   ``check_inputs`` | ``check_exclusions``
      or@500   ``_state != "verifying"`` | ``_verification_patch_sha256 is None``
      and@552  ``unchanged`` | ``audit["ok"]`` | ``inputs_unchanged``
      or@633   ``not isinstance(value, str)`` | ``not value.strip()``
      or@662   ``not isinstance(record, dict)`` | the schema comparison
      or@671   ``not isinstance(record[key], str)`` | ``not record[key].strip()``
      and@700  ``isinstance(dissent, str)`` | ``_valid_sha256(dissent)``
      gt@740   the ``>=`` bound on the git output cap
      or@740   the ``stdout`` arm | the ``stderr`` arm
      or@744   ``detail`` | ``process.returncode``
      or@810   ``checked.stderr`` | ``checked.stdout``
      or@815   ``seeded.stderr`` | ``seeded.stdout``
      and@831  ``read_tree_exit == 0`` | ``apply_exit == 0``
      gt@864   the delivery-patch byte cap
      gt@870   the delivery file-count cap
      or@886   ``parts & _GENERATED_PARTS`` | ``suffix in _GENERATED_SUFFIXES``
      and@898  ``target.exists()`` | ``target.is_file()``
      gt@903   the per-file byte cap
      and@916  ``line.startswith("+")`` | ``not line.startswith("+++")``
      gt@927   the changed-path truncation bound
      or@958   ``path.is_symlink()`` | ``not path.is_file()``
      gt@961   the 4 MiB evidence cap
      or@990   ``not run_id`` | ``run_id != manifest run_id``
      eq@996   ``sealed_digest == actual_digest``
      eq@997   ``phase_seal == "invalid"``
      or@1006  ``not isinstance(artifact, str)`` | the path-shape checks
      gt@1011  the sealed artifact's size cap
      or@1011  ``path.is_symlink()`` | ``not path.is_file()``
      or@1022  the empty-state fallback message

    The module's behaviour was correct throughout; the *evidence* was
    missing.  These tests drive the missing arm of each guard and pin the
    behaviour the guard protects.
    """

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
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

    def make_worktree(self, parent: Path):
        """Return (source, isolated) with a prepared detached worktree."""
        source = self.make_repository(parent)
        isolated = IsolatedCodeWorkspace(
            source, evidence_root=parent / "evidence"
        ).prepare()
        assert isolated.worktree is not None and isolated.evidence_dir is not None
        return source, isolated

    def make_check_repository(self, parent: Path) -> Path:
        """A repository with a host check script that the patch never touches."""
        root = parent / "repo"
        root.mkdir()
        git(root, "init")
        git(root, "config", "user.email", "northstar-tests@example.invalid")
        git(root, "config", "user.name", "Northstar Tests")
        (root / "app.py").write_text("value = 1\n", encoding="utf-8")
        (root / "checks").mkdir()
        (root / "checks" / "run_check.py").write_text("import sys\nsys.exit(0)\n", encoding="utf-8")
        git(root, "add", "app.py", "checks/run_check.py")
        git(root, "commit", "-m", "initial with host check")
        return root

    def machine_in(self, isolated, **kwargs) -> CodePhaseMachine:
        """A phase machine bound to the isolated run's own evidence directory."""
        return CodePhaseMachine(
            run_id=isolated.run_id,
            evidence_dir=isolated.evidence_dir,
            worktree=isolated.worktree,
            start_commit=isolated.start_commit,
            **kwargs,
        )

    def drive_to_verifying(self, phases: CodePhaseMachine) -> None:
        phases.start()
        phases.submit_plan({"files": ["app.py"], "steps": ["edit"], "check_indices": [0]})

    # ------------------------------------------------------------------
    # or@288 -- begin_check must refuse a task that already has an outcome
    # ------------------------------------------------------------------
    def test_begin_check_refuses_a_task_that_already_has_an_outcome(self):
        """`or@288`: the ``_outcome is not None`` half of the guard.

        ``begin_check`` opens a host-verification effect.  A task that has
        already reached a terminal outcome must not be able to open
        another one: the second half of the guard is what refuses it.
        Under the mutant (``or`` -> ``and``) a task whose state still
        reads ``"verifying"`` but which already carries an outcome would
        be allowed to open a fresh check.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(run_id="outcome-guard", evidence_dir=parent / "evidence")
            self.drive_to_verifying(phases)
            phases.begin_verification()
            self.assertEqual(phases.state, "verifying")
            # The one state that reaches the guard's SECOND arm: the
            # phase reads "verifying" but the task already has an outcome.
            phases._outcome = "success"
            with self.assertRaisesRegex(CodeTaskError, "host checks require the verifying phase"):
                phases.begin_check(index=0)

    def test_begin_check_refuses_a_task_that_is_not_verifying(self):
        """`or@288`: the other half, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(run_id="outcome-guard-2", evidence_dir=parent / "evidence")
            phases.start()
            with self.assertRaisesRegex(CodeTaskError, "host checks require the verifying phase"):
                phases.begin_check(index=0)

    def test_begin_check_is_allowed_without_an_outcome(self):
        """`or@288`: the accepted case, so the tests above are not passing by accident."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(run_id="outcome-guard-3", evidence_dir=parent / "evidence")
            self.drive_to_verifying(phases)
            phases.begin_verification()
            effect = phases.begin_check(index=0)
            self.assertTrue(effect)
            self.assertEqual(phases.as_dict()["effects"][0]["tool"], "HostCheck")

    # ------------------------------------------------------------------
    # or@335 -- pinning needs a worktree AND a start commit
    # ------------------------------------------------------------------
    def test_pinning_without_a_start_commit_fails_closed(self):
        """`or@335`: the ``not self.start_commit`` half.

        The worktree is present but the start commit is unknown, so the
        pins cannot be content-addressed at a known tree.  Under the
        mutant (``or`` -> ``and``) the guard would be satisfied by the
        worktree alone, and the pins would be taken against an unknown
        commit -- or the failure would surface as some later, less
        specific error.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                phases = self.machine_in(isolated)
                phases.start_commit = ""
                with self.assertRaisesRegex(
                    CodeTaskError,
                    "check inputs cannot be pinned without a worktree and start commit",
                ):
                    phases._pin_check_inputs()
            finally:
                isolated.cleanup()

    def test_pinning_without_a_worktree_fails_closed(self):
        """`or@335`: the other half, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(
                run_id="no-worktree",
                evidence_dir=parent / "evidence",
                start_commit="0" * 40,
            )
            with self.assertRaisesRegex(
                CodeTaskError,
                "check inputs cannot be pinned without a worktree and start commit",
            ):
                phases._pin_check_inputs()

    # ------------------------------------------------------------------
    # or@398 -- verifying pins need a worktree AND captured pins
    # ------------------------------------------------------------------
    def test_verifying_pins_requires_captured_pins(self):
        """`or@398`: the ``_check_input_pins is None`` half.

        ``_verify_check_input_pins`` compares the pinned inputs against
        the worktree's current content.  With a worktree but no captured
        pins there is nothing to compare, so the call must fail closed.
        Under the mutant (``or`` -> ``and``) the missing pins would be
        accepted as "nothing to verify".
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                phases = self.machine_in(isolated)
                with self.assertRaisesRegex(
                    CodeTaskError, "check input pins have not been captured"
                ):
                    phases._verify_check_input_pins()
            finally:
                isolated.cleanup()

    def test_verifying_pins_requires_a_worktree(self):
        """`or@398`: the other half, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(
                run_id="pins-no-worktree",
                evidence_dir=parent / "evidence",
                start_commit="0" * 40,
            )
            with self.assertRaisesRegex(
                CodeTaskError, "check input pins have not been captured"
            ):
                phases._verify_check_input_pins()

    # ------------------------------------------------------------------
    # or@452 -- the replay diagnostic, or the fallback message
    # ------------------------------------------------------------------
    def test_replay_failure_reports_the_git_diagnostic(self):
        """`or@452`: the ``receipt.get("diagnostic")`` half.

        When the patch cannot be replayed, the error must carry Git's
        own diagnostic -- the reason the apply failed.  Under the mutant
        (``or`` -> ``and``) the diagnostic would be replaced by the
        generic fallback and the operator would lose the cause.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                # Commit a change, then change the file again: the patch
                # against HEAD no longer applies to the START commit.
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                git(isolated.worktree, "commit", "-am", "second commit")
                (isolated.worktree / "app.py").write_text("value = 3\n", encoding="utf-8")
                phases = self.machine_in(isolated)
                self.drive_to_verifying(phases)
                with self.assertRaisesRegex(
                    CodeTaskError, "final patch cannot be replayed"
                ) as caught:
                    phases.begin_verification()
                message = str(caught.exception)
                self.assertNotIn("git apply check failed", message)
                self.assertIn("app.py", message)
            finally:
                isolated.cleanup()

    # ------------------------------------------------------------------
    # or@480 -- check inputs OR exclusions without a worktree
    # ------------------------------------------------------------------
    def test_check_exclusions_without_a_worktree_fail_closed(self):
        """`or@480`: the ``check_exclusions`` half.

        A task that declares only *exclusions* (no check inputs) still
        needs a worktree: the exclusion list is validated against the
        start commit.  Under the mutant (``or`` -> ``and``) a task with
        exclusions but no check inputs would skip the worktree check
        entirely and seal an unvalidated exclusion list.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(
                run_id="exclusions-no-worktree",
                evidence_dir=parent / "evidence",
                start_commit="0" * 40,
                check_exclusions=(("app.py", "not pinned"),),
            )
            self.drive_to_verifying(phases)
            with self.assertRaisesRegex(
                CodeTaskError,
                "check inputs or exclusions cannot be verified without a worktree",
            ):
                phases.begin_verification()

    def test_check_inputs_without_a_worktree_fail_closed(self):
        """`or@480`: the other half, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(
                run_id="inputs-no-worktree",
                evidence_dir=parent / "evidence",
                start_commit="0" * 40,
                check_inputs=("app.py",),
            )
            self.drive_to_verifying(phases)
            with self.assertRaisesRegex(
                CodeTaskError,
                "check inputs or exclusions cannot be verified without a worktree",
            ):
                phases.begin_verification()

    # ------------------------------------------------------------------
    # or@500 -- sealing needs the verifying state AND a precheck receipt
    # ------------------------------------------------------------------
    def test_seal_requires_a_completed_patch_precheck(self):
        """`or@500`: the ``_verification_patch_sha256 is None`` half.

        ``seal_verification`` proves the host checks did not change the
        audited patch.  Without a precheck there is no patch to compare
        against, so the seal must refuse.  Under the mutant
        (``or`` -> ``and``) a machine that reached the verifying state
        without a precheck would still seal, producing a receipt whose
        ``unchanged_during_verification`` compares nothing.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                phases = self.machine_in(isolated)
                self.drive_to_verifying(phases)
                phases.begin_verification()
                # Force the verifying state without keeping the precheck.
                phases._verification_patch_sha256 = None
                with self.assertRaisesRegex(
                    CodeTaskError, "delivery sealing requires completed patch prechecks"
                ):
                    phases.seal_verification()
            finally:
                isolated.cleanup()

    def test_seal_requires_the_verifying_state(self):
        """`or@500`: the other half, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                phases = self.machine_in(isolated)
                self.drive_to_verifying(phases)
                with self.assertRaisesRegex(
                    CodeTaskError, "delivery sealing requires completed patch prechecks"
                ):
                    phases.seal_verification()
            finally:
                isolated.cleanup()

    # ------------------------------------------------------------------
    # and@552 -- the seal's overall ok flag
    # ------------------------------------------------------------------
    def test_seal_is_not_ok_when_the_patch_changed_during_verification(self):
        """`and@552`: the ``unchanged`` conjunct.

        The seal is only ``ok`` when the patch, the audit AND the pinned
        inputs all agree.  Under the mutant (``and`` -> ``or``) any one
        of the three agreeing would make the whole receipt ok.  Here the
        patch changed after the precheck, so ``unchanged`` is False while
        the audit and the pins are fine.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None and isolated.evidence_dir is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                phases = self.machine_in(isolated)
                self.drive_to_verifying(phases)
                phases.begin_verification()
                # Change the delivery AFTER the precheck: the audit sees a
                # different patch than the one that was verified.
                (isolated.worktree / "app.py").write_text("value = 3\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    CodeTaskError, "host verification modified the audited delivery patch"
                ):
                    phases.seal_verification()
                seal = json.loads(
                    (isolated.evidence_dir / "delivery-seal.json").read_text(encoding="utf-8")
                )
                self.assertFalse(seal["unchanged_during_verification"])
                self.assertTrue(seal["patch_audit_ok"])
                self.assertTrue(seal["check_inputs_unchanged"])
                self.assertFalse(seal["ok"])
            finally:
                isolated.cleanup()

    def test_seal_is_not_ok_when_the_audit_fails(self):
        """`and@552`: the ``audit["ok"]`` conjunct.

        The seal must be refused when the delivery audit found a hazard,
        even though the patch is unchanged and the pinned inputs are
        unchanged.  The audit is stubbed here so that exactly one
        conjunct is false.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None and isolated.evidence_dir is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                phases = self.machine_in(isolated)
                self.drive_to_verifying(phases)
                phases.begin_verification()
                precheck_sha = phases._verification_patch_sha256
                failing_audit = {"ok": False, "patch_sha256": precheck_sha, "findings": []}
                with patch("code_task.audit_delivery_patch", return_value=failing_audit):
                    with self.assertRaisesRegex(
                        CodeTaskError, "delivery audit failed after host verification"
                    ):
                        phases.seal_verification()
                seal = json.loads(
                    (isolated.evidence_dir / "delivery-seal.json").read_text(encoding="utf-8")
                )
                self.assertFalse(seal["patch_audit_ok"])
                self.assertTrue(seal["unchanged_during_verification"])
                self.assertTrue(seal["check_inputs_unchanged"])
                self.assertFalse(seal["ok"])
            finally:
                isolated.cleanup()

    def test_seal_is_not_ok_when_a_pinned_input_changed(self):
        """`and@552`: the ``inputs_unchanged`` conjunct.

        The pinned inputs are stubbed so that exactly one conjunct is
        false: the patch is unchanged, the audit is clean, but a pinned
        input no longer matches its baseline.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = self.make_check_repository(parent)
            isolated = IsolatedCodeWorkspace(
                source, evidence_root=parent / "evidence"
            ).prepare()
            try:
                assert isolated.worktree is not None and isolated.evidence_dir is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                phases = self.machine_in(isolated, check_inputs=("checks/run_check.py",))
                self.drive_to_verifying(phases)
                phases.begin_verification()
                mismatched = [
                    {
                        "path": "app.py",
                        "baseline_blob_sha": "0" * 64,
                        "current_blob_sha": "1" * 64,
                        "unchanged": False,
                    }
                ]
                with patch.object(
                    CodePhaseMachine, "_verify_check_input_pins", return_value=mismatched
                ):
                    with self.assertRaisesRegex(
                        CodeTaskError, "pinned check inputs changed during verification"
                    ):
                        phases.seal_verification()
                seal = json.loads(
                    (isolated.evidence_dir / "delivery-seal.json").read_text(encoding="utf-8")
                )
                self.assertFalse(seal["check_inputs_unchanged"])
                self.assertTrue(seal["unchanged_during_verification"])
                self.assertTrue(seal["patch_audit_ok"])
                self.assertFalse(seal["ok"])
            finally:
                isolated.cleanup()

    def test_seal_is_ok_when_every_conjunct_agrees(self):
        """`and@552`: the control -- all three agree."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None and isolated.evidence_dir is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                phases = self.machine_in(isolated)
                self.drive_to_verifying(phases)
                phases.begin_verification()
                phases.seal_verification()
                seal = json.loads(
                    (isolated.evidence_dir / "delivery-seal.json").read_text(encoding="utf-8")
                )
                self.assertTrue(seal["unchanged_during_verification"])
                self.assertTrue(seal["patch_audit_ok"])
                self.assertTrue(seal["check_inputs_unchanged"])
                self.assertTrue(seal["ok"])
            finally:
                isolated.cleanup()

    # ------------------------------------------------------------------
    # or@633 -- a dissent field must be non-empty text
    # ------------------------------------------------------------------
    def test_blank_dissent_text_fields_are_rejected(self):
        """`or@633`: the ``not value.strip()`` half.

        A blank ``dissenter``/``rule_version``/``verdict``/``reason`` is
        well-typed text, so only the emptiness half refuses it.  Under
        the mutant (``or`` -> ``and``) a blank dissent field would be
        accepted and pinned into the seal.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            seal = parent / "delivery-seal.json"
            seal.write_text("{}\n", encoding="utf-8")
            for field in ("dissenter", "rule_version", "verdict", "reason"):
                with self.subTest(field=field):
                    kwargs = self._dissent_kwargs(seal)
                    kwargs[field] = "   "
                    with self.assertRaisesRegex(
                        CodeTaskError, f"dissent {field} must be non-empty text"
                    ):
                        build_delivery_dissent(**kwargs)

    def test_non_text_dissent_fields_are_rejected(self):
        """`or@633`: the other half, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            seal = parent / "delivery-seal.json"
            seal.write_text("{}\n", encoding="utf-8")
            for field in ("dissenter", "rule_version", "verdict", "reason"):
                with self.subTest(field=field):
                    kwargs = self._dissent_kwargs(seal)
                    kwargs[field] = 42
                    with self.assertRaisesRegex(
                        CodeTaskError, f"dissent {field} must be non-empty text"
                    ):
                        build_delivery_dissent(**kwargs)

    @staticmethod
    def _dissent_kwargs(seal: Path) -> dict:
        return {
            "seal_path": seal,
            "dissenter": "reviewer",
            "rule_hash": "a" * 64,
            "rule_version": "v1",
            "corpus_hash": "b" * 64,
            "verdict": "pin_disputed",
            "reason": "the declared check inputs omitted a helper",
        }

    # ------------------------------------------------------------------
    # or@662 -- the dissent schema guard
    # ------------------------------------------------------------------
    def test_a_non_dict_dissent_is_rejected(self):
        """`or@662`: the ``not isinstance(record, dict)`` half.

        A dissent record that is not an object at all cannot carry a
        schema, so it must be refused.  Under the mutant
        (``or`` -> ``and``) the schema comparison would be reached on a
        non-object and the guard would not refuse it as the declared
        error.
        """
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dissent.json"
            for value in ([], "northstar.delivery-dissent.v1", 7, None):
                with self.subTest(value=repr(value)):
                    path.write_text(json.dumps(value), encoding="utf-8")
                    with self.assertRaisesRegex(CodeTaskError, "invalid delivery dissent schema"):
                        load_delivery_dissent(path)

    def test_a_dissent_with_the_wrong_schema_is_rejected(self):
        """`or@662`: the other half, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dissent.json"
            path.write_text(
                json.dumps({"schema": "northstar.delivery-dissent.v2"}), encoding="utf-8"
            )
            with self.assertRaisesRegex(CodeTaskError, "invalid delivery dissent schema"):
                load_delivery_dissent(path)

    # ------------------------------------------------------------------
    # or@671 -- a dissent's text fields must be non-empty text
    # ------------------------------------------------------------------
    def test_blank_dissent_record_fields_are_rejected(self):
        """`or@671`: the ``not record[key].strip()`` half.

        A loaded dissent whose ``dissenter``/``rule_version``/``verdict``/
        ``reason`` is blank must be refused.  Under the mutant
        (``or`` -> ``and``) the blank value would pass the type check and
        be returned as a valid record.
        """
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dissent.json"
            for field in ("dissenter", "rule_version", "verdict", "reason"):
                with self.subTest(field=field):
                    record = self._dissent_record()
                    record[field] = "\t\n "
                    path.write_text(json.dumps(record), encoding="utf-8")
                    with self.assertRaisesRegex(
                        CodeTaskError, f"delivery dissent {field} must be non-empty text"
                    ):
                        load_delivery_dissent(path)

    def test_non_text_dissent_record_fields_are_rejected(self):
        """`or@671``: the other half, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dissent.json"
            for field in ("dissenter", "rule_version", "verdict", "reason"):
                with self.subTest(field=field):
                    record = self._dissent_record()
                    record[field] = 42
                    path.write_text(json.dumps(record), encoding="utf-8")
                    with self.assertRaisesRegex(
                        CodeTaskError, f"delivery dissent {field} must be non-empty text"
                    ):
                        load_delivery_dissent(path)

    @staticmethod
    def _dissent_record() -> dict:
        return {
            "schema": "northstar.delivery-dissent.v1",
            "seal_sha256": "a" * 64,
            "dissenter": "reviewer",
            "rule_hash": "b" * 64,
            "rule_version": "v1",
            "corpus_hash": "c" * 64,
            "verdict": "pin_disputed",
            "reason": "the declared check inputs omitted a helper",
        }

    # ------------------------------------------------------------------
    # and@700 -- a dissent string is a digest only if it is a valid SHA-256
    # ------------------------------------------------------------------
    def test_a_non_sha256_dissent_string_is_read_as_a_path(self):
        """`and@700`: the ``_valid_sha256(dissent)`` half.

        ``pin_dissents`` treats a string argument as an already-computed
        digest only when it is a 64-hex SHA-256.  A string that is not a
        digest must be read as a PATH.  Under the mutant
        (``and`` -> ``or``) every string would be taken as a digest, so a
        path would be pinned as if it were its own hash.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            dissent_file = parent / "dissent.json"
            dissent_file.write_text("dissent content\n", encoding="utf-8")
            pinned = pin_dissents((str(dissent_file),))
            self.assertEqual(
                pinned[0]["dissent_sha256"],
                hashlib.sha256(dissent_file.read_bytes()).hexdigest(),
            )
            self.assertEqual(pinned[0]["path"], str(dissent_file))

    def test_a_sha256_dissent_string_is_pinned_as_a_digest(self):
        """`and@700`: the other half, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            digest = "d" * 64
            pinned = pin_dissents((digest,))
            self.assertEqual(pinned[0]["dissent_sha256"], digest)
            self.assertNotIn("path", pinned[0])

    # ------------------------------------------------------------------
    # gt@740 / or@740 -- the 64 MiB git output cap
    # ------------------------------------------------------------------
    def test_git_stdout_at_the_cap_is_accepted(self):
        """`gt@740`: the stdout arm's boundary.

        Output exactly at the cap is within it.  Under the mutant
        (``>`` -> ``>=``) it would be refused one byte early.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_repository(Path(directory))
            probe = code_task._run_git(root, "rev-parse", "HEAD", check=False)
            with patch("code_task.MAX_GIT_OUTPUT_BYTES", len(probe.stdout)):
                code_task._run_git(root, "rev-parse", "HEAD", check=False)

    def test_git_stderr_at_the_cap_is_accepted(self):
        """`gt@740`: the stderr arm's boundary."""
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_repository(Path(directory))
            probe = code_task._run_git(root, "rev-parse", "--verify", "no-such-ref", check=False)
            with patch("code_task.MAX_GIT_OUTPUT_BYTES", len(probe.stderr)):
                code_task._run_git(root, "rev-parse", "--verify", "no-such-ref", check=False)

    def test_oversized_git_stderr_is_refused(self):
        """`or@740`: the ``len(stderr)`` arm.

        Git's *stderr* is capped by the same 64 MiB evidence limit as
        its stdout.  Under the mutant (``or`` -> ``and``) an enormous
        stderr would be captured whole into memory and into the error
        message.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_repository(Path(directory))
            with patch("code_task.MAX_GIT_OUTPUT_BYTES", 8):
                with self.assertRaisesRegex(
                    CodeTaskError, "git output exceeded the 64 MiB evidence limit"
                ):
                    code_task._run_git(root, "rev-parse", "--verify", "no-such-ref")

    def test_oversized_git_stdout_is_refused(self):
        """`or@740`: the ``len(stdout)`` arm, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_repository(Path(directory))
            with patch("code_task.MAX_GIT_OUTPUT_BYTES", 8):
                with self.assertRaisesRegex(
                    CodeTaskError, "git output exceeded the 64 MiB evidence limit"
                ):
                    code_task._run_git(root, "rev-parse", "HEAD", check=False)

    # ------------------------------------------------------------------
    # or@744 -- the git failure message names the reason
    # ------------------------------------------------------------------
    def test_a_git_failure_reports_the_reason_not_the_exit_code(self):
        """`or@744`: the ``detail`` half.

        When Git fails, the error must carry Git's own diagnostic so the
        operator can see WHY it failed.  Under the mutant
        (``or`` -> ``and``) the generic exit code would be reported
        instead and the reason lost.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_repository(Path(directory))
            with self.assertRaises(CodeTaskError) as caught:
                code_task._run_git(root, "rev-parse", "--verify", "no-such-ref")
            message = str(caught.exception)
            self.assertNotIn("failed: 128", message)
            self.assertIn("no-such-ref", message)

    # ------------------------------------------------------------------
    # or@810 / or@815 -- the replay diagnostic's source stream
    # ------------------------------------------------------------------
    def test_the_replay_diagnostic_reads_stderr_first(self):
        """`or@810`: the ``checked.stderr`` half.

        Git writes its "patch does not apply" diagnostic to stderr, so
        the receipt's diagnostic must come from stderr.  Under the mutant
        (``or`` -> ``and``) the diagnostic would be read from stdout
        instead -- which is empty for a failing apply -- and the receipt
        would carry no reason at all.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                git(isolated.worktree, "commit", "-am", "second commit")
                (isolated.worktree / "app.py").write_text("value = 3\n", encoding="utf-8")
                receipt = code_task.validate_patch_replay(
                    isolated.worktree,
                    start_commit=isolated.start_commit,
                    evidence_dir=parent / "evidence",
                )
                self.assertFalse(receipt["ok"])
                self.assertEqual(receipt["apply_exit_code"], 1)
                self.assertIn("app.py", receipt["diagnostic"])
            finally:
                isolated.cleanup()

    def test_the_replay_diagnostic_reports_a_bad_start_commit(self):
        """`or@815`: the ``seeded.stderr`` half.

        When the start commit cannot be read into the index, the
        receipt's diagnostic must carry Git's stderr ("not a valid
        object name").  Under the mutant (``or`` -> ``and``) it would be
        read from stdout, which is empty, and the receipt would say
        nothing.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                receipt = code_task.validate_patch_replay(
                    isolated.worktree,
                    start_commit="deadbeef",
                    evidence_dir=parent / "evidence",
                )
                self.assertFalse(receipt["ok"])
                self.assertNotEqual(receipt["read_tree_exit_code"], 0)
                self.assertNotEqual(receipt["apply_exit_code"], 0)
                self.assertIn("deadbeef", receipt["diagnostic"])
            finally:
                isolated.cleanup()

    # ------------------------------------------------------------------
    # and@831 -- the replay receipt's ok flag
    # ------------------------------------------------------------------
    def test_the_replay_receipt_is_not_ok_when_the_apply_fails(self):
        """`and@831`: the ``apply_exit == 0`` conjunct.

        The receipt is only ok when the tree was seeded AND the patch
        applied.  Under the mutant (``and`` -> ``or``) a failed apply
        would still be ok because the read-tree succeeded.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                git(isolated.worktree, "commit", "-am", "second commit")
                (isolated.worktree / "app.py").write_text("value = 3\n", encoding="utf-8")
                receipt = code_task.validate_patch_replay(
                    isolated.worktree,
                    start_commit=isolated.start_commit,
                    evidence_dir=parent / "evidence",
                )
                self.assertEqual(receipt["read_tree_exit_code"], 0)
                self.assertNotEqual(receipt["apply_exit_code"], 0)
                self.assertFalse(receipt["ok"])
            finally:
                isolated.cleanup()

    def test_the_replay_receipt_is_not_ok_when_the_tree_cannot_be_read(self):
        """`and@831`: the other conjunct, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                receipt = code_task.validate_patch_replay(
                    isolated.worktree,
                    start_commit="deadbeef",
                    evidence_dir=parent / "evidence",
                )
                self.assertNotEqual(receipt["read_tree_exit_code"], 0)
                self.assertFalse(receipt["ok"])
            finally:
                isolated.cleanup()

    # ------------------------------------------------------------------
    # gt@864 / gt@870 / gt@927 -- the delivery caps
    # ------------------------------------------------------------------
    def test_an_oversized_delivery_patch_is_a_finding(self):
        """`gt@864`: the delivery-patch byte cap."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                with patch("code_task.MAX_DELIVERY_PATCH_BYTES", 10):
                    receipt = code_task.audit_delivery_patch(
                        isolated.worktree, evidence_dir=parent / "evidence"
                    )
                self.assertFalse(receipt["ok"])
                self.assertIn(
                    "patch_too_large", {item["code"] for item in receipt["findings"]}
                )
            finally:
                isolated.cleanup()

    def test_a_patch_at_the_cap_is_not_over_the_cap(self):
        """`gt@864`: the boundary, from the other side."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                (isolated.worktree / "app.py").write_text("value = 2\n", encoding="utf-8")
                probe = code_task.audit_delivery_patch(
                    isolated.worktree, evidence_dir=parent / "evidence"
                )
                with patch("code_task.MAX_DELIVERY_PATCH_BYTES", probe["patch_bytes"]):
                    receipt = code_task.audit_delivery_patch(
                        isolated.worktree, evidence_dir=parent / "evidence"
                    )
                self.assertEqual(receipt["patch_bytes"], probe["patch_bytes"])
                self.assertNotIn(
                    "patch_too_large", {item["code"] for item in receipt["findings"]}
                )
            finally:
                isolated.cleanup()

    def test_too_many_changed_files_is_a_finding(self):
        """`gt@870`: the delivery file-count cap."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                for index in range(5):
                    (isolated.worktree / f"extra{index}.py").write_text(
                        f"x = {index}\n", encoding="utf-8"
                    )
                with patch("code_task.MAX_DELIVERY_FILES", 2):
                    receipt = code_task.audit_delivery_patch(
                        isolated.worktree, evidence_dir=parent / "evidence"
                    )
                self.assertFalse(receipt["ok"])
                self.assertIn(
                    "too_many_files", {item["code"] for item in receipt["findings"]}
                )
            finally:
                isolated.cleanup()

    def test_the_file_count_cap_boundary_is_strict(self):
        """`gt@870`: the boundary, from the other side."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                for index in range(3):
                    (isolated.worktree / f"extra{index}.py").write_text(
                        f"x = {index}\n", encoding="utf-8"
                    )
                with patch("code_task.MAX_DELIVERY_FILES", 3):
                    receipt = code_task.audit_delivery_patch(
                        isolated.worktree, evidence_dir=parent / "evidence"
                    )
                self.assertEqual(receipt["changed_files"], 3)
                self.assertNotIn(
                    "too_many_files", {item["code"] for item in receipt["findings"]}
                )
            finally:
                isolated.cleanup()

    def test_changed_paths_are_truncated_at_the_cap(self):
        """`gt@927`: the truncation bound.

        The receipt flags truncation only when there are MORE than
        ``MAX_DELIVERY_FILES + 1`` paths.  Under the mutant
        (``>`` -> ``>=``) exactly ``MAX_DELIVERY_FILES + 1`` paths would
        be flagged as truncated.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                for index in range(4):
                    (isolated.worktree / f"extra{index}.py").write_text(
                        f"x = {index}\n", encoding="utf-8"
                    )
                with patch("code_task.MAX_DELIVERY_FILES", 3):
                    receipt = code_task.audit_delivery_patch(
                        isolated.worktree, evidence_dir=parent / "evidence"
                    )
                # 4 changed paths == the cap + 1: not truncated.
                self.assertEqual(receipt["changed_files"], 4)
                self.assertFalse(receipt["changed_paths_truncated"])
                self.assertEqual(len(receipt["changed_paths"]), 4)
            finally:
                isolated.cleanup()

    def test_changed_paths_are_truncated_above_the_cap(self):
        """`gt@927`: the other side, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                for index in range(5):
                    (isolated.worktree / f"extra{index}.py").write_text(
                        f"x = {index}\n", encoding="utf-8"
                    )
                with patch("code_task.MAX_DELIVERY_FILES", 3):
                    receipt = code_task.audit_delivery_patch(
                        isolated.worktree, evidence_dir=parent / "evidence"
                    )
                self.assertTrue(receipt["changed_paths_truncated"])
                self.assertEqual(len(receipt["changed_paths"]), 4)
            finally:
                isolated.cleanup()

    # ------------------------------------------------------------------
    # or@886 -- generated artifacts
    # ------------------------------------------------------------------
    def test_a_generated_suffix_is_a_finding(self):
        """`or@886`: the ``suffix in _GENERATED_SUFFIXES`` half.

        A compiled artifact (``.pyc``) is excluded from delivery even
        though no path segment is a generated directory name.  Under the
        mutant (``or`` -> ``and``) the suffix half would never be
        consulted and such an artifact would ship.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                (isolated.worktree / "compiled.pyc").write_bytes(b"\x00\x01")
                receipt = code_task.audit_delivery_patch(
                    isolated.worktree, evidence_dir=parent / "evidence"
                )
                self.assertFalse(receipt["ok"])
                self.assertIn(
                    "generated_artifact", {item["code"] for item in receipt["findings"]}
                )
            finally:
                isolated.cleanup()

    def test_a_generated_directory_is_a_finding(self):
        """`or@886`: the other half, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                (isolated.worktree / "build").mkdir()
                (isolated.worktree / "build" / "out.py").write_text("x = 1\n", encoding="utf-8")
                receipt = code_task.audit_delivery_patch(
                    isolated.worktree, evidence_dir=parent / "evidence"
                )
                self.assertFalse(receipt["ok"])
                self.assertIn(
                    "generated_artifact", {item["code"] for item in receipt["findings"]}
                )
            finally:
                isolated.cleanup()

    # ------------------------------------------------------------------
    # and@898 / gt@903 -- the per-file size check
    # ------------------------------------------------------------------
    def test_a_changed_directory_is_not_measured_as_a_large_file(self):
        """`and@898`: the ``target.is_file()`` conjunct.

        A changed path can resolve to a DIRECTORY (here a symlink to an
        ignored directory).  Only a regular file may be measured, so the
        directory's own size must not be reported as a file size.  Under
        the mutant (``and`` -> ``or``) the size check would run on the
        directory and could report a spurious ``large_file`` finding.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = parent / "repo"
            source.mkdir()
            git(source, "init")
            git(source, "config", "user.email", "northstar-tests@example.invalid")
            git(source, "config", "user.name", "Northstar Tests")
            (source / "app.py").write_text("value = 1\n", encoding="utf-8")
            (source / ".gitignore").write_text("ignored/\n", encoding="utf-8")
            (source / "link.txt").symlink_to("old")
            git(source, "add", "app.py", ".gitignore", "link.txt")
            git(source, "commit", "-m", "initial")
            isolated = IsolatedCodeWorkspace(
                source, evidence_root=parent / "evidence"
            ).prepare()
            try:
                assert isolated.worktree is not None
                # Retarget the symlink at an ignored directory: the only
                # changed path is the symlink, and it resolves to a
                # directory whose own size exceeds the file cap.
                (isolated.worktree / "link.txt").unlink()
                (isolated.worktree / "link.txt").symlink_to("ignored")
                (isolated.worktree / "ignored").mkdir()
                for index in range(50):
                    (isolated.worktree / "ignored" / f"p{index}.bin").write_bytes(
                        b"x" * 100
                    )
                # The cap is placed just BELOW the directory's own size, so a
                # mutant that measures the directory would report it as too
                # large.  The regular files inside are ignored by Git and
                # are not changed paths, so they are never measured.
                directory_size = (isolated.worktree / "ignored").stat().st_size
                self.assertGreater(directory_size, 0)
                with patch(
                    "code_task.MAX_DELIVERY_FILE_BYTES", directory_size - 1
                ):
                    receipt = code_task.audit_delivery_patch(
                        isolated.worktree, evidence_dir=parent / "evidence"
                    )
                self.assertNotIn(
                    "large_file", {item["code"] for item in receipt["findings"]}
                )
            finally:
                isolated.cleanup()

    def test_a_large_changed_file_is_a_finding(self):
        """`and@898`: the other conjunct, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                (isolated.worktree / "app.py").write_text("x" * 100 + "\n", encoding="utf-8")
                with patch("code_task.MAX_DELIVERY_FILE_BYTES", 10):
                    receipt = code_task.audit_delivery_patch(
                        isolated.worktree, evidence_dir=parent / "evidence"
                    )
                self.assertIn(
                    "large_file", {item["code"] for item in receipt["findings"]}
                )
            finally:
                isolated.cleanup()

    def test_a_file_at_the_byte_cap_is_not_too_large(self):
        """`gt@903`: the per-file byte cap boundary.

        A changed file exactly at the cap is within it.  Under the
        mutant (``>`` -> ``>=``) it would be reported as too large.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                (isolated.worktree / "app.py").write_text("x" * 40, encoding="utf-8")
                with patch("code_task.MAX_DELIVERY_FILE_BYTES", 40):
                    receipt = code_task.audit_delivery_patch(
                        isolated.worktree, evidence_dir=parent / "evidence"
                    )
                self.assertNotIn(
                    "large_file", {item["code"] for item in receipt["findings"]}
                )
            finally:
                isolated.cleanup()

    def test_a_file_one_byte_over_the_cap_is_too_large(self):
        """`gt@903`: the bound, from the other side."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                (isolated.worktree / "app.py").write_text("x" * 41, encoding="utf-8")
                with patch("code_task.MAX_DELIVERY_FILE_BYTES", 40):
                    receipt = code_task.audit_delivery_patch(
                        isolated.worktree, evidence_dir=parent / "evidence"
                    )
                self.assertIn(
                    "large_file", {item["code"] for item in receipt["findings"]}
                )
            finally:
                isolated.cleanup()

    # ------------------------------------------------------------------
    # and@916 -- the secret scan reads added lines only
    # ------------------------------------------------------------------
    def test_a_secret_in_a_patch_header_is_not_a_finding(self):
        """`and@916`: the ``not line.startswith("+++")`` conjunct.

        The secret scan reads the ADDED lines of the patch.  A patch
        header (``+++ b/<path>``) is not added content.  Under the
        mutant (``and`` -> ``or``) the header would be scanned as added
        content, and a credential-shaped PATH would be reported as a
        leaked secret.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                # A PATH whose name is credential-shaped: it appears in
                # the "+++ b/<path>" header but never in added content.
                (isolated.worktree / ("sk-" + "A" * 40 + ".py")).write_text(
                    "x = 1\n", encoding="utf-8"
                )
                receipt = code_task.audit_delivery_patch(
                    isolated.worktree, evidence_dir=parent / "evidence"
                )
                self.assertNotIn(
                    "api_key", {item["code"] for item in receipt["findings"]}
                )
            finally:
                isolated.cleanup()

    def test_a_secret_in_an_added_line_is_a_finding(self):
        """`and@916`: the other conjunct, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, isolated = self.make_worktree(parent)
            try:
                assert isolated.worktree is not None
                (isolated.worktree / "app.py").write_text(
                    "key = 'sk-" + "A" * 40 + "'\n", encoding="utf-8"
                )
                receipt = code_task.audit_delivery_patch(
                    isolated.worktree, evidence_dir=parent / "evidence"
                )
                self.assertIn("api_key", {item["code"] for item in receipt["findings"]})
            finally:
                isolated.cleanup()

    # ------------------------------------------------------------------
    # or@958 / gt@961 -- reading a code evidence artifact
    # ------------------------------------------------------------------
    def test_a_symlinked_evidence_artifact_is_refused(self):
        """`or@958`: the ``path.is_symlink()`` half.

        Evidence must be a REGULAR file.  A symlink pointing at a
        regular file would satisfy ``is_file()``, so only the symlink
        check refuses it.  Under the mutant (``or`` -> ``and``) the
        symlink check would be skipped and the evidence would be read
        through the link.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = parent / "real.json"
            target.write_text(json.dumps({"schema": "x"}), encoding="utf-8")
            (parent / "manifest.json").symlink_to(target)
            with self.assertRaisesRegex(
                CodeTaskError, "code evidence is missing a regular manifest.json"
            ):
                code_task._read_evidence_json(parent, "manifest.json")

    def test_a_missing_evidence_artifact_is_refused(self):
        """`or@958`: the other half, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            with self.assertRaisesRegex(
                CodeTaskError, "code evidence is missing a regular manifest.json"
            ):
                code_task._read_evidence_json(parent, "manifest.json")

    def test_an_evidence_artifact_at_the_cap_is_accepted(self):
        """`gt@961`: the 4 MiB evidence cap boundary.

        An evidence file exactly at the cap is within it.  Under the
        mutant (``>`` -> ``>=``) it would be refused one byte early.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            cap = 4 * 1024 * 1024
            path = parent / "manifest.json"
            base = {"schema": "northstar.code-evidence.v1", "pad": ""}
            overhead = len(json.dumps(base).encode("utf-8"))
            base["pad"] = "p" * (cap - overhead)
            raw = json.dumps(base).encode("utf-8")
            self.assertEqual(len(raw), cap)
            path.write_bytes(raw)
            payload, _ = code_task._read_evidence_json(parent, "manifest.json")
            self.assertEqual(payload["schema"], "northstar.code-evidence.v1")

    def test_an_oversized_evidence_artifact_is_refused(self):
        """`gt@961`: the bound, from the other side."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            cap = 4 * 1024 * 1024
            path = parent / "manifest.json"
            base = {"schema": "northstar.code-evidence.v1", "pad": ""}
            overhead = len(json.dumps(base).encode("utf-8"))
            base["pad"] = "p" * (cap - overhead + 1)
            path.write_bytes(json.dumps(base).encode("utf-8"))
            with self.assertRaisesRegex(CodeTaskError, "exceeds 4 MiB"):
                code_task._read_evidence_json(parent, "manifest.json")

    # ------------------------------------------------------------------
    # or@990 -- the manifest/phase run id agreement
    # ------------------------------------------------------------------
    def test_an_empty_phase_run_id_is_an_integrity_error(self):
        """`or@990`: the ``not run_id`` half.

        A phase journal with NO run id cannot be matched to its
        manifest.  Under the mutant (``or`` -> ``and``) the empty id
        would only be compared against the manifest's id, and two empty
        ids would slip through as agreement.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(run_id="run-id-guard", evidence_dir=parent / "evidence")
            phases.start()
            journal = phases.as_dict()
            journal["run_id"] = ""
            (parent / "evidence" / "phases.json").write_text(json.dumps(journal), encoding="utf-8")
            (parent / "evidence" / "manifest.json").write_text(
                json.dumps({"schema": "northstar.code-evidence.v1", "run_id": ""}),
                encoding="utf-8",
            )
            receipt = code_task.reconcile_code_evidence(parent / "evidence")
            self.assertIn(
                "manifest and phase run ids do not match", receipt["integrity_errors"]
            )
            self.assertEqual(receipt["classification"], "invalid_evidence")

    def test_a_mismatched_phase_run_id_is_an_integrity_error(self):
        """`or@990`: the other half, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(run_id="run-id-guard-2", evidence_dir=parent / "evidence")
            phases.start()
            (parent / "evidence" / "manifest.json").write_text(
                json.dumps(
                    {"schema": "northstar.code-evidence.v1", "run_id": "a-different-run"}
                ),
                encoding="utf-8",
            )
            receipt = code_task.reconcile_code_evidence(parent / "evidence")
            self.assertIn(
                "manifest and phase run ids do not match", receipt["integrity_errors"]
            )

    # ------------------------------------------------------------------
    # eq@996 / eq@997 -- the phase seal verdict
    # ------------------------------------------------------------------
    def test_a_matching_phase_digest_is_a_valid_seal(self):
        """`eq@996`: the ``sealed_digest == actual_digest`` half.

        When the manifest's phase digest matches the journal on disk,
        the seal is valid and the evidence is not corrupt.  Under the
        mutant (``==`` -> ``!=``) the seal would be marked INVALID for
        a perfectly good journal.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(run_id="phase-seal-valid", evidence_dir=parent / "evidence")
            phases.start()
            raw = (parent / "evidence" / "phases.json").read_bytes()
            (parent / "evidence" / "manifest.json").write_text(
                json.dumps(
                    {
                        "schema": "northstar.code-evidence.v1",
                        "run_id": phases.run_id,
                        "phases_sha256": hashlib.sha256(raw).hexdigest(),
                    }
                ),
                encoding="utf-8",
            )
            receipt = code_task.reconcile_code_evidence(parent / "evidence")
            self.assertEqual(receipt["phase_seal"], "valid")
            self.assertNotIn(
                "phase journal digest does not match the manifest",
                receipt["integrity_errors"],
            )

    def test_a_mismatched_phase_digest_is_an_invalid_seal(self):
        """`eq@996` + `eq@997`: the other half, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(run_id="phase-seal-invalid", evidence_dir=parent / "evidence")
            phases.start()
            (parent / "evidence" / "manifest.json").write_text(
                json.dumps(
                    {
                        "schema": "northstar.code-evidence.v1",
                        "run_id": phases.run_id,
                        "phases_sha256": "0" * 64,
                    }
                ),
                encoding="utf-8",
            )
            receipt = code_task.reconcile_code_evidence(parent / "evidence")
            self.assertEqual(receipt["phase_seal"], "invalid")
            self.assertIn(
                "phase journal digest does not match the manifest",
                receipt["integrity_errors"],
            )
            self.assertEqual(receipt["classification"], "invalid_evidence")

    # ------------------------------------------------------------------
    # or@1006 -- the artifact path guard
    # ------------------------------------------------------------------
    def test_an_escaping_artifact_path_is_an_integrity_error(self):
        """`or@1006`: the path-shape checks.

        A manifest that names an artifact OUTSIDE the evidence directory
        (``../outside.json``) must be refused: the digest check would
        otherwise read a file the manifest does not own.  Under the
        mutant (``or`` -> ``and``) the path-shape check would be skipped
        for a well-typed artifact string.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(run_id="artifact-guard", evidence_dir=parent / "evidence")
            phases.start()
            outside = parent / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            (parent / "evidence" / "manifest.json").write_text(
                json.dumps(
                    {
                        "schema": "northstar.code-evidence.v1",
                        "run_id": phases.run_id,
                        "outside": "../outside.json",
                        "outside_sha256": hashlib.sha256(outside.read_bytes()).hexdigest(),
                    }
                ),
                encoding="utf-8",
            )
            receipt = code_task.reconcile_code_evidence(parent / "evidence")
            self.assertIn("outside artifact path is invalid", receipt["integrity_errors"])
            self.assertEqual(receipt["classification"], "invalid_evidence")

    def test_a_non_text_artifact_path_is_an_integrity_error(self):
        """`or@1006`: the type half, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(run_id="artifact-guard-2", evidence_dir=parent / "evidence")
            phases.start()
            (parent / "evidence" / "manifest.json").write_text(
                json.dumps(
                    {
                        "schema": "northstar.code-evidence.v1",
                        "run_id": phases.run_id,
                        "task": 42,
                        "task_sha256": "0" * 64,
                    }
                ),
                encoding="utf-8",
            )
            receipt = code_task.reconcile_code_evidence(parent / "evidence")
            self.assertIn("task artifact path is invalid", receipt["integrity_errors"])

    # ------------------------------------------------------------------
    # gt@1011 / or@1011 -- the sealed artifact guard
    # ------------------------------------------------------------------
    def test_a_sealed_artifact_at_the_size_cap_is_accepted(self):
        """`gt@1011`: the sealed artifact's size cap boundary.

        A sealed artifact exactly at the cap is within it.  Under the
        mutant (``>`` -> ``>=``) it would be refused one byte early.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(run_id="artifact-cap", evidence_dir=parent / "evidence")
            phases.start()
            artifact = parent / "evidence" / "task.json"
            payload = b'{"task": true}'
            artifact.write_bytes(payload)
            (parent / "evidence" / "manifest.json").write_text(
                json.dumps(
                    {
                        "schema": "northstar.code-evidence.v1",
                        "run_id": phases.run_id,
                        "task": "task.json",
                        "task_sha256": hashlib.sha256(payload).hexdigest(),
                    }
                ),
                encoding="utf-8",
            )
            with patch("code_task.MAX_GIT_OUTPUT_BYTES", len(payload)):
                receipt = code_task.reconcile_code_evidence(parent / "evidence")
            self.assertNotIn(
                "task artifact path is invalid", receipt["integrity_errors"]
            )
            self.assertFalse(
                any("task" in message for message in receipt["integrity_errors"]),
                receipt["integrity_errors"],
            )

    def test_an_oversized_sealed_artifact_is_an_integrity_error(self):
        """`gt@1011`: the bound, from the other side."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(run_id="artifact-oversize", evidence_dir=parent / "evidence")
            phases.start()
            payload = b'{"task": true}'
            (parent / "evidence" / "task.json").write_bytes(payload)
            (parent / "evidence" / "manifest.json").write_text(
                json.dumps(
                    {
                        "schema": "northstar.code-evidence.v1",
                        "run_id": phases.run_id,
                        "task": "task.json",
                        "task_sha256": hashlib.sha256(payload).hexdigest(),
                    }
                ),
                encoding="utf-8",
            )
            with patch("code_task.MAX_GIT_OUTPUT_BYTES", len(payload) - 1):
                receipt = code_task.reconcile_code_evidence(parent / "evidence")
            self.assertTrue(
                any("task" in message for message in receipt["integrity_errors"]),
                receipt["integrity_errors"],
            )

    def test_a_symlinked_sealed_artifact_is_an_integrity_error(self):
        """`or@1011`: the ``path.is_symlink()`` half."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(run_id="artifact-symlink", evidence_dir=parent / "evidence")
            phases.start()
            target = parent / "real.json"
            payload = b"{}"
            target.write_bytes(payload)
            (parent / "evidence" / "task.json").symlink_to(target)
            (parent / "evidence" / "manifest.json").write_text(
                json.dumps(
                    {
                        "schema": "northstar.code-evidence.v1",
                        "run_id": phases.run_id,
                        "task": "task.json",
                        "task_sha256": hashlib.sha256(payload).hexdigest(),
                    }
                ),
                encoding="utf-8",
            )
            receipt = code_task.reconcile_code_evidence(parent / "evidence")
            self.assertTrue(
                any("task" in message for message in receipt["integrity_errors"]),
                receipt["integrity_errors"],
            )
            self.assertEqual(receipt["classification"], "invalid_evidence")

    def test_a_missing_sealed_artifact_is_an_integrity_error(self):
        """`or@1011`: the other half, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(run_id="artifact-missing", evidence_dir=parent / "evidence")
            phases.start()
            (parent / "evidence" / "manifest.json").write_text(
                json.dumps(
                    {
                        "schema": "northstar.code-evidence.v1",
                        "run_id": phases.run_id,
                        "task": "task.json",
                        "task_sha256": "0" * 64,
                    }
                ),
                encoding="utf-8",
            )
            receipt = code_task.reconcile_code_evidence(parent / "evidence")
            self.assertTrue(
                any("task" in message for message in receipt["integrity_errors"]),
                receipt["integrity_errors"],
            )
            self.assertEqual(receipt["classification"], "invalid_evidence")

    # ------------------------------------------------------------------
    # or@1022 -- the unknown phase state
    # ------------------------------------------------------------------
    def test_an_unknown_phase_state_is_an_integrity_error(self):
        """`or@1022`: the ``state not in CODE_PHASE_TERMINALS`` half.

        A phase journal whose state is neither an active phase nor a
        terminal outcome is corrupt.  Under the mutant
        (``or`` -> ``and``) the terminal half would be consulted alone
        and the state would be accepted.
        """
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(run_id="unknown-state", evidence_dir=parent / "evidence")
            phases.start()
            journal = phases.as_dict()
            journal["state"] = "invented"
            journal["outcome"] = None
            (parent / "evidence" / "phases.json").write_text(json.dumps(journal), encoding="utf-8")
            (parent / "evidence" / "manifest.json").write_text(
                json.dumps({"schema": "northstar.code-evidence.v1", "run_id": phases.run_id}),
                encoding="utf-8",
            )
            receipt = code_task.reconcile_code_evidence(parent / "evidence")
            self.assertIn("unknown phase state: invented", receipt["integrity_errors"])
            self.assertEqual(receipt["classification"], "invalid_evidence")

    def test_a_terminal_phase_state_is_accepted(self):
        """`or@1022`: the other half, as the control."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            phases = CodePhaseMachine(run_id="terminal-state", evidence_dir=parent / "evidence")
            phases.start()
            phases.submit_plan({"files": ["app.py"], "steps": ["edit"]})
            phases.begin_execution(tool="Write", call_id="write-1")
            phases.complete_execution("effect-1", status="completed")
            phases.begin_verification()
            phases.finish("success")
            (parent / "evidence" / "manifest.json").write_text(
                json.dumps({"schema": "northstar.code-evidence.v1", "run_id": phases.run_id}),
                encoding="utf-8",
            )
            receipt = code_task.reconcile_code_evidence(parent / "evidence")
            self.assertNotIn(
                "unknown phase state: success", receipt["integrity_errors"]
            )

if __name__ == "__main__":
    unittest.main()
