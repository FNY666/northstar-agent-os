"""Black-box tests for the dependency-free code-run evidence hard gates."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "components" / "northstar-agent-runtime"
SCRIPT = ROOT / "scripts" / "check-code-run-evidence.py"
SPEC = importlib.util.spec_from_file_location("code_evidence_gates", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError(f"cannot import {SCRIPT}")
GATES = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATES
SPEC.loader.exec_module(GATES)


def git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *arguments], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def reseal(run: Path, key: str, filename: str) -> None:
    manifest = read_json(run / "manifest.json")
    manifest[f"{key}_sha256"] = hashlib.sha256((run / filename).read_bytes()).hexdigest()
    write_json(run / "manifest.json", manifest)


class CodeEvidenceGateTests(unittest.TestCase):
    """One valid host-produced fixture; every tamper test starts from a copy."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.parent = Path(cls.temporary.name)
        cls.repository = cls.parent / "repo"
        cls.repository.mkdir()
        git(cls.repository, "init")
        git(cls.repository, "config", "user.email", "northstar-tests@example.invalid")
        git(cls.repository, "config", "user.name", "Northstar Tests")
        (cls.repository / "value.txt").write_text("old\n", encoding="utf-8")
        git(cls.repository, "add", "value.txt")
        git(cls.repository, "commit", "-m", "initial")
        sys.path.insert(0, str(RUNTIME))
        from cli import main  # Imported only to create a genuine CLI evidence fixture.

        cls.cli_main = staticmethod(main)
        cls.good = cls._run_code(
            "verified", checks=("read line < value.txt; test \"$line\" = new",), write=True
        )
        cls.failed = cls._run_code("failed", checks=("false",), write=False)
        cls.unverified = cls._run_code("unverified", checks=(), write=False)
        cls.plan_only = cls._run_code("plan-only", checks=(), write=False, plan_only=True)
        cls.counter = 0

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            sys.path.remove(str(RUNTIME))
        except ValueError:
            pass
        cls.temporary.cleanup()

    @classmethod
    def _run_code(cls, name: str, *, checks: tuple[str, ...], write: bool, plan_only: bool = False) -> Path:
        turns = [
            {"tool": {"name": "SubmitPlan", "input": {
                "summary": "make the requested minimal change",
                "files": ["value.txt"], "steps": ["inspect", "change"],
                "risks": ["preserve newline"], "check_indices": list(range(len(checks))),
            }}},
        ]
        if write:
            turns.append({"tool": {"name": "Write", "input": {"path": "value.txt", "content": "new\n"}}})
        turns.append({"text": "done"})
        script = cls.parent / f"{name}.json"
        write_json(script, turns)
        evidence = cls.parent / f"{name}-evidence"
        args = [
            "code", "perform a fixture change", "--workspace", str(cls.repository),
            # Intentional test-only process backend: it is not OS isolation.
            "--sandbox", "process", "--seccomp", "off", "--capdrop", "off", "--landlock", "off",
            "--no-policy-file", "--no-workspace-agents", "--no-skills", "--no-memory", "--no-plugins",
            "--script", str(script), "--evidence-dir", str(evidence),
        ]
        if plan_only:
            args.append("--plan-only")
        for check in checks:
            args.extend(("--check", check))
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cls.cli_main(args)
        expected = 6 if checks == ("false",) else 0
        if code != expected:  # pragma: no cover - fixture setup diagnosis
            raise RuntimeError(f"code fixture {name} exited {code}: {stderr.getvalue()} {stdout.getvalue()}")
        return next(evidence.iterdir())

    def fresh(self, source: Path | None = None) -> Path:
        type(self).counter += 1
        target = self.parent / f"copy-{self.counter}"
        shutil.copytree(source or self.good, target, symlinks=True)
        return target

    def check_cli(self, run: Path, *arguments: str) -> tuple[int, dict[str, object]]:
        process = subprocess.run(
            [sys.executable, str(SCRIPT), "--json", *arguments, str(run)],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(process.stderr, "", process.stderr)
        return process.returncode, json.loads(process.stdout)

    def test_01_genuine_scripted_cli_success_is_verified(self):
        report = GATES.inspect(self.good)
        self.assertEqual(report["classification"], "verified_success")
        self.assertTrue(report["verified_success"])
        self.assertTrue(report["layers"]["evidence_integrity"]["passed"])
        self.assertTrue(report["layers"]["trajectory"]["passed"])
        code, from_cli = self.check_cli(self.good)
        self.assertEqual(code, 0)
        self.assertTrue(from_cli["read_only"])

    def test_02_missing_patch_digest_fails_closed(self):
        run = self.fresh()
        manifest = read_json(run / "manifest.json")
        manifest.pop("patch_sha256")
        write_json(run / "manifest.json", manifest)
        code, report = self.check_cli(run)
        self.assertEqual(code, 2)
        self.assertFalse(report["layers"]["evidence_integrity"]["passed"])

    def test_03_phase_effect_cannot_precede_submit_plan(self):
        run = self.fresh()
        phases = read_json(run / "phases.json")
        planned_time = phases["transitions"][1]["timestamp_unix_ms"]
        phases["effects"][0]["started_unix_ms"] = planned_time - 1
        write_json(run / "phases.json", phases)
        reseal(run, "phases", "phases.json")
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["trajectory"]["passed"])
        self.assertIn("not after SubmitPlan", " ".join(report["layers"]["trajectory"]["reasons"]))

    def test_04_effect_completion_timestamp_must_not_run_backwards(self):
        run = self.fresh()
        phases = read_json(run / "phases.json")
        phases["effects"][0]["finished_unix_ms"] = phases["effects"][0]["started_unix_ms"] - 1
        write_json(run / "phases.json", phases)
        reseal(run, "phases", "phases.json")
        self.assertFalse(GATES.inspect(run)["layers"]["trajectory"]["passed"])

    def test_05_host_check_must_correspond_to_independent_receipt(self):
        run = self.fresh()
        phases = read_json(run / "phases.json")
        phases["effects"][-1]["tool"] = "Write"
        write_json(run / "phases.json", phases)
        reseal(run, "phases", "phases.json")
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["trajectory"]["passed"])
        self.assertIn("HostCheck", " ".join(report["layers"]["trajectory"]["reasons"]))

    def test_06_check_nonzero_cannot_claim_success(self):
        run = self.fresh()
        verification = read_json(run / "verification.json")
        result = verification["summaries"][0]["results"][0]
        result["exit_code"] = 1
        # Keeping ok true demonstrates that neither a summary nor its boolean is trusted.
        write_json(run / "verification.json", verification)
        reseal(run, "verification", "verification.json")
        report = GATES.inspect(run)
        self.assertFalse(report["verified_success"])
        self.assertFalse(report["layers"]["trajectory"]["passed"])

    def test_07_delivery_seal_patch_mismatch_blocks_verified_success(self):
        run = self.fresh()
        seal = read_json(run / "delivery-seal.json")
        seal["patch_sha256"] = "0" * 64
        write_json(run / "delivery-seal.json", seal)
        reseal(run, "delivery_seal", "delivery-seal.json")
        code, report = self.check_cli(run)
        self.assertEqual(code, 2)
        self.assertFalse(report["verified_success"])
        self.assertIn("delivery seal", " ".join(report["layers"]["verified_completion"]["reasons"]))

    def test_08_summary_only_fabricated_success_is_rejected(self):
        run = self.fresh()
        phases = read_json(run / "phases.json")
        phases["effects"] = []
        write_json(run / "phases.json", phases)
        reseal(run, "phases", "phases.json")
        report = GATES.inspect(run)
        self.assertFalse(report["verified_success"])
        self.assertFalse(report["layers"]["trajectory"]["passed"])

    def test_09_wrong_terminal_outcome_is_rejected(self):
        run = self.fresh()
        phases = read_json(run / "phases.json")
        phases["state"] = "error_postconditions_failed"
        phases["outcome"] = "error_postconditions_failed"
        phases["transitions"][-1]["to"] = "error_postconditions_failed"
        write_json(run / "phases.json", phases)
        reseal(run, "phases", "phases.json")
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["trajectory"]["passed"])
        self.assertFalse(report["verified_success"])

    def test_10_symlinked_artifact_is_rejected(self):
        run = self.fresh()
        outside = self.parent / "outside-task.json"
        outside.write_text("{}", encoding="utf-8")
        (run / "task.json").unlink()
        (run / "task.json").symlink_to(outside)
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["evidence_integrity"]["passed"])
        self.assertIn("symlink", " ".join(report["layers"]["evidence_integrity"]["reasons"]))

    def test_11_oversized_patch_is_rejected(self):
        run = self.fresh()
        (run / "changes.patch").write_bytes(b"x" * (8 * 1024 * 1024 + 1))
        manifest = read_json(run / "manifest.json")
        manifest["patch_sha256"] = hashlib.sha256((run / "changes.patch").read_bytes()).hexdigest()
        manifest["patch_bytes"] = (run / "changes.patch").stat().st_size
        write_json(run / "manifest.json", manifest)
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["evidence_integrity"]["passed"])

    def test_12_duplicate_json_keys_are_rejected(self):
        run = self.fresh()
        (run / "manifest.json").write_text('{"schema":"northstar.code-evidence.v1","schema":"evil"}', encoding="utf-8")
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["evidence_integrity"]["passed"])

    def test_13_nonfinite_json_number_is_rejected(self):
        run = self.fresh()
        raw = (run / "phases.json").read_text(encoding="utf-8").replace('"timestamp_unix_ms": ', '"timestamp_unix_ms": NaN, "ignored": ', 1)
        (run / "phases.json").write_text(raw, encoding="utf-8")
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["evidence_integrity"]["passed"])

    def test_14_malformed_task_type_is_rejected(self):
        run = self.fresh()
        task = read_json(run / "task.json")
        task["plan_only"] = "false"
        write_json(run / "task.json", task)
        reseal(run, "task", "task.json")
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["evidence_integrity"]["passed"])

    def test_15_manifest_path_traversal_is_rejected(self):
        run = self.fresh()
        manifest = read_json(run / "manifest.json")
        manifest["task"] = "../task.json"
        write_json(run / "manifest.json", manifest)
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["evidence_integrity"]["passed"])

    def test_16_genuine_failed_run_is_valid_but_never_verified_success(self):
        report = GATES.inspect(self.failed)
        self.assertEqual(report["classification"], "valid_non_success_terminal")
        self.assertTrue(report["layers"]["evidence_integrity"]["passed"])
        self.assertTrue(report["layers"]["trajectory"]["passed"])
        self.assertFalse(report["verified_success"])
        code, _ = self.check_cli(self.failed)
        self.assertEqual(code, 0)

    def test_17_unverified_success_can_be_complete_but_require_verified_fails(self):
        report = GATES.inspect(self.unverified)
        self.assertEqual(report["classification"], "complete_unverified_success")
        self.assertTrue(report["complete_evidence"])
        self.assertFalse(report["verified_success"])
        default_code, _ = self.check_cli(self.unverified)
        strict_code, _ = self.check_cli(self.unverified, "--require-verified")
        self.assertEqual(default_code, 0)
        self.assertEqual(strict_code, 2)

    def test_18_checker_is_read_only_for_evidence(self):
        run = self.fresh()
        before = {
            path.relative_to(run).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in run.rglob("*") if path.is_file() and not path.is_symlink()
        }
        code, report = self.check_cli(run)
        after = {
            path.relative_to(run).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in run.rglob("*") if path.is_file() and not path.is_symlink()
        }
        self.assertEqual(code, 0)
        self.assertTrue(report["read_only"])
        self.assertEqual(before, after)

    def test_19_valid_plan_only_terminal_is_accepted_but_never_verified(self):
        report = GATES.inspect(self.plan_only)
        self.assertEqual(report["classification"], "valid_plan_only_terminal")
        self.assertTrue(report["plan_only"])
        self.assertFalse(report["verified_success"])
        default_code, _ = self.check_cli(self.plan_only)
        strict_code, _ = self.check_cli(self.plan_only, "--require-verified")
        self.assertEqual(default_code, 0)
        self.assertEqual(strict_code, 2)

    def test_20_manifest_list_status_fails_closed_without_crashing(self):
        run = self.fresh()
        manifest = read_json(run / "manifest.json")
        manifest["status"] = ["success"]
        write_json(run / "manifest.json", manifest)
        code, report = self.check_cli(run)
        self.assertEqual(code, 2)
        self.assertFalse(report["layers"]["evidence_integrity"]["passed"])

    def test_21_phase_dict_state_fails_closed_without_crashing(self):
        run = self.fresh()
        phases = read_json(run / "phases.json")
        phases["state"] = {"success": True}
        write_json(run / "phases.json", phases)
        reseal(run, "phases", "phases.json")
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["trajectory"]["passed"])

    def test_22_transition_list_target_fails_closed_without_crashing(self):
        run = self.fresh()
        phases = read_json(run / "phases.json")
        phases["transitions"][-1]["to"] = ["success"]
        write_json(run / "phases.json", phases)
        reseal(run, "phases", "phases.json")
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["trajectory"]["passed"])

    def test_23_effect_dict_status_fails_closed_without_crashing(self):
        run = self.fresh()
        phases = read_json(run / "phases.json")
        phases["effects"][0]["status"] = {"completed": True}
        write_json(run / "phases.json", phases)
        reseal(run, "phases", "phases.json")
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["trajectory"]["passed"])

    def test_24_effect_list_id_fails_closed_without_crashing(self):
        run = self.fresh()
        phases = read_json(run / "phases.json")
        phases["effects"][0]["effect_id"] = ["effect-1"]
        write_json(run / "phases.json", phases)
        reseal(run, "phases", "phases.json")
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["trajectory"]["passed"])

    def test_25_plan_check_indices_containers_fail_closed_without_crashing(self):
        run = self.fresh()
        phases = read_json(run / "phases.json")
        phases["plan"]["check_indices"] = [[0], {"index": 0}]
        write_json(run / "phases.json", phases)
        reseal(run, "phases", "phases.json")
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["trajectory"]["passed"])

    def test_26_deep_json_fails_closed_without_recursion_error(self):
        run = self.fresh()
        nested = "0"
        for _ in range(GATES.MAX_JSON_DEPTH + 2):
            nested = '{"nested":' + nested + "}"
        (run / "task.json").write_text(nested, encoding="utf-8")
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["evidence_integrity"]["passed"])
        self.assertIn("nesting depth", " ".join(report["layers"]["evidence_integrity"]["reasons"]))

    def test_27_too_many_json_nodes_fails_closed(self):
        run = self.fresh()
        values = ",".join("0" for _ in range(GATES.MAX_JSON_NODES + 1))
        (run / "task.json").write_text('{"many":[' + values + "]}", encoding="utf-8")
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["evidence_integrity"]["passed"])
        self.assertIn("nodes", " ".join(report["layers"]["evidence_integrity"]["reasons"]))

    def test_28_effect_completion_after_terminal_is_rejected(self):
        run = self.fresh()
        phases = read_json(run / "phases.json")
        terminal_time = phases["transitions"][-1]["timestamp_unix_ms"]
        phases["effects"][-1]["finished_unix_ms"] = terminal_time + 1
        write_json(run / "phases.json", phases)
        reseal(run, "phases", "phases.json")
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["trajectory"]["passed"])
        self.assertIn("after the terminal", " ".join(report["layers"]["trajectory"]["reasons"]))

    def test_29_executing_effect_must_start_in_executing_interval(self):
        run = self.fresh()
        phases = read_json(run / "phases.json")
        verifying_time = next(
            item["timestamp_unix_ms"] for item in phases["transitions"] if item["to"] == "verifying"
        )
        phases["effects"][0]["started_unix_ms"] = verifying_time + 1
        phases["effects"][0]["finished_unix_ms"] = verifying_time + 1
        write_json(run / "phases.json", phases)
        reseal(run, "phases", "phases.json")
        report = GATES.inspect(run)
        self.assertFalse(report["layers"]["trajectory"]["passed"])
        self.assertIn("executing phase interval", " ".join(report["layers"]["trajectory"]["reasons"]))

    def test_30_success_with_in_flight_effect_is_invalid(self):
        run = self.fresh()
        phases = read_json(run / "phases.json")
        phases["effects"][0]["status"] = "in_flight"
        phases["effects"][0]["finished_unix_ms"] = None
        write_json(run / "phases.json", phases)
        reseal(run, "phases", "phases.json")
        report = GATES.inspect(run)
        self.assertEqual(report["classification"], "invalid_or_incomplete_evidence")
        self.assertIn("in_flight", " ".join(report["layers"]["trajectory"]["reasons"]))

    def test_31_success_with_unknown_effect_is_invalid(self):
        run = self.fresh()
        phases = read_json(run / "phases.json")
        phases["effects"][0]["status"] = "unknown"
        write_json(run / "phases.json", phases)
        reseal(run, "phases", "phases.json")
        report = GATES.inspect(run)
        self.assertEqual(report["classification"], "invalid_or_incomplete_evidence")
        self.assertIn("unknown", " ".join(report["layers"]["trajectory"]["reasons"]))

    def test_32_success_with_failed_effect_is_invalid_but_denied_is_allowed(self):
        failed = self.fresh()
        phases = read_json(failed / "phases.json")
        phases["effects"][0]["status"] = "failed"
        write_json(failed / "phases.json", phases)
        reseal(failed, "phases", "phases.json")
        report = GATES.inspect(failed)
        self.assertEqual(report["classification"], "invalid_or_incomplete_evidence")
        denied = self.fresh()
        phases = read_json(denied / "phases.json")
        phases["effects"][0]["status"] = "denied"
        write_json(denied / "phases.json", phases)
        reseal(denied, "phases", "phases.json")
        self.assertTrue(GATES.inspect(denied)["verified_success"])

    def test_33_success_with_failed_completion_is_not_non_success_terminal(self):
        run = self.fresh()
        seal = read_json(run / "delivery-seal.json")
        seal["patch_sha256"] = "0" * 64
        write_json(run / "delivery-seal.json", seal)
        reseal(run, "delivery_seal", "delivery-seal.json")
        report = GATES.inspect(run)
        self.assertTrue(report["layers"]["evidence_integrity"]["passed"])
        self.assertTrue(report["layers"]["trajectory"]["passed"])
        self.assertEqual(report["classification"], "invalid_or_incomplete_evidence")


if __name__ == "__main__":
    unittest.main()
