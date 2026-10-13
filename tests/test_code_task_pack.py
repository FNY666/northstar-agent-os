"""Contract tests for the frozen 24-task offline coding benchmark."""
from __future__ import annotations

import importlib.util
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-code-task-pack.py"
MANIFEST = ROOT / "benchmarks" / "code-tasks" / "v1" / "manifest.json"
SPEC = importlib.util.spec_from_file_location("validate_code_task_pack", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError(f"cannot load {SCRIPT}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
RUNNER_SCRIPT = ROOT / "scripts" / "run-code-task-pack.py"
RUNNER_SPEC = importlib.util.spec_from_file_location("run_code_task_pack", RUNNER_SCRIPT)
if RUNNER_SPEC is None or RUNNER_SPEC.loader is None:  # pragma: no cover
    raise RuntimeError(f"cannot load {RUNNER_SCRIPT}")
RUNNER = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(RUNNER)
CONTROLS_SCRIPT = ROOT / "scripts" / "check-code-task-pack.py"
CONTROLS_SPEC = importlib.util.spec_from_file_location("check_code_task_pack", CONTROLS_SCRIPT)
if CONTROLS_SPEC is None or CONTROLS_SPEC.loader is None:
    raise RuntimeError(f"cannot load {CONTROLS_SCRIPT}")
CONTROLS = importlib.util.module_from_spec(CONTROLS_SPEC)
CONTROLS_SPEC.loader.exec_module(CONTROLS)


class CodeTaskPackTests(unittest.TestCase):
    def test_frozen_manifest_has_exact_allocation(self):
        payload = MODULE.load_manifest(MANIFEST)
        self.assertEqual(MODULE.validate(payload), [])
        result = MODULE.summary(payload)
        self.assertEqual(result["tasks"], 24)
        self.assertEqual(result["languages"], {"python": 12, "typescript": 12})
        self.assertEqual(
            result["categories"],
            {"bugfix": 8, "feature": 6, "refactor": 4, "build_test": 3, "security": 3},
        )
        self.assertEqual(result["fixture_status"], {"materialized": 24})

    def test_recorded_fixture_controls_match_the_frozen_pack_and_references(self):
        payload = MODULE.load_manifest(MANIFEST)
        summary = json.loads((MANIFEST.parent / "controls-baseline.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["manifest_sha256"], MODULE.fingerprint(payload))
        self.assertEqual(summary["measurement"], "fixture_reference_controls")
        self.assertFalse(summary["real_model_evaluated"])
        self.assertFalse(summary["release_eligible"])
        self.assertEqual((summary["checked"], summary["passed"], summary["failed"]), (24, 24, 0))
        recorded = {row["task_id"]: row for row in summary["tasks"]}
        self.assertEqual(len(summary["tasks"]), 24)
        self.assertEqual(set(recorded), {task["id"] for task in payload["tasks"]})
        for task in payload["tasks"]:
            row = recorded[task["id"]]
            self.assertTrue(row["baseline_rejected"])
            self.assertTrue(row["reference_passed"])
            self.assertEqual(row["fixture_sha256"], task["fixture_sha256"])
            self.assertEqual(row["evaluator_sha256"], task["evaluator_sha256"])
            reference = MANIFEST.parent / "references" / f"{Path(task['evaluator_suite']).name}.json"
            self.assertEqual(row["reference_sha256"], hashlib.sha256(reference.read_bytes()).hexdigest())

    def test_control_summary_refuses_incomplete_or_unsupported_success(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            CONTROLS.summarize_controls({"complete": False, "ok": False, "failed": 0})
        with self.assertRaisesRegex(ValueError, "do not support"):
            CONTROLS.summarize_controls({"complete": True, "ok": True, "failed": 0, "declared": 24, "checked": 24, "passed": 24, "tasks": []})

    def test_flaky_test_fixture_rejects_unconditional_replacement_assertions(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "flaky"
            RUNNER.prepare("py-build-002-flaky-clock-test", candidate)
            (candidate / "tests/test_countdown.py").write_text(
                "import unittest\n"
                "class FakeTests(unittest.TestCase):\n"
                "    def test_a(self): self.assertTrue(True)\n"
                "    def test_b(self): self.assertTrue(True)\n"
                "    def test_c(self): self.assertTrue(True)\n",
                encoding="utf-8",
            )
            receipt = RUNNER.evaluate("py-build-002-flaky-clock-test", candidate)
            self.assertEqual(receipt["public"][0]["exit_code"], 0)
            self.assertFalse(receipt["ok"])
            self.assertEqual(receipt["hidden"]["exit_code"], 1)

    def test_agent_projection_cannot_expose_evaluator_routing(self):
        payload = MODULE.load_manifest(MANIFEST)
        projected = MODULE.agent_view(payload, "py-sec-001-archive-path")
        self.assertEqual(set(projected), set(MODULE.PUBLIC_FIELDS))
        self.assertNotIn("evaluator_suite", projected)
        self.assertNotIn("fixture_status", projected)

        runnable = MODULE.agent_view(payload, "py-bug-001-bounded-retry")
        self.assertEqual(set(runnable), set(MODULE.PUBLIC_FIELDS))
        self.assertNotIn("evaluator_suite", runnable)

    def test_validator_rejects_quota_drift(self):
        payload = MODULE.load_manifest(MANIFEST)
        payload["tasks"][0]["language"] = "typescript"
        errors = MODULE.validate(payload)
        self.assertTrue(any("language allocation" in error for error in errors))

    def test_materialized_fixtures_are_discriminating_and_hide_evaluator(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            python_candidate = parent / "python"
            public = RUNNER.prepare("py-bug-001-bounded-retry", python_candidate)
            self.assertNotIn("evaluator_suite", public)
            self.assertFalse((python_candidate / RUNNER.EVALUATOR_DIR).exists())
            self.assertFalse(RUNNER.evaluate("py-bug-001-bounded-retry", python_candidate)["ok"])

            source = (python_candidate / "retry.py").read_text(encoding="utf-8")
            source = source.replace(
                "    last_error: Exception | None = None\n    for _ in range(max_attempts + 1):",
                "    if max_attempts <= 0:\n"
                "        raise ValueError('max_attempts must be positive')\n"
                "    last_error: Exception | None = None\n"
                "    for _ in range(max_attempts):",
            )
            (python_candidate / "retry.py").write_text(source, encoding="utf-8")
            self.assertTrue(RUNNER.evaluate("py-bug-001-bounded-retry", python_candidate)["ok"])

    def test_typescript_fixture_has_a_passing_repair(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "typescript"
            RUNNER.prepare("ts-bug-002-zero-timeout", candidate)
            self.assertFalse(RUNNER.evaluate("ts-bug-002-zero-timeout", candidate)["ok"])
            source = (candidate / "options.ts").read_text(encoding="utf-8")
            source = source.replace(
                "  return {timeoutMs: input.timeoutMs || 5_000};",
                "  const timeoutMs = input.timeoutMs ?? 5_000;\n"
                "  if (timeoutMs < 0) throw new RangeError('timeoutMs must be non-negative');\n"
                "  return {timeoutMs};",
            )
            (candidate / "options.ts").write_text(source, encoding="utf-8")
            self.assertTrue(RUNNER.evaluate("ts-bug-002-zero-timeout", candidate)["ok"])

    def test_prepared_git_fixture_is_reproducible_and_patch_replays_cleanly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commits = []
            for name in ("first", "second"):
                target = root / name
                RUNNER.prepare("py-bug-001-bounded-retry", target, git_repository=True)
                commits.append(RUNNER._git(target, "rev-parse", "HEAD").stdout)
            self.assertEqual(commits[0], commits[1])
            candidate = root / "first"
            source = (candidate / "retry.py").read_text(encoding="utf-8")
            source = source.replace(
                "    for _ in range(max_attempts + 1):",
                "    if max_attempts <= 0:\n"
                "        raise ValueError('max_attempts must be positive')\n"
                "    for _ in range(max_attempts):",
            )
            (candidate / "retry.py").write_text(source, encoding="utf-8")
            delivery = RUNNER._git(candidate, "diff", "--binary", "HEAD").stdout
            receipt = RUNNER.evaluate_patch("py-bug-001-bounded-retry", delivery)
            self.assertTrue(receipt["ok"])
            self.assertEqual(receipt["evaluation_mode"], "patch_replay")
            self.assertEqual(receipt["changed_files"], ["retry.py"])
            self.assertEqual(receipt["start_commit"], commits[0].decode().strip())
            self.assertFalse(receipt["release_eligible"])

    def test_patch_evaluator_rejects_reserved_paths_and_candidate_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate"
            RUNNER.prepare("py-bug-001-bounded-retry", candidate, git_repository=True)
            (candidate / "NORTHSTAR_TASK.json").write_text("{}\n", encoding="utf-8")
            delivery = RUNNER._git(candidate, "diff", "--binary", "HEAD").stdout
            with self.assertRaisesRegex(ValueError, "reserved"):
                RUNNER.evaluate_patch("py-bug-001-bounded-retry", delivery)
            secret = root / "outside.txt"
            secret.write_text("private", encoding="utf-8")
            (candidate / "link.txt").symlink_to(secret)
            with self.assertRaisesRegex(ValueError, "special file"):
                RUNNER.evaluate("py-bug-001-bounded-retry", candidate)

    def test_check_runner_bounds_output_and_returns_timeout_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            timeout = RUNNER._run([sys.executable, "-c", "import time; time.sleep(10)"], root, 0.1)
            self.assertEqual(timeout["exit_code"], 124)
            self.assertTrue(timeout["timed_out"])
            output = RUNNER._run([sys.executable, "-c", "print('x' * 2097152)"], root, 10)
            self.assertEqual(output["exit_code"], 125)
            self.assertTrue(output["output_limited"])
            self.assertLessEqual(len(output["output"]), RUNNER.RETAINED_OUTPUT_BYTES)

    def test_check_runner_does_not_inherit_credentials_or_runtime_injection(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"NORTHSTAR_TEST_SECRET": "secret", "NODE_OPTIONS": "injection"}):
                receipt = RUNNER._run(
                    [sys.executable, "-c", "import os,json; print(json.dumps([os.getenv('NORTHSTAR_TEST_SECRET'), os.getenv('NODE_OPTIONS')]))"],
                    Path(directory), 10,
                )
            self.assertEqual(receipt["exit_code"], 0)
            self.assertEqual(json.loads(receipt["output"]), [None, None])

    def test_malformed_manifest_fields_fail_validation_without_type_errors(self):
        payload = MODULE.load_manifest(MANIFEST)
        payload["tasks"][0]["language"] = []
        payload["tasks"][0]["category"] = {}
        payload["defaults"]["wall_time_seconds"] = False
        errors = MODULE.validate(payload)
        self.assertTrue(any("language is invalid" in error for error in errors))
        self.assertTrue(any("category is invalid" in error for error in errors))
        self.assertTrue(any("wall_time_seconds" in error for error in errors))

    def test_northstar_delivered_patch_passes_clean_fixture_evaluation(self):
        runtime_root = ROOT / "components" / "northstar-agent-runtime"
        sys.path.insert(0, str(runtime_root))
        try:
            from sdk import CodeTask, RunOptions, reconcile_code_run, run_code

            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                workspace = root / "fixture"
                public = RUNNER.prepare("py-bug-001-bounded-retry", workspace, git_repository=True)
                original = (workspace / "retry.py").read_text(encoding="utf-8")
                repair = original.replace(
                    "    for _ in range(max_attempts + 1):",
                    "    if max_attempts <= 0:\n"
                    "        raise ValueError('max_attempts must be positive')\n"
                    "    for _ in range(max_attempts):",
                )
                report = run_code(
                    CodeTask(
                        goal=public["prompt"], workspace=str(workspace),
                        checks=("python3 -m unittest discover -s tests -v",),
                    ),
                    options=RunOptions(scripted_turns=[
                        {"tool": {"name": "SubmitPlan", "input": {
                            "summary": "bound retries and reject non-positive limits",
                            "files": ["retry.py"], "steps": ["validate limit", "bound attempts"],
                            "risks": ["preserve the final exception object"], "check_indices": [0],
                        }}},
                        {"tool": {"name": "Write", "input": {"path": "retry.py", "content": repair}}},
                        {"text": "retry helper repaired"},
                    ]),
                    evidence_dir=str(root / "evidence"),
                )
                self.assertTrue(report.ok)
                self.assertEqual((workspace / "retry.py").read_text(encoding="utf-8"), original)
                evaluation = RUNNER.evaluate_patch("py-bug-001-bounded-retry", Path(report.patch_path).read_bytes())
                self.assertTrue(evaluation["ok"])
                self.assertEqual(evaluation["start_commit"], report.start_commit)
                self.assertEqual(reconcile_code_run(report.evidence_dir)["classification"], "terminal")
        finally:
            sys.path.pop(0)


if __name__ == "__main__":
    unittest.main()
