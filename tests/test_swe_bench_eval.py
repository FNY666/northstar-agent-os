"""Contract tests for the SWE-bench evaluation adapter.

The adapter must not need the upstream package to be imported in order to
be inspected, and it must never turn a run that did not happen into a
verdict.  The upstream harness itself is exercised by running it; these
tests only guard the adapter's own contract.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "run_swe_bench_eval.py"


def _module():
    spec = importlib.util.spec_from_file_location("swe_eval", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["swe_eval"] = module
    spec.loader.exec_module(module)
    return module


def _task(instance_id: str) -> dict:
    return {
        "instance_id": instance_id,
        "repo": "x/y",
        "base_commit": "abc",
        "version": "1.0",
        "fail_to_pass": ["a::b"],
        "pass_to_pass": ["c::d"],
        "environment_image": "img:latest",
        "environment_digest": "sha256:" + "0" * 64,
        "image": "img:latest",
        "eval_type": "pytest",
        "log_parser": "pytest",
        "eval_script": "{}",
    }


def _install_stub_upstream(resolved: bool = True):
    """Put a stub ``swebench`` package in place of the real one."""
    import types

    saved = {name: sys.modules.get(name) for name in (
        "swebench", "swebench.harness", "swebench.harness.constants",
        "swebench.harness.grading", "swebench.harness.run_evaluation",
        "swebench.harness.utils", "docker",
    )}

    root = types.ModuleType("swebench")
    harness = types.ModuleType("swebench.harness")
    constants = types.ModuleType("swebench.harness.constants")
    grading = types.ModuleType("swebench.harness.grading")
    runner = types.ModuleType("swebench.harness.run_evaluation")
    utils = types.ModuleType("swebench.harness.utils")
    docker_mod = types.ModuleType("docker")

    constants.FAIL_TO_PASS = "FAIL_TO_PASS"
    constants.PASS_TO_PASS = "PASS_TO_PASS"
    grading.get_resolution_status = lambda report: (
        "RESOLVED_FULL" if resolved else "RESOLVED_NO"
    )
    runner.run_instance = lambda spec, pred, client, run_id, timeout=None: (
        pred["instance_id"],
        {pred["instance_id"]: {"tests_status": {}, "patch_successfully_applied": True}},
    )
    utils.make_test_spec = lambda instance: object()
    docker_mod.from_env = lambda: object()

    root.harness = harness
    harness.constants = constants
    harness.grading = grading
    harness.run_evaluation = runner
    harness.utils = utils
    sys.modules.update({
        "swebench": root,
        "swebench.harness": harness,
        "swebench.harness.constants": constants,
        "swebench.harness.grading": grading,
        "swebench.harness.run_evaluation": runner,
        "swebench.harness.utils": utils,
        "docker": docker_mod,
    })
    return saved


def _remove_stub_upstream(saved: dict) -> None:
    for name, module in saved.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module


class SweBenchEvalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = _module()

    def test_a_task_without_a_patch_is_never_counted_as_a_pass(self):
        # A stub upstream harness: the adapter must not reach it at all
        # when there is no patch, and must not report a pass.
        stub = _install_stub_upstream()
        try:
            sample = {"tasks": [_task("x__y-1")]}
            receipt = self.module.evaluate(
                sample, {}, run_id="t", timeout=1,
            )
        finally:
            _remove_stub_upstream(stub)
        self.assertEqual(receipt["summary"]["passed"], 0)
        self.assertEqual(receipt["tasks"][0]["outcome"], "no_patch_delivered")
        self.assertFalse(receipt["tasks"][0]["resolved"])
        self.assertEqual(
            receipt["summary"]["failure_kinds"], {"no_patch_delivered": 1}
        )

    def test_a_task_the_upstream_calls_fully_resolved_counts_as_a_pass(self):
        stub = _install_stub_upstream(resolved=True)
        try:
            sample = {"tasks": [_task("x__y-1")]}
            receipt = self.module.evaluate(
                sample, {"x__y-1": "diff --git a b\n"}, run_id="t", timeout=1,
            )
        finally:
            _remove_stub_upstream(stub)
        self.assertEqual(receipt["summary"]["passed"], 1)
        self.assertEqual(receipt["tasks"][0]["outcome"], "RESOLVED_FULL")

    def test_a_task_the_upstream_does_not_resolve_is_not_a_pass(self):
        stub = _install_stub_upstream(resolved=False)
        try:
            sample = {"tasks": [_task("x__y-1")]}
            receipt = self.module.evaluate(
                sample, {"x__y-1": "diff --git a b\n"}, run_id="t", timeout=1,
            )
        finally:
            _remove_stub_upstream(stub)
        self.assertEqual(receipt["summary"]["passed"], 0)
        self.assertEqual(receipt["tasks"][0]["outcome"], "RESOLVED_NO")

    def test_the_verdicts_are_the_upstream_verdicts(self):
        self.assertEqual(self.module.RESOLVED_FULL, "RESOLVED_FULL")
        self.assertEqual(self.module.RESOLVED_PARTIAL, "RESOLVED_PARTIAL")
        self.assertEqual(self.module.RESOLVED_NO, "RESOLVED_NO")

    def test_a_frozen_task_is_shaped_the_way_the_upstream_harness_needs_it(self):
        task = {
            "instance_id": "astropy__astropy-12907",
            "repo": "astropy/astropy",
            "base_commit": "abc",
            "version": "4.3",
            "fail_to_pass": ["a::b"],
            "pass_to_pass": ["c::d"],
            "image": "swebench/sweb.eval.x86_64.astropy_1776_astropy-12907:latest",
            "eval_type": "pytest",
            "log_parser": "pytest",
            "eval_script": '{"apply_patch": "x"}',
        }
        shaped = self.module._upstream_instance(task)
        self.assertEqual(shaped["FAIL_TO_PASS"], ["a::b"])
        self.assertEqual(shaped["PASS_TO_PASS"], ["c::d"])
        self.assertEqual(shaped["image"], task["image"])
        # The upstream dataset carries the eval script as a JSON string.
        self.assertIsInstance(shaped["eval_script"], dict)

    def test_an_eval_script_that_is_not_json_is_left_alone(self):
        self.assertEqual(self.module._as_object("not json"), "not json")
        self.assertEqual(self.module._as_object({"a": 1}), {"a": 1})

    def test_failure_kinds_count_only_the_tasks_that_were_not_solved(self):
        rows = [
            {"resolved": True, "outcome": "RESOLVED_FULL"},
            {"resolved": False, "outcome": "RESOLVED_NO"},
            {"resolved": False, "outcome": "RESOLVED_NO"},
            {"resolved": False, "outcome": "no_patch_delivered"},
        ]
        kinds = self.module._kinds(rows)
        self.assertEqual(kinds, {"RESOLVED_NO": 2, "no_patch_delivered": 1})
        self.assertNotIn("RESOLVED_FULL", kinds)

    def test_the_script_refuses_to_run_without_the_upstream_package(self):
        self.assertFalse(self.module._upstream_available())
        code = self.module.main(["--patches", "/nonexistent", "--output", "/tmp/x.json"])
        self.assertEqual(code, 2)


class FrozenSampleShapeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sample = json.loads(
            (ROOT / "benchmarks" / "swe-bench" / "verified-50.json").read_text(encoding="utf-8")
        )

    def test_every_task_carries_what_the_upstream_harness_needs(self):
        for task in self.sample["tasks"]:
            with self.subTest(task=task["instance_id"]):
                for field in (
                    "instance_id", "repo", "base_commit", "version",
                    "fail_to_pass", "pass_to_pass", "environment_image",
                    "environment_digest", "eval_type", "log_parser", "eval_script",
                ):
                    self.assertIn(field, task)
                    self.assertIsNotNone(task[field])

    def test_the_sample_is_still_fifty_tasks_over_many_repositories(self):
        self.assertEqual(len(self.sample["tasks"]), 50)
        self.assertGreaterEqual(len({t["repo"] for t in self.sample["tasks"]}), 10)

    def test_no_repository_dominates_the_sample(self):
        counts: dict[str, int] = {}
        for task in self.sample["tasks"]:
            counts[task["repo"]] = counts.get(task["repo"], 0) + 1
        self.assertLessEqual(max(counts.values()), 12)


if __name__ == "__main__":
    unittest.main()
