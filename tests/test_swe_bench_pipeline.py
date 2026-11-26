"""The solver and the evaluator must agree on the patch file.

The solver writes ``instance_id -> patch text``; the evaluator reads the
same shape.  If the two drift apart the evaluation silently measures
nothing, so the contract is checked here.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SOLVER = _load("solve_swe_bench", "scripts/solve_swe_bench.py")
EVALUATOR = _load("run_swe_bench_eval", "scripts/run_swe_bench_eval.py")


class PatchFileContractTests(unittest.TestCase):
    def test_the_solver_and_the_evaluator_use_the_same_instance_ids(self):
        sample = SOLVER.load_sample(ROOT / "benchmarks" / "swe-bench" / "verified-50.json")
        self.assertEqual(len(sample["tasks"]), 50)
        # The evaluator keys its patch lookup by instance id, so the ids in
        # the sample have to be the ids a patch file is keyed by.
        self.assertTrue(all("instance_id" in task for task in sample["tasks"]))

    def test_the_evaluator_accepts_the_shape_the_solver_writes(self):
        patches = {"astropy__astropy-12907": "diff --git a/x b/x\n"}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "patches.json"
            path.write_text(json.dumps(patches), encoding="utf-8")
            loaded = json.loads(path.read_text(encoding="utf-8"))
        self.assertIsInstance(loaded, dict)
        for key, value in loaded.items():
            self.assertIsInstance(key, str)
            self.assertIsInstance(value, str)

    def test_the_evaluator_refuses_to_run_without_the_upstream_harness(self):
        # Without the upstream harness there is no verdict to give, so the
        # evaluator must fail closed rather than report a pass rate it
        # cannot back up.
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "eval.json"
            (Path(temporary) / "sample.json").write_text(
                json.dumps({"tasks": []}), encoding="utf-8"
            )
            (Path(temporary) / "patches.json").write_text("{}", encoding="utf-8")
            if EVALUATOR._upstream_available():
                self.skipTest("the upstream harness is installed here")
            code = EVALUATOR.main([
                "--patches", str(Path(temporary) / "patches.json"),
                "--sample", str(Path(temporary) / "sample.json"),
                "--output", str(output),
            ])
            self.assertEqual(code, 2)
            self.assertFalse(output.exists())

    def test_a_missing_patch_is_reported_as_no_patch_delivered(self):
        # An instance without a patch must not be counted as a failure of
        # the model; it is a failure to deliver, and the receipt says so.
        if not EVALUATOR._upstream_available():
            self.skipTest("the upstream harness is not installed here")
        # The evaluator reshapes a frozen task for the upstream harness, so
        # the task has to be a real one with every field it reads.
        real = SOLVER.load_sample(ROOT / "benchmarks" / "swe-bench" / "verified-50.json")
        sample = {"tasks": [real["tasks"][0]]}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "eval.json"
            (Path(temporary) / "sample.json").write_text(
                json.dumps(sample), encoding="utf-8"
            )
            (Path(temporary) / "patches.json").write_text("{}", encoding="utf-8")
            code = EVALUATOR.main([
                "--patches", str(Path(temporary) / "patches.json"),
                "--sample", str(Path(temporary) / "sample.json"),
                "--output", str(output),
                "--task", real["tasks"][0]["instance_id"],
            ])
            self.assertEqual(code, 0)
            receipt = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(receipt["tasks"][0]["outcome"], "no_patch_delivered")
        self.assertFalse(receipt["tasks"][0]["resolved"])
        self.assertEqual(receipt["summary"]["passed"], 0)


class EvaluationTimeoutTests(unittest.TestCase):
    def test_a_timed_out_run_is_not_reported_as_an_error(self):
        # The upstream runner returns nothing when a run times out.  The
        # adapter must record a timeout, not blow up while unpacking, and
        # not turn the timeout into a verdict about the patch.
        if not EVALUATOR._upstream_available():
            self.skipTest("the upstream harness is not installed here")
        import swebench.harness.run_evaluation as upstream

        real = SOLVER.load_sample(ROOT / "benchmarks" / "swe-bench" / "verified-50.json")
        sample = {"tasks": [real["tasks"][0]]}
        original = upstream.run_instance
        upstream.run_instance = lambda *arguments, **keywords: None
        try:
            receipt = EVALUATOR.evaluate(
                sample,
                {real["tasks"][0]["instance_id"]: "diff --git a/x b/x\n"},
                run_id="timeout-test", timeout=1,
            )
        finally:
            upstream.run_instance = original
        row = receipt["tasks"][0]
        self.assertEqual(row["outcome"], "evaluation_timeout")
        self.assertFalse(row["resolved"])
        self.assertEqual(receipt["summary"]["passed"], 0)


class MissingTestResultsTests(unittest.TestCase):
    """The upstream runner reports no test results when it never ran them."""

    def _evaluate_with_entry(self, entry: dict) -> dict:
        if not EVALUATOR._upstream_available():
            self.skipTest("the upstream harness is not installed here")
        import swebench.harness.run_evaluation as upstream

        real = SOLVER.load_sample(ROOT / "benchmarks" / "swe-bench" / "verified-50.json")
        sample = {"tasks": [real["tasks"][0]]}
        instance_id = real["tasks"][0]["instance_id"]
        original = upstream.run_instance
        upstream.run_instance = lambda *arguments, **keywords: (None, {instance_id: entry})
        try:
            return EVALUATOR.evaluate(
                sample, {instance_id: "diff --git a/x b/x\n"},
                run_id="missing-tests", timeout=1,
            )
        finally:
            upstream.run_instance = original

    def test_a_patch_that_does_not_apply_is_reported_as_such(self):
        receipt = self._evaluate_with_entry({
            "patch_exists": True,
            "patch_is_None": False,
            "patch_successfully_applied": False,
            "infra_failure": False,
            "resolved": False,
        })
        row = receipt["tasks"][0]
        self.assertEqual(row["outcome"], "patch_not_applied")
        self.assertFalse(row["resolved"])
        self.assertEqual(receipt["summary"]["passed"], 0)

    def test_a_run_without_test_results_is_not_reported_as_a_verdict(self):
        receipt = self._evaluate_with_entry({
            "patch_exists": True,
            "patch_is_None": False,
            "patch_successfully_applied": True,
            "infra_failure": True,
            "resolved": False,
        })
        row = receipt["tasks"][0]
        self.assertEqual(row["outcome"], "no_test_results")
        self.assertFalse(row["resolved"])
        self.assertTrue(row["infra_failure"])


if __name__ == "__main__":
    unittest.main()
