"""Tests for the SWE-bench solver.

The solver's job is narrow and its parts are checkable without a model:
read the frozen sample, find an instance's environment image, fetch the
upstream problem statement, and read the patch a run delivered.  The model
call and the container evaluation are checked by running them for real.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOLVER = ROOT / "scripts" / "solve_swe_bench.py"

SPEC = importlib.util.spec_from_file_location("solve_swe_bench", SOLVER)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError(f"cannot load {SOLVER}")
SOLVER_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOLVER_MODULE)


class SolverSampleTests(unittest.TestCase):
    def test_the_frozen_sample_loads_and_has_the_expected_shape(self):
        sample = SOLVER_MODULE.load_sample(ROOT / "benchmarks" / "swe-bench" / "verified-50.json")
        self.assertEqual(len(sample["tasks"]), 50)
        for task in sample["tasks"][:5]:
            self.assertIn("instance_id", task)
            self.assertIn("environment_image", task)
            self.assertIn("base_commit", task)

    def test_every_instance_id_is_unique(self):
        sample = SOLVER_MODULE.load_sample(ROOT / "benchmarks" / "swe-bench" / "verified-50.json")
        ids = [task["instance_id"] for task in sample["tasks"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_the_environment_image_matches_the_instance(self):
        # The image name carries the instance, so a mismatch would mean the
        # evaluation would run against a different repository state.  The
        # instance's own separator is not legal in the middle of a Docker
        # tag, so the repository and the instance number are what carry it.
        sample = SOLVER_MODULE.load_sample(ROOT / "benchmarks" / "swe-bench" / "verified-50.json")
        for task in sample["tasks"]:
            image = task["environment_image"]
            repository, _, number = task["instance_id"].partition("__")[2].rpartition("-")
            self.assertIn(repository, image)
            self.assertIn(number, image)

    def test_the_image_of_an_instance_can_be_looked_up(self):
        image = SOLVER_MODULE.image_for_instance("astropy__astropy-12907")
        self.assertIn("astropy_1776_astropy-12907", image)

    def test_looking_up_an_unknown_instance_raises(self):
        with self.assertRaises(SOLVER_MODULE.SolverError):
            SOLVER_MODULE.image_for_instance("not-a-real-instance")

    def test_a_missing_instance_raises(self):
        with self.assertRaises(SolverError := SOLVER_MODULE.SolverError):
            SOLVER_MODULE._problem_statements(["not-a-real-instance"])


class SolverPatchTests(unittest.TestCase):
    def test_the_patch_is_read_from_the_evidence_bundle(self):
        # The runtime edits the repository in a detached worktree, so the
        # evidence bundle is the authoritative record of the delivery.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertIsNone(SOLVER_MODULE._read_patch(root))
            run_dir = root / "code-1"
            run_dir.mkdir()
            self.assertIsNone(SOLVER_MODULE._read_patch(root))
            (run_dir / "changes.patch").write_bytes(b"diff --git a/x b/x\n")
            self.assertEqual(SOLVER_MODULE._read_patch(root), b"diff --git a/x b/x\n")

    def test_two_run_directories_are_ambiguous(self):
        # Two runs under one evidence root would make it impossible to say
        # which patch belongs to the task.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("code-1", "code-2"):
                directory = root / name
                directory.mkdir()
                (directory / "changes.patch").write_bytes(b"x")
            self.assertIsNone(SOLVER_MODULE._read_patch(root))


class SolverCredentialTests(unittest.TestCase):
    def test_no_credentials_means_not_evaluated(self):
        environment = dict(os.environ)
        for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            environment.pop(name, None)
        original = os.environ
        try:
            os.environ = environment
            self.assertFalse(SOLVER_MODULE._credentials_present("openai"))
            self.assertFalse(SOLVER_MODULE._credentials_present("anthropic"))
            self.assertTrue(SOLVER_MODULE._credentials_present("scripted"))
        finally:
            os.environ = original


class SolverReceiptTests(unittest.TestCase):
    def test_a_run_without_credentials_says_so_and_invents_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "solve.json"
            original = os.environ
            environment = dict(original)
            for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
                environment.pop(name, None)
            try:
                os.environ = environment
                code = SOLVER_MODULE.main([
                    "--provider", "openai",
                    "--output", str(output),
                    "--task", "astropy__astropy-12907",
                ])
            finally:
                os.environ = original
            self.assertEqual(code, 0)
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(receipt["real_model_evaluated"])
            self.assertEqual(receipt["summary"]["reason"], "no_provider_credentials")
            self.assertEqual(receipt["summary"]["solved"], 0)


if __name__ == "__main__":
    unittest.main()
