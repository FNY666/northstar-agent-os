"""Contract tests for the real-model baseline harness.

The harness measures a real model against the frozen offline task pack, so the
tests here never call a model.  They check the receipt contract, the
classification rules and the guard that keeps a run without credentials from
being reported as a measurement.
"""
from __future__ import annotations

import difflib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run-code-task-baseline.py"
SPEC = importlib.util.spec_from_file_location("run_code_task_baseline", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError(f"cannot load {SCRIPT}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BaselineReceiptTests(unittest.TestCase):
    def test_the_frozen_pack_identity_is_recorded(self):
        identity = MODULE._pack_identity()
        self.assertEqual(identity["pack_id"], "northstar-offline-code-v1")
        # The fingerprint must match the one frozen into controls-baseline.json,
        # otherwise the measurement would be taken against a different pack.
        controls = json.loads(
            (ROOT / "benchmarks" / "code-tasks" / "v1" / "controls-baseline.json").read_text()
        )
        self.assertEqual(identity["manifest_sha256"], controls["manifest_sha256"])
        self.assertEqual(len(identity["task_ids"]), 24)
        self.assertIn(
            identity["manifest_sha256"],
            (ROOT / "benchmarks" / "code-tasks" / "v1" / "controls-baseline.json").read_text(),
        )

    def test_a_run_without_credentials_is_not_a_measurement(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receipt.json"
            receipt = MODULE.run_baseline(
                provider="openai",
                model="some-model",
                base_url="",
                output=output,
                only=["py-feat-001-batch-normalize"],
            )
        self.assertFalse(receipt["real_model_evaluated"])
        self.assertFalse(receipt["release_eligible"])
        self.assertEqual(receipt["summary"]["reason"], "no_provider_credentials")
        self.assertEqual(receipt["tasks"], [])

    def test_the_receipt_records_the_frozen_conditions(self):
        receipt = MODULE.run_baseline(
            provider="openai",
            model="some-model",
            base_url="https://example.invalid/v1",
            output=Path(tempfile.mkdtemp()) / "receipt.json",
            only=["py-feat-001-batch-normalize"],
        )
        conditions = receipt["conditions"]
        self.assertEqual(conditions["provider"], "openai")
        self.assertEqual(conditions["model"], "some-model")
        self.assertEqual(conditions["sandbox"]["backend"], "process")
        self.assertIn("seccomp", conditions["sandbox"])
        self.assertIn("toolchain", conditions)
        self.assertIn("python", conditions["toolchain"])
        self.assertEqual(conditions["pack"]["manifest_sha256"], MODULE._pack_identity()["manifest_sha256"])

    def test_the_release_gate_needs_twenty_of_twenty_four(self):
        self.assertEqual(MODULE.RELEASE_GATE_TASKS, 20)
        self.assertEqual(len(MODULE._pack_identity()["task_ids"]), 24)

    def test_an_unknown_task_id_is_refused(self):
        with self.assertRaises(ValueError):
            MODULE.run_baseline(
                provider="openai",
                model="some-model",
                base_url="",
                output=Path(tempfile.mkdtemp()) / "receipt.json",
                only=["not-a-real-task"],
            )


class BaselineClassificationTests(unittest.TestCase):
    def test_a_passing_run_is_reported_as_passed(self):
        result = {"return_code": 0, "timed_out": False, "patch_bytes": 120}
        evaluation = {"ok": True}
        self.assertEqual(MODULE._classify(result, evaluation), "passed")

    def test_a_public_check_failure_is_its_own_class(self):
        result = {"return_code": 6, "timed_out": False, "patch_bytes": 120}
        evaluation = {"ok": False, "public": [{"exit_code": 1, "timed_out": False}]}
        self.assertEqual(MODULE._classify(result, evaluation), "public_check_failed")

    def test_a_timed_out_run_is_never_counted_as_a_pass(self):
        result = {"return_code": 124, "timed_out": True, "patch_bytes": 0}
        self.assertEqual(MODULE._classify(result, None), "timeout")
        self.assertNotEqual(MODULE._classify(result, {"ok": True}), "passed")

    def test_a_timed_out_check_is_its_own_class(self):
        result = {"return_code": 6, "timed_out": False, "patch_bytes": 120}
        evaluation = {"ok": False, "public": [{"exit_code": 124, "timed_out": True}]}
        self.assertEqual(MODULE._classify(result, evaluation), "check_timeout")

    def test_a_hidden_check_failure_is_its_own_class(self):
        result = {"return_code": 6, "timed_out": False, "patch_bytes": 120}
        evaluation = {
            "ok": False,
            "public": [{"exit_code": 0, "timed_out": False}],
            "hidden": {"exit_code": 1},
        }
        self.assertEqual(MODULE._classify(result, evaluation), "hidden_check_failed")

    def test_a_run_without_a_patch_cannot_pass(self):
        # Without a patch there is nothing to evaluate, so the run cannot pass.
        result = {"return_code": 0, "timed_out": False, "patch_bytes": 0}
        self.assertEqual(MODULE._classify(result, None), "no_patch_delivered")


if __name__ == "__main__":
    unittest.main()


class BaselineEndToEndTests(unittest.TestCase):
    """Drive the whole harness against the runtime's scripted provider.

    The script answers the two turns a code task needs -- submit a plan, then
    write the file -- so this exercises the real runtime, the real evaluation
    and the real receipt without calling a hosted model.
    """

    #: The code-task tool set is host-owned: a plan must be submitted before any
    #: effectful tool runs, and the edit itself is a unified patch, not a write.
    _PLAN = {
        "name": "SubmitPlan",
        "input": {
            "summary": "implement the batch API",
            "files": ["names.py"],
            "steps": ["write names.py"],
            "risks": [],
            "check_indices": [],
        },
    }

    def _script(self, tmp: str, content: str) -> str:
        """A scripted run that submits a plan and then applies one patch."""
        fixture = (
            ROOT / "benchmarks" / "code-tasks" / "v1" / "fixtures" / "py-feat-001" / "names.py"
        )
        before = fixture.read_text(encoding="utf-8").splitlines(keepends=True)
        after = content.splitlines(keepends=True)
        body = difflib.unified_diff(before, after, fromfile="a/names.py", tofile="b/names.py", n=3)
        patch = "diff --git a/names.py b/names.py\n" + "".join(body)
        script = Path(tmp) / "script.json"
        script.write_text(
            json.dumps(
                {
                    "turns": [
                        {"tool": self._PLAN},
                        {"tool": {"name": "ApplyPatch", "input": {"patch": patch}}},
                    ]
                }
            ),
            encoding="utf-8",
        )
        return str(script)

    def _run(self, tmp: str, content: str) -> dict:
        output = Path(tmp) / "receipt.json"
        code = MODULE.main(
            [
                "--provider", "scripted",
                "--model", "scripted",
                "--script", self._script(tmp, content),
                "--task", "py-feat-001-batch-normalize",
                "--output", str(output),
                "--keep-workdir", str(Path(tmp) / "keep"),
            ]
        )
        self.assertEqual(code, 0)
        return json.loads(output.read_text(encoding="utf-8"))

    def test_a_correct_edit_is_measured_as_a_pass(self):
        reference = json.loads(
            (
                ROOT
                / "benchmarks"
                / "code-tasks"
                / "v1"
                / "references"
                / "py-feat-001.json"
            ).read_text()
        )
        with tempfile.TemporaryDirectory() as tmp:
            receipt = self._run(tmp, reference["names.py"])
        self.assertTrue(receipt["real_model_evaluated"])
        self.assertEqual(receipt["tasks"][0]["outcome"], "passed")
        self.assertTrue(receipt["tasks"][0]["evaluation_ok"])
        self.assertGreater(receipt["tasks"][0]["patch_bytes"], 0)

    def test_a_wrong_edit_is_measured_as_a_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt = self._run(tmp, "def broken():\n    return None\n")
        self.assertTrue(receipt["real_model_evaluated"])
        self.assertEqual(receipt["tasks"][0]["outcome"], "public_check_failed")
        self.assertFalse(receipt["tasks"][0]["evaluation_ok"])
        self.assertFalse(receipt["release_gate"]["eligible"])
