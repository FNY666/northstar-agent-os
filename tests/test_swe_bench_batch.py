"""Tests for the SWE-bench batch runner, focused on resuming."""
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_swe_bench_batch.py"


def _module():
    spec = importlib.util.spec_from_file_location("swe_batch", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["swe_batch"] = module
    spec.loader.exec_module(module)
    return module


class _FakeProcess:
    def __init__(self, returncode=0):
        self.returncode = returncode


class BatchResumeTests(unittest.TestCase):
    def setUp(self):
        self.module = _module()
        self.sample = {"tasks": [{"instance_id": "a__x-1"}, {"instance_id": "b__y-2"}]}

    def _batch(self, out, **kwargs):
        params = dict(
            sample=self.sample, out=Path(out), provider="openai", model="m",
            base_url="", temperature=None, timeout=1, python=sys.executable,
            eval_python=sys.executable, log=lambda *a: None,
        )
        params.update(kwargs)
        return self.module.run_batch(**params)

    def test_an_instance_with_an_evaluation_receipt_is_not_solved_again(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "eval-a__x-1.json").write_text(json.dumps({"tasks": []}), encoding="utf-8")
            calls = []

            def fake_run(command, log):
                calls.append(command)
                return 0

            self.module._run = fake_run
            result = self._batch(out)
            self.assertIn("a__x-1", result["skipped"])
            # the solver never ran for the instance that already has a receipt
            self.assertFalse(any("a__x-1" in " ".join(c) for c in calls))

    def test_the_patch_file_is_never_truncated(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            patch_file = out / "patches.json"
            patch_file.write_text(json.dumps({"old__one-1": "diff --git a b\n"}), encoding="utf-8")
            (out / "solve-a__x-1-patches.json").write_text(
                json.dumps({"a__x-1": "diff --git a c\n"}), encoding="utf-8"
            )

            def fake_run(command, log):
                Path(log).parent.mkdir(parents=True, exist_ok=True)
                Path(log).write_text("{}", encoding="utf-8")
                return 0

            self.module._run = fake_run
            self._batch(out)
            merged = json.loads(patch_file.read_text(encoding="utf-8"))
            self.assertIn("old__one-1", merged)
            self.assertIn("a__x-1", merged)

    def test_a_second_run_skips_what_the_first_run_finished(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)

            def fake_run(command, log):
                Path(log).parent.mkdir(parents=True, exist_ok=True)
                if "run_swe_bench_eval.py" in " ".join(command):
                    name = command[command.index("--output") + 1]
                    Path(name).write_text(
                        json.dumps({"tasks": [{"instance_id": "x", "outcome": "RESOLVED_FULL"}]}),
                        encoding="utf-8",
                    )
                Path(log).write_text("{}", encoding="utf-8")
                return 0

            self.module._run = fake_run
            first = self._batch(out)
            self.assertEqual(len(first["solved"]), 2)
            second = self._batch(out)
            self.assertEqual(len(second["skipped"]), 2)
            self.assertEqual(len(second["solved"]), 0)


if __name__ == "__main__":
    unittest.main()
