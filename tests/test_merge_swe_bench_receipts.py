import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _module():
    path = ROOT / "scripts" / "merge_swe_bench_receipts.py"
    spec = importlib.util.spec_from_file_location("merge_receipts", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MergeReceiptsTests(unittest.TestCase):
    def setUp(self):
        self.module = _module()

    def _batch(self, count=2):
        out = Path(tempfile.mkdtemp())
        for index in range(count):
            instance = "repo__repo-%d" % index
            (out / f"solve-{instance}.json").write_text(json.dumps({
                "conditions": {"model": "m", "temperature": 0.0},
                "real_model_evaluated": True,
                "tasks": [{"instance_id": instance, "outcome": "solved", "patch_bytes": 10}],
            }), encoding="utf-8")
            (out / f"eval-{instance}.json").write_text(json.dumps({
                "tasks": [{"instance_id": instance, "outcome": "RESOLVED_FULL", "resolved": True}],
            }), encoding="utf-8")
        return out

    def test_the_receipts_of_a_batch_are_joined(self):
        out = self._batch(2)
        solve, evaluate, gaps = self.module.collect(out)
        self.assertEqual(len(solve["tasks"]), 2)
        self.assertEqual(len(evaluate["tasks"]), 2)
        self.assertEqual(gaps, {})

    def test_an_instance_without_a_solve_receipt_is_left_out_and_said(self):
        out = self._batch(1)
        (out / "eval-repo__repo-9.json").write_text(json.dumps({
            "tasks": [{"instance_id": "repo__repo-9", "outcome": "RESOLVED_FULL"}],
        }), encoding="utf-8")
        solve, evaluate, gaps = self.module.collect(out)
        self.assertEqual(len(solve["tasks"]), 1)
        self.assertIn("repo__repo-9", gaps)

    def test_the_conditions_of_the_batch_are_kept(self):
        out = self._batch(2)
        solve, _, _ = self.module.collect(out)
        self.assertEqual(solve["conditions"]["model"], "m")
        self.assertTrue(solve["real_model_evaluated"])

    def test_a_batch_with_nothing_complete_is_refused(self):
        out = Path(tempfile.mkdtemp())
        code = self.module.main([
            "--batch", str(out),
            "--solve-output", str(out / "solve.json"),
            "--eval-output", str(out / "eval.json"),
        ])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
