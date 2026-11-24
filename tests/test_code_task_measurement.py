"""Contract tests for recorded real-model measurements.

A measurement that ships with the pack is evidence.  These tests check
that the evidence says what it claims: that it points at the pack it was
measured against, that it reports a real evaluation, and that its release
gate follows from the tasks it records.
"""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MEASUREMENTS = ROOT / "benchmarks" / "code-tasks" / "v1" / "measurements"

# Read the threshold from the harness rather than from the record, so that a
# record cannot satisfy the test by moving the goalposts itself.
_spec = importlib.util.spec_from_file_location(
    "northstar_code_task_baseline", ROOT / "scripts" / "run-code-task-baseline.py"
)
_baseline_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_baseline_module)
RELEASE_GATE_TASKS = _baseline_module.RELEASE_GATE_TASKS


def _records() -> list[dict]:
    if not MEASUREMENTS.is_dir():
        return []
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(MEASUREMENTS.glob("*.json"))
    ]


class RecordedMeasurementTests(unittest.TestCase):
    def test_every_record_describes_a_real_evaluation(self):
        records = _records()
        self.assertTrue(records, "no recorded measurement is present")
        for record in records:
            with self.subTest(record=record.get("schema")):
                self.assertEqual(record["schema"], "northstar.code-task-measurement.v1")
                self.assertEqual(record["measurement"], "real_model_baseline")
                self.assertTrue(record["real_model_evaluated"])

    def test_a_record_is_pinned_to_the_pack_it_was_measured_against(self):
        manifest = json.loads(
            (ROOT / "benchmarks" / "code-tasks" / "v1" / "manifest.json").read_text(encoding="utf-8")
        )
        for record in _records():
            with self.subTest(record=record["schema"]):
                self.assertEqual(record["pack_id"], manifest["pack_id"])
                self.assertEqual(
                    record["pack_manifest_sha256"],
                    json.loads(
                        (
                            ROOT / "benchmarks" / "code-tasks" / "v1" / "controls-baseline.json"
                        ).read_text(encoding="utf-8")
                    )["manifest_sha256"],
                )

    def test_the_release_gate_follows_from_the_recorded_tasks(self):
        for record in _records():
            with self.subTest(record=record["schema"]):
                tasks = record["tasks"]
                passed = sum(1 for row in tasks if row["outcome"] == "passed")
                self.assertEqual(record["summary"]["checked"], len(tasks))
                self.assertEqual(record["summary"]["passed"], passed)
                self.assertEqual(record["summary"]["failed"], len(tasks) - passed)
                gate = record["release_gate"]
                self.assertEqual(gate["passed"], passed)
                # The threshold is a constant of the harness, not something the
                # record may choose for itself: a record that widened its own
                # gate would otherwise pass every self-consistency check.
                self.assertEqual(gate["required_tasks"], RELEASE_GATE_TASKS)
                self.assertEqual(gate["eligible"], passed >= RELEASE_GATE_TASKS)
                self.assertEqual(record["release_eligible"], gate["eligible"])

    def test_a_failing_task_is_never_counted_as_a_pass(self):
        for record in _records():
            for row in record["tasks"]:
                with self.subTest(task=row["task_id"], outcome=row["outcome"]):
                    if row["outcome"] == "passed":
                        self.assertTrue(row["evaluation_ok"])
                        self.assertTrue(row["patch_sha256"])
                    else:
                        self.assertNotEqual(row["outcome"], "passed")

    def test_the_endpoint_is_described_plainly(self):
        for record in _records():
            with self.subTest(record=record["schema"]):
                note = record["model"]["endpoint_note"]
                self.assertTrue(note)
                base_url = record["model"]["base_url"]
                if base_url and "(provider default)" not in base_url:
                    host = base_url.split("//", 1)[-1].split("/", 1)[0]
                    if not host.endswith(("openai.com", "anthropic.com")):
                        self.assertIn("third-party relay", note)


if __name__ == "__main__":
    unittest.main()
