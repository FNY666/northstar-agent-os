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

_record_spec = importlib.util.spec_from_file_location(
    "northstar_record_measurement", ROOT / "scripts" / "record_measurement.py"
)
_record_module = importlib.util.module_from_spec(_record_spec)
_record_spec.loader.exec_module(_record_module)


def _records() -> list[dict]:
    if not MEASUREMENTS.is_dir():
        return []
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(MEASUREMENTS.glob("*.json"))
    ]


class RecordedMeasurementTests(unittest.TestCase):
    def test_endpoint_attribution_requires_a_vendor_domain_boundary(self):
        expected = {
            "https://api.openai.com/v1": "OpenAI official endpoint",
            "https://OPENAI.COM./v1": "OpenAI official endpoint",
            "https://api.anthropic.com/v1": "Anthropic official endpoint",
            "https://attackeropenai.com/v1": "third-party relay",
            "https://openai.com.attacker.example/v1": "third-party relay",
            "https://notanthropic.com/v1": "third-party relay",
            "https://anthropic.com.attacker.example/v1": "third-party relay",
            "https://openai.com@attacker.example/v1": "third-party relay",
        }
        for base_url, expected_note in expected.items():
            with self.subTest(base_url=base_url):
                note = _record_module._endpoint_note(base_url)
                self.assertTrue(note.startswith(expected_note), note)

    def test_archiving_redacts_path_credentials_from_legacy_receipts(self):
        secret = "dummy-archive-path-secret"
        base_url = (
            f"https://user:dummy-archive-user-secret@gateway.example.invalid/"
            f"v1/tenant/{secret}/chat/completions?api_key=dummy-archive-query-secret"
        )
        receipt = {
            "conditions": {
                "provider": "openai",
                "model": "test-model",
                "base_url": base_url,
                "pack": {"pack_id": "test-pack", "manifest_sha256": "test-sha"},
                "limits": {},
                "sandbox": {},
                "toolchain": {},
            },
            "summary": {},
            "measurement": "real_model_baseline",
            "real_model_evaluated": True,
            "release_eligible": False,
            "release_gate": {},
            "tasks": [],
        }
        record = _record_module.build_record(receipt)
        serialized = json.dumps(record, sort_keys=True)
        archived_url = record["model"]["base_url"]

        self.assertTrue(archived_url.startswith("https://gateway.example.invalid/_redacted-path-sha256/"))
        self.assertEqual(archived_url, _record_module._record_base_url(base_url))
        self.assertEqual(archived_url, _baseline_module._receipt_base_url(base_url))
        self.assertNotIn(secret, serialized)
        self.assertNotIn("dummy-archive-user-secret", serialized)
        self.assertNotIn("dummy-archive-query-secret", serialized)
        self.assertIn("third-party relay (gateway.example.invalid)", record["model"]["endpoint_note"])

    def test_every_record_describes_a_real_evaluation(self):
        records = _records()
        self.assertTrue(records, "no recorded measurement is present")
        for record in records:
            with self.subTest(record=record.get("schema")):
                self.assertIn(
                    record["schema"],
                    (
                        "northstar.code-task-measurement.v1",
                        "northstar.code-task-measurement-repeated.v1",
                    ),
                )
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


class RepeatedMeasurementTests(unittest.TestCase):
    """The lower of two runs is the number that counts."""

    RECORD = (
        Path(__file__).resolve().parent.parent
        / "benchmarks" / "code-tasks" / "v1" / "measurements"
        / "2026-11-24-gpt-6-astra-repeated.json"
    )

    def setUp(self) -> None:
        self.record = json.loads(self.RECORD.read_text(encoding="utf-8"))

    def test_the_recorded_number_is_the_lower_of_the_runs(self):
        counts = self.record["summary"]["run_passed"]
        self.assertGreaterEqual(len(counts), 2)
        self.assertEqual(self.record["summary"]["passed"], min(counts))

    def test_a_higher_run_does_not_raise_the_recorded_number(self):
        self.assertEqual(
            self.record["release_gate"]["passed"],
            self.record["summary"]["lower_of_runs"],
        )
        self.assertTrue(
            self.record["release_gate"]["eligible"]
            == (self.record["summary"]["lower_of_runs"] >= self.record["release_gate"]["required_tasks"])
        )

    def test_both_runs_are_kept_so_the_fold_can_be_checked(self):
        self.assertEqual(len(self.record["runs"]), self.record["summary"]["runs"])
        for run in self.record["runs"]:
            self.assertIn("passed", run)
            self.assertIn("tasks", run)

    def test_the_runs_measured_the_same_thing(self):
        self.assertTrue(self.record["conditions_identical_across_runs"])

    def test_tasks_that_differed_between_runs_are_named(self):
        unstable = self.record["unstable_tasks"]
        self.assertTrue(unstable)
        for entry in unstable:
            self.assertIn("task_id", entry)
            self.assertGreater(len(set(entry["outcomes"])), 1)

    def test_a_single_run_cannot_be_reported_as_a_repeated_measurement(self):
        self.assertGreater(self.record["summary"]["runs"], 1)
