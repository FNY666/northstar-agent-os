"""Tests for the SWE-bench measurement record."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORDER = ROOT / "scripts" / "record_swe_bench_measurement.py"

SPEC = importlib.util.spec_from_file_location("record_swe_bench_measurement", RECORDER)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError(f"cannot load {RECORDER}")
RECORDER_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECORDER_MODULE)


def _solve(rows: list[dict]) -> dict:
    return {
        "real_model_evaluated": True,
        "conditions": {"provider": "openai", "model": "gpt-6-astra", "temperature": 0.0},
        "tasks": rows,
    }


def _eval(rows: list[dict]) -> dict:
    return {"conditions": {"harness": "upstream swebench 5.0.2"}, "tasks": rows}


class MeasurementRecordTests(unittest.TestCase):
    def test_a_resolved_instance_is_counted_as_a_pass(self):
        record = RECORDER_MODULE.build_record(
            _solve([{"instance_id": "a__b-1", "repo": "a/b", "patch_bytes": 10}]),
            _eval([{"instance_id": "a__b-1", "outcome": "RESOLVED_FULL", "resolved": True}]),
            ROOT / "benchmarks" / "swe-bench" / "verified-50.json",
        )
        self.assertEqual(record["summary"]["resolved_full"], 1)
        self.assertEqual(record["summary"]["resolved_rate"], 1.0)

    def test_a_partial_resolution_is_not_a_pass(self):
        # RESOLVED_PARTIAL means the failing tests pass but something else
        # broke.  Counting it as a pass would overstate the result.
        record = RECORDER_MODULE.build_record(
            _solve([{"instance_id": "a__b-1", "repo": "a/b", "patch_bytes": 10}]),
            _eval([{"instance_id": "a__b-1", "outcome": "RESOLVED_PARTIAL", "resolved": False}]),
            ROOT / "benchmarks" / "swe-bench" / "verified-50.json",
        )
        self.assertEqual(record["summary"]["resolved_full"], 0)
        self.assertEqual(record["summary"]["resolved_partial"], 1)
        self.assertEqual(record["summary"]["failed"], 0)
        self.assertEqual(record["summary"]["resolved_rate"], 0.0)

    def test_a_timeout_is_not_a_verdict_and_not_a_pass(self):
        # The run did not finish, so there is no verdict on the model.  It is
        # reported apart from the failures: counting it as one would blame
        # the model for the harness taking too long.
        record = RECORDER_MODULE.build_record(
            _solve([{"instance_id": "a__b-1", "repo": "a/b", "patch_bytes": 10}]),
            _eval([{"instance_id": "a__b-1", "outcome": "evaluation_timeout", "resolved": False}]),
            ROOT / "benchmarks" / "swe-bench" / "verified-50.json",
        )
        self.assertEqual(record["summary"]["resolved_full"], 0)
        self.assertEqual(record["summary"]["failed"], 0)
        self.assertEqual(record["summary"]["not_a_verdict"], 1)
        self.assertEqual(record["summary"]["resolved_rate_over_verdicts"], 0.0)

    def test_an_inconclusive_run_is_reported_apart_from_the_failures(self):
        record = RECORDER_MODULE.build_record(
            _solve([{"instance_id": "a__b-1", "repo": "a/b", "patch_bytes": 10}]),
            _eval([{"instance_id": "a__b-1", "outcome": "evaluation_inconclusive", "resolved": False}]),
            ROOT / "benchmarks" / "swe-bench" / "verified-50.json",
        )
        self.assertEqual(record["summary"]["failed"], 0)
        self.assertEqual(record["summary"]["not_a_verdict"], 1)

    def test_every_outcome_the_evaluator_can_produce_is_known(self):
        # A new outcome that the record does not know about would silently
        # be counted as a model failure.  The two halves have to agree.
        outcomes = {
            "RESOLVED_FULL", "RESOLVED_PARTIAL", "RESOLVED_NO",
            "patch_not_applied", "no_patch_delivered",
            "evaluation_inconclusive", "evaluation_infrastructure_failure",
            "evaluation_timeout", "ERROR",
        }
        known = {
            RECORDER_MODULE.RESOLVED_FULL,
            RECORDER_MODULE.RESOLVED_PARTIAL,
            "RESOLVED_NO",
        } | set(RECORDER_MODULE.NOT_A_VERDICT)
        self.assertEqual(outcomes - known, set())
        # RESOLVED_NO is a verdict on the model, so it has to count as a
        # failure rather than as a run that produced no verdict.
        self.assertNotIn("RESOLVED_NO", RECORDER_MODULE.NOT_A_VERDICT)

    def test_a_real_failure_is_still_a_failure(self):
        record = RECORDER_MODULE.build_record(
            _solve([{"instance_id": "a__b-1", "repo": "a/b", "patch_bytes": 10}]),
            _eval([{"instance_id": "a__b-1", "outcome": "RESOLVED_NO", "resolved": False}]),
            ROOT / "benchmarks" / "swe-bench" / "verified-50.json",
        )
        self.assertEqual(record["summary"]["failed"], 1)
        self.assertEqual(record["summary"]["not_a_verdict"], 0)

    def test_the_conditions_of_both_halves_are_recorded(self):
        record = RECORDER_MODULE.build_record(
            _solve([{"instance_id": "a__b-1", "repo": "a/b", "patch_bytes": 10}]),
            _eval([{"instance_id": "a__b-1", "outcome": "RESOLVED_FULL", "resolved": True}]),
            ROOT / "benchmarks" / "swe-bench" / "verified-50.json",
        )
        self.assertEqual(record["conditions"]["model"], "gpt-6-astra")
        self.assertEqual(record["conditions"]["temperature"], 0.0)
        self.assertEqual(record["conditions"]["harness"], "upstream swebench 5.0.2")
        self.assertIn("sample_sha256", record["conditions"])

    def test_disagreeing_halves_are_refused(self):
        with self.assertRaises(ValueError):
            RECORDER_MODULE.build_record(
                _solve([{"instance_id": "a__b-1", "repo": "a/b"}]),
                _eval([{"instance_id": "c__d-2", "outcome": "RESOLVED_FULL"}]),
                ROOT / "benchmarks" / "swe-bench" / "verified-50.json",
            )

    def test_the_output_directory_is_created(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "nested" / "record.json"
            solve = Path(temporary) / "solve.json"
            evaluate = Path(temporary) / "eval.json"
            sample = Path(temporary) / "sample.json"
            solve.write_text(json.dumps(_solve([{"instance_id": "a__b-1", "repo": "a/b"}])))
            evaluate.write_text(json.dumps(_eval([{"instance_id": "a__b-1", "outcome": "RESOLVED_FULL", "resolved": True}])))
            sample.write_text("{}")
            code = RECORDER_MODULE.main([
                "--solve", str(solve), "--eval", str(evaluate),
                "--sample", str(sample), "--output", str(output),
            ])
            self.assertEqual(code, 0)
            self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
