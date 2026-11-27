"""Tests for storing an integrity check result."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import record_swe_bench_integrity as mod  # noqa: E402


class RecordTests(unittest.TestCase):
    def test_the_record_carries_the_sample_it_was_run_on(self):
        payload = {"summary": {"instances": 3}, "instances": [{"instance_id": "a", "verdict": "trustworthy"}]}
        record = mod.build_record(payload, "sample.json", "abc123", {"probe": "gold+empty"})
        self.assertEqual(record["sample"], "sample.json")
        self.assertEqual(record["sample_sha256"], "abc123")
        self.assertEqual(record["conditions"]["probe"], "gold+empty")
        self.assertEqual(record["summary"]["instances"], 3)

    def test_an_untrustworthy_task_is_named_in_the_record(self):
        payload = {"summary": {}, "instances": [{"instance_id": "b", "verdict": "empty_patch_accepted"}]}
        record = mod.build_record(payload, "sample.json", "")
        self.assertEqual(record["instances"][0]["instance_id"], "b")
        self.assertEqual(record["instances"][0]["verdict"], "empty_patch_accepted")

    def test_the_record_has_its_own_schema_name(self):
        record = mod.build_record({}, "sample.json", "")
        self.assertEqual(record["schema"], "northstar.swe-bench.integrity.v1")


if __name__ == "__main__":
    unittest.main()
