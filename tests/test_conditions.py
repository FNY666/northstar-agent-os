"""Tests for the conditions of an integrity check.

A stored verdict says nothing about which harness produced it unless the
conditions are stored with it. These tests make sure the conditions are
never silently dropped on the way from the probe to the record.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import swe_bench_integrity as mod  # noqa: E402
from record_swe_bench_integrity import build_record  # noqa: E402


class ConditionsTests(unittest.TestCase):
    def test_the_store_keeps_the_conditions_next_to_the_verdicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = mod.CheckStore(Path(tmp) / "check.json")
            store.conditions = {"harness": "swebench", "harness_version": "5.0.2"}
            store.add(mod.InstanceIntegrity(instance_id="a", verdict=mod.TRUSTWORTHY))
            store.flush()
            written = json.loads((Path(tmp) / "check.json").read_text(encoding="utf-8"))
            self.assertEqual(written["conditions"]["harness_version"], "5.0.2")

    def test_the_conditions_survive_a_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "check.json"
            first = mod.CheckStore(path)
            first.conditions = {"harness": "swebench"}
            first.flush()

            again = mod.CheckStore(path)
            self.assertEqual(again.conditions["harness"], "swebench")

    def test_a_record_built_from_a_check_carries_the_conditions(self):
        payload = {
            "summary": {"instances": 1},
            "instances": [{"instance_id": "a", "verdict": "trustworthy"}],
            "conditions": {"harness": "swebench", "timeout": 5400},
        }
        record = build_record(payload, "sample.json", "abc")
        self.assertEqual(record["conditions"]["harness"], "swebench")
        self.assertEqual(record["conditions"]["timeout"], 5400)

    def test_a_record_without_conditions_is_not_a_record_of_a_run(self):
        # The failure this guards against: a stored result that cannot say
        # which harness produced it.
        payload = {"summary": {}, "instances": []}
        record = build_record(payload, "sample.json", "abc")
        self.assertEqual(record["conditions"], {})

    def test_the_conditions_survive_the_probe_to_record_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = mod.CheckStore(Path(tmp) / "check.json")
            store.conditions = {"harness": "swebench", "probes": ["gold", "empty"]}
            store.add(mod.InstanceIntegrity(instance_id="a", verdict=mod.TRUSTWORTHY))
            store.flush()

            payload = json.loads((Path(tmp) / "check.json").read_text(encoding="utf-8"))
            record = build_record(payload, "sample.json", "abc")
            self.assertEqual(record["conditions"]["probes"], ["gold", "empty"])


if __name__ == "__main__":
    unittest.main()
