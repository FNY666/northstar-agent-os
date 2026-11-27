"""Tests for keeping the integrity verdicts on disk as they arrive."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import swe_bench_integrity as mod  # noqa: E402


class StoreTests(unittest.TestCase):
    def test_a_verdict_is_on_disk_before_the_run_is_over(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "check.json"
            store = mod.CheckStore(path)
            item = mod.InstanceIntegrity(instance_id="a", verdict=mod.TRUSTWORTHY)
            store.add(item, {"gold": {"resolved": True}})
            store.flush("sample.json")
            written = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(written["instances"][0]["instance_id"], "a")
            self.assertEqual(written["summary"]["instances"], 1)

    def test_a_run_that_starts_again_does_not_repeat_the_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "check.json"
            first = mod.CheckStore(path)
            first.add(mod.InstanceIntegrity(instance_id="a", verdict=mod.TRUSTWORTHY))
            first.flush()

            second = mod.CheckStore(path)
            self.assertTrue(second.done("a"))
            self.assertFalse(second.done("b"))
            self.assertEqual(len(second.items), 1)

    def test_the_verdicts_survive_a_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "check.json"
            store = mod.CheckStore(path)
            store.add(
                mod.InstanceIntegrity(
                    instance_id="a",
                    verdict=mod.EMPTY_ACCEPTED,
                    fail_to_pass_passing_when_empty=["t::x"],
                    failures_under_both=["t::y"],
                )
            )
            store.flush()

            again = mod.CheckStore(path)
            item = again.items[0]
            self.assertEqual(item.verdict, mod.EMPTY_ACCEPTED)
            self.assertEqual(item.fail_to_pass_passing_when_empty, ["t::x"])
            self.assertEqual(item.failures_under_both, ["t::y"])

    def test_a_half_written_file_does_not_stop_a_new_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "check.json"
            path.write_text("{not json", encoding="utf-8")
            store = mod.CheckStore(path)
            self.assertEqual(store.items, [])
            self.assertFalse(store.done("a"))

    def test_the_store_keeps_the_raw_grader_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "check.json"
            store = mod.CheckStore(path)
            store.add(mod.InstanceIntegrity(instance_id="a", verdict=mod.TRUSTWORTHY), {"gold": {"x": 1}})
            store.flush()
            written = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(written["raw"]["a"]["gold"]["x"], 1)

    def test_the_summary_counts_the_verdicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = mod.CheckStore(Path(tmp) / "check.json")
            store.add(mod.InstanceIntegrity(instance_id="a", verdict=mod.TRUSTWORTHY))
            store.add(mod.InstanceIntegrity(instance_id="b", verdict=mod.EMPTY_ACCEPTED))
            summary = store.report().summary()
            self.assertEqual(summary["instances"], 2)
            self.assertEqual(summary["trustworthy"], 1)
            self.assertEqual(summary["untrustworthy"], 1)


if __name__ == "__main__":
    unittest.main()
