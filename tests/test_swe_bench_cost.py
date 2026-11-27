"""Tests for reading what a run cost from its evidence bundle."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "swe_bench_cost.py"


def _module():
    spec = importlib.util.spec_from_file_location("swe_bench_cost", MODULE)
    module = importlib.util.module_from_spec(spec)
    sys.modules["swe_bench_cost"] = module
    spec.loader.exec_module(module)
    return module


def _bundle(root: Path, events: list[dict], name: str = "code-1") -> Path:
    evidence = root / name
    sessions = evidence / "sessions"
    sessions.mkdir(parents=True)
    lines = [json.dumps(event) for event in events]
    (sessions / "ns-1.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return root


class ReadUsageTests(unittest.TestCase):
    def setUp(self):
        self.mod = _module()

    def test_the_cost_of_a_run_is_read_from_its_transcript(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = _bundle(Path(tmp), [
                {"type": "assistant", "content": "x"},
                {
                    "type": "result",
                    "total_usage": {
                        "input_tokens": 514861,
                        "output_tokens": 1836,
                        "cache_read_input_tokens": 464896,
                        "cache_creation_input_tokens": 0,
                    },
                    "total_cost_usd": 8.557959,
                    "duration_ms": 73018,
                    "tool_calls": 22,
                    "num_turns": 17,
                },
            ])
            found = self.mod.read_usage(evidence)
        self.assertEqual(found["usage"]["input_tokens"], 514861)
        self.assertEqual(found["usage"]["cache_read_input_tokens"], 464896)
        self.assertEqual(found["cost_usd"], 8.557959)
        self.assertEqual(found["duration_ms"], 73018)
        self.assertEqual(found["tool_calls"], 22)
        self.assertEqual(found["num_turns"], 17)

    def test_the_tool_calls_are_found_when_the_result_event_has_none(self):
        """The result event counts the turns; the calls live on the message."""
        with tempfile.TemporaryDirectory() as tmp:
            evidence = _bundle(Path(tmp), [
                {"type": "assistant", "tool_calls": 22, "content": "x"},
                {
                    "type": "result",
                    "total_usage": {"input_tokens": 100},
                    "total_cost_usd": 1.5,
                    "num_turns": 3,
                },
            ])
            found = self.mod.read_usage(evidence)
        self.assertEqual(found["tool_calls"], 22)
        self.assertEqual(found["num_turns"], 3)

    def test_an_unknown_cost_is_not_reported_as_zero(self):
        """A missing transcript means unknown, not free."""
        with tempfile.TemporaryDirectory() as tmp:
            found = self.mod.read_usage(Path(tmp) / "nothing")
        self.assertIsNone(found["cost_usd"])
        self.assertEqual(found["usage"]["input_tokens"], 0)

    def test_a_transcript_without_a_result_event_costs_nothing_known(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = _bundle(Path(tmp), [{"type": "assistant", "content": "x"}])
            found = self.mod.read_usage(evidence)
        self.assertIsNone(found["num_turns"])

    def test_a_truncated_last_line_does_not_hide_the_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp)
            sessions = evidence / "code-1" / "sessions"
            sessions.mkdir(parents=True)
            (sessions / "ns-1.jsonl").write_text(
                json.dumps({"type": "result", "total_cost_usd": 1.5,
                            "total_usage": {"input_tokens": 10}}) + "\n"
                + '{"type": "assistant", "conten',
                encoding="utf-8",
            )
            found = self.mod.read_usage(evidence)
        self.assertEqual(found["cost_usd"], 1.5)
        self.assertEqual(found["usage"]["input_tokens"], 10)


class TotalUsageTests(unittest.TestCase):
    def setUp(self):
        self.mod = _module()

    def test_the_costs_of_the_instances_are_summed(self):
        receipts = [
            {"usage": {"input_tokens": 100, "output_tokens": 5},
             "cost_usd": 1.25, "duration_ms": 1000, "tool_calls": 3, "num_turns": 2},
            {"usage": {"input_tokens": 200, "output_tokens": 7},
             "cost_usd": 2.50, "duration_ms": 2000, "tool_calls": 4, "num_turns": 3},
        ]
        total = self.mod.total_usage(receipts)
        self.assertEqual(total["usage"]["input_tokens"], 300)
        self.assertEqual(total["cost_usd"], 3.75)
        self.assertEqual(total["instances_with_cost"], 2)
        self.assertEqual(total["duration_ms"], 3000)
        self.assertEqual(total["tool_calls"], 7)

    def test_an_instance_without_a_cost_is_counted_as_unknown(self):
        receipts = [
            {"usage": {"input_tokens": 100}, "cost_usd": 1.0},
            {"usage": {}, "cost_usd": None},
        ]
        total = self.mod.total_usage(receipts)
        self.assertEqual(total["cost_usd"], 1.0)
        self.assertEqual(total["instances_without_cost"], 1)
        self.assertEqual(total["instances_without_usage"], 1)


if __name__ == "__main__":
    unittest.main()
