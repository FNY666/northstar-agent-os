"""Parallel-safe tool batches: gate stays serial; handlers may share a pool."""
from __future__ import annotations

import threading
import time
import unittest

import support  # noqa: F401
from support import RuntimeTestCase, text_turn

from loop import RuntimeConfig, RuntimeConfigurationError
from tools import ToolContext, ToolRegistry, ToolResult, ToolSpec
from tools.parallel import (
    MAX_PARALLEL_TOOLS,
    batch_is_parallel_safe,
    clamp_parallel_tools,
    is_parallel_safe_spec,
)


class ParallelClassifierTests(unittest.TestCase):
    def test_clamp_rejects_zero_and_over_cap(self):
        self.assertEqual(clamp_parallel_tools(1), 1)
        self.assertEqual(clamp_parallel_tools(4), 4)
        with self.assertRaises(ValueError):
            clamp_parallel_tools(0)
        with self.assertRaises(ValueError):
            clamp_parallel_tools(MAX_PARALLEL_TOOLS + 1)
        with self.assertRaises(ValueError):
            clamp_parallel_tools("4")

    def test_only_read_non_mutating_is_safe(self):
        read = ToolSpec(
            name="R",
            description="",
            input_schema={},
            handler=lambda p, c: "ok",
            kind="read",
            is_mutating=False,
        )
        write = ToolSpec(
            name="W",
            description="",
            input_schema={},
            handler=lambda p, c: "ok",
            kind="edit",
            is_mutating=True,
        )
        task = ToolSpec(
            name="Task",
            description="",
            input_schema={},
            handler=lambda p, c: "ok",
            kind="task",
            is_mutating=False,
            is_delegation=True,
        )
        self.assertTrue(is_parallel_safe_spec(read))
        self.assertFalse(is_parallel_safe_spec(write))
        self.assertFalse(is_parallel_safe_spec(task))
        self.assertTrue(batch_is_parallel_safe([read, read]))
        self.assertFalse(batch_is_parallel_safe([read, write]))
        self.assertFalse(batch_is_parallel_safe([read]))


class ParallelDispatchTests(RuntimeTestCase):
    def test_runtime_config_rejects_invalid_parallel_tools(self):
        with self.assertRaises(RuntimeConfigurationError):
            RuntimeConfig(parallel_tools=0)
        with self.assertRaises(RuntimeConfigurationError):
            RuntimeConfig(parallel_tools=99)

    def test_parallel_read_batch_preserves_order_and_overlaps(self):
        barrier = threading.Barrier(3, timeout=5)
        started: list[str] = []
        lock = threading.Lock()

        def slow_read(payload: dict, ctx: ToolContext) -> ToolResult:
            name = str(payload.get("tag") or "?")
            with lock:
                started.append(name)
            barrier.wait()
            time.sleep(0.02)
            return ToolResult.ok(f"done-{name}")

        registry = ToolRegistry()
        registry.register(
            ToolSpec(
                name="SlowRead",
                description="blocks until three peers arrive",
                input_schema={"type": "object", "properties": {"tag": {"type": "string"}}},
                handler=slow_read,
                kind="read",
                is_mutating=False,
            )
        )
        provider = self.provider(
            [
                {
                    "tools": [
                        {"name": "SlowRead", "input": {"tag": "a"}},
                        {"name": "SlowRead", "input": {"tag": "b"}},
                        {"name": "SlowRead", "input": {"tag": "c"}},
                    ]
                },
                text_turn("done"),
            ]
        )
        t0 = time.monotonic()
        report = self.drive(
            self.runtime(
                provider=provider,
                tools=registry,
                parallel_tools=3,
                max_turns=4,
            )
        )
        elapsed = time.monotonic() - t0
        results = report.transcript[2].tool_results
        self.assertEqual([r.text() for r in results], ["done-a", "done-b", "done-c"])
        self.assertEqual([r.is_error for r in results], [False, False, False])
        # If the three handlers truly overlapped, wall time is well under 3 serial sleeps.
        self.assertLess(elapsed, 0.5, f"handlers did not overlap (elapsed={elapsed:.3f}s)")
        self.assertEqual(sorted(started), ["a", "b", "c"])

    def test_mixed_batch_stays_serial_even_when_parallel_tools_set(self):
        order: list[str] = []

        def mark(payload: dict, ctx: ToolContext) -> ToolResult:
            order.append(str(payload.get("tag")))
            time.sleep(0.03)
            return ToolResult.ok(str(payload.get("tag")))

        registry = ToolRegistry()
        registry.register(
            ToolSpec(
                name="MarkRead",
                description="",
                input_schema={},
                handler=mark,
                kind="read",
                is_mutating=False,
            )
        )
        registry.register(
            ToolSpec(
                name="MarkWrite",
                description="",
                input_schema={},
                handler=mark,
                kind="edit",
                is_mutating=True,
            )
        )
        provider = self.provider(
            [
                {
                    "tools": [
                        {"name": "MarkRead", "input": {"tag": "r1"}},
                        {"name": "MarkWrite", "input": {"tag": "w1"}},
                        {"name": "MarkRead", "input": {"tag": "r2"}},
                    ]
                },
                text_turn("done"),
            ]
        )
        report = self.drive(
            self.runtime(
                provider=provider,
                tools=registry,
                parallel_tools=4,
                allowed_tools=("MarkRead", "MarkWrite"),
                max_turns=4,
            )
        )
        results = report.transcript[2].tool_results
        self.assertEqual([r.text() for r in results], ["r1", "w1", "r2"])
        # Serial order of start == finish order for a mixed batch.
        self.assertEqual(order, ["r1", "w1", "r2"])

    def test_each_call_still_crosses_the_gate_independently(self):
        registry = ToolRegistry()
        registry.register(
            ToolSpec(
                name="Peek",
                description="",
                input_schema={},
                handler=lambda p, c: ToolResult.ok("seen"),
                kind="read",
                is_mutating=False,
            )
        )
        provider = self.provider(
            [
                {
                    "tools": [
                        {"name": "Peek", "input": {}},
                        {"name": "Peek", "input": {}},
                    ]
                },
                text_turn("done"),
            ]
        )
        # Default mode + no allow-list: read tools are permitted; still two independent
        # evaluations (two reports). Parallelism must not collapse them into one gate hit.
        report = self.drive(
            self.runtime(provider=provider, tools=registry, parallel_tools=2, max_turns=4)
        )
        self.assertEqual(len(report.tool_calls), 2)
        self.assertEqual([c.name for c in report.tool_calls], ["Peek", "Peek"])
        self.assertFalse(any(c.denied for c in report.tool_calls))


if __name__ == "__main__":
    unittest.main()
