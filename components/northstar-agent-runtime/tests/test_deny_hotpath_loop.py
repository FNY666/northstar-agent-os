"""Tests for the loop's hot-path deny wiring (conclusion 54).

The runtime loop is where the deny lookup actually sits on the hot path:
every dispatch consults the sealed deny before the gate decides.  These
tests check that the wiring is real -- not that a dispatcher works in
isolation -- and that the host opts in explicitly.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from deny_hotpath import DenyStore
from support import RuntimeTestCase, tool_turn, text_turn
from loop import RuntimeConfigurationError
from tools import ToolRegistry, ToolResult, ToolSpec


class DenyStoreWiringTests(RuntimeTestCase):
    """The deny store is opt-in, and it refuses the run when it cannot open."""

    def test_the_deny_store_is_off_by_default(self):
        runtime = self.runtime(provider=self.provider([text_turn("done")]))
        self.assertIsNone(runtime.deny_dispatcher)
        self.assertIsNone(runtime.deny_store)

    def test_opting_in_wires_a_dispatcher(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "deny.sqlite3")
            runtime = self.runtime(
                provider=self.provider([text_turn("done")]),
                deny_store_path=path,
            )
            self.assertIsNotNone(runtime.deny_dispatcher)
            runtime.deny_store.close()

    def test_an_unopenable_deny_store_refuses_the_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            # A directory is not a database file: opening it must fail.
            path = str(Path(tmp) / "not-a-db")
            Path(path).mkdir()
            with self.assertRaises(RuntimeConfigurationError):
                self.runtime(
                    provider=self.provider([text_turn("done")]),
                    deny_store_path=path,
                )

    def test_a_non_string_deny_store_path_is_refused(self):
        with self.assertRaises(RuntimeConfigurationError):
            self.runtime(
                provider=self.provider([text_turn("done")]),
                deny_store_path=123,
            )


class DenyDispatchTests(RuntimeTestCase):
    """A revoked scope never reaches the handler."""

    def _registry(self, effects: list) -> ToolRegistry:
        registry = ToolRegistry()
        registry.register(
            ToolSpec(
                name="Lookup",
                description="read-only lookup",
                input_schema={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "additionalProperties": False,
                },
                handler=lambda payload, _ctx: effects.append(payload)
                or ToolResult.ok("looked up"),
                kind="read",
                is_mutating=False,
            )
        )
        return registry

    def test_a_revoked_scope_blocks_the_tool_call(self):
        effects: list = []
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "deny.sqlite3")
            store = DenyStore(path)
            store.revoke("main/Lookup", reason="operator revoked")
            store.close()
            runtime = self.runtime(
                provider=self.provider([
                    tool_turn("Lookup", {"query": "x"}),
                    text_turn("done"),
                ]),
                tools=self._registry(effects),
                can_use_tool=lambda *_args: True,
                allowed_tools=("Lookup",),
                deny_store_path=path,
            )
            report = self.drive(runtime)
            runtime.deny_store.close()
        self.assertEqual(effects, [], "a revoked scope must not run the handler")
        self.assertTrue(report.tool_calls)
        self.assertTrue(report.tool_calls[0].denied)

    def test_an_unrevoked_scope_still_runs_the_tool(self):
        effects: list = []
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "deny.sqlite3")
            runtime = self.runtime(
                provider=self.provider([
                    tool_turn("Lookup", {"query": "x"}),
                    text_turn("done"),
                ]),
                tools=self._registry(effects),
                can_use_tool=lambda *_args: True,
                allowed_tools=("Lookup",),
                deny_store_path=path,
            )
            report = self.drive(runtime)
            runtime.deny_store.close()
        self.assertEqual(effects, [{"query": "x"}])
        self.assertTrue(report.tool_calls)
        self.assertFalse(report.tool_calls[0].denied)

    def test_the_parallel_dispatch_path_also_refuses_a_revoked_scope(self):
        """The parallel batch runs the same governed path, so the deny
        applies there too -- a second code path must not skip the check."""
        effects: list = []
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "deny.sqlite3")
            store = DenyStore(path)
            store.revoke("main/Lookup", reason="operator revoked")
            store.close()
            runtime = self.runtime(
                provider=self.provider([
                    # One turn with two tool calls: the batch is parallel-safe
                    # (both are reads), so this really takes the parallel path.
                    {"tools": [
                        {"name": "Lookup", "input": {"query": "x"}},
                        {"name": "Lookup", "input": {"query": "y"}},
                    ]},
                    text_turn("done"),
                ]),
                tools=self._registry(effects),
                can_use_tool=lambda *_args: True,
                allowed_tools=("Lookup",),
                parallel_tools=2,
                deny_store_path=path,
            )
            report = self.drive(runtime)
            refusal_count = runtime.deny_store.refusal_count()
            runtime.deny_store.close()
        self.assertEqual(effects, [], "a revoked scope must not run the handler")
        self.assertTrue(report.tool_calls)
        self.assertTrue(all(call.denied for call in report.tool_calls))
        self.assertEqual(refusal_count, 2, "every dispatch left a refusal row")

    def test_the_dispatch_path_leaves_a_refusal_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "deny.sqlite3")
            runtime = self.runtime(
                provider=self.provider([
                    tool_turn("Lookup", {"query": "x"}),
                    text_turn("done"),
                ]),
                tools=self._registry([]),
                can_use_tool=lambda *_args: True,
                allowed_tools=("Lookup",),
                deny_store_path=path,
            )
            self.drive(runtime)
            rows = runtime.deny_store.refusals()
            runtime.deny_store.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["scope"], "main/Lookup")
        self.assertEqual(rows[0]["outcome"], "allowed")
