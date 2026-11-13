"""The context-engineering rules on the real dispatch and compaction paths.

B173 fable.  The unit tests in ``test_context_budget.py`` pin the rules; these
pin the *wiring*: an oversized tool result is offloaded on the way to the
provider, an old write/edit call collapses to a pointer under window
pressure, and a compaction summarises a copy whose oversized results are
already pointers (offload before summarize).

The durable transcript keeps the full bytes in every case.  A pointer is a
saving, never a loss.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from context_budget import ContextThresholds
from support import RuntimeTestCase, text_turn, tool_turn
from tools import ToolRegistry, ToolResult, ToolSpec


def huge_result(tokens: int = 30_000, marker: str = "z") -> str:
    return marker * (tokens * 4)


def registry_with_result(content: str) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="Big",
            description="returns a very large result",
            input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            handler=lambda payload, _ctx: ToolResult.ok(content),
            kind="read",
            is_mutating=False,
        )
    )
    return registry


class RealPathOffloadTests(RuntimeTestCase):
    """An oversized tool result is offloaded on the way to the provider."""

    def test_a_30k_token_tool_result_reaches_the_provider_as_a_pointer(self):
        workspace = self.workspace()
        provider = self.provider([tool_turn("Big", {}), text_turn("done")])
        runtime = self.runtime(
            provider=provider,
            workspace=workspace,
            tools=registry_with_result(huge_result()),
            allowed_tools=("Big",),
            context_thresholds=ContextThresholds(),
        )
        report = self.drive(runtime)
        blocks = provider.sent_tool_results()
        self.assertTrue(blocks, "the tool result must have reached the provider")
        content = blocks[0]["content"]
        self.assertIn("offloaded tool result", content)
        self.assertIn("Read", content)
        # The bytes are still on disk: the pointer is recoverable.
        pointer_path = content.split("written to ", 1)[1].split("]", 1)[0]
        self.assertTrue(Path(pointer_path).exists(), "the offloaded bytes must be on disk")
        self.assertGreaterEqual(len(Path(pointer_path).read_text(encoding="utf-8")), 30_000 * 4)
        # An offload is a saving, not a tax: nothing was injected, so the
        # memory tax is still zero.
        self.assertEqual(report.context["memory_tax"]["injected_tokens"], 0)

    def test_a_small_tool_result_is_not_offloaded(self):
        workspace = self.workspace()
        provider = self.provider([tool_turn("Big", {}), text_turn("done")])
        runtime = self.runtime(
            provider=provider,
            workspace=workspace,
            tools=registry_with_result("small result"),
            allowed_tools=("Big",),
            context_thresholds=ContextThresholds(),
        )
        self.drive(runtime)
        content = provider.sent_tool_results()[0]["content"]
        self.assertIn("small result", content)
        self.assertNotIn("offloaded", content)

    def test_the_rules_are_off_unless_a_host_opts_in(self):
        workspace = self.workspace()
        provider = self.provider([tool_turn("Big", {}), text_turn("done")])
        runtime = self.runtime(
            provider=provider,
            workspace=workspace,
            tools=registry_with_result(huge_result()),
            allowed_tools=("Big",),
        )
        report = self.drive(runtime)
        content = provider.sent_tool_results()[0]["content"]
        self.assertNotIn("offloaded", content)
        self.assertIsNone(report.context)


class RealPathWindowPressureTests(RuntimeTestCase):
    """Under window pressure an old write/edit call becomes a pointer."""

    def test_an_old_write_call_collapses_to_a_recoverable_pointer(self):
        workspace = self.workspace()
        provider = self.provider(
            [
                tool_turn("Write", {"path": "a.txt", "content": "y" * 4_000}),
                text_turn("done"),
            ]
        )
        runtime = self.runtime(
            provider=provider,
            workspace=workspace,
            allowed_tools=("Write",),
            can_use_tool=lambda *_args: True,
            context_thresholds=ContextThresholds(
                context_window_tokens=1_000, window_pressure_fraction=0.85
            ),
        )
        self.drive(runtime)
        request = provider.last_request()
        self.assertIsNotNone(request)
        writes = [
            block
            for message in request.messages
            for block in message.get("content", [])
            if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") == "Write"
        ]
        self.assertTrue(writes, "the write call must be in the payload")
        payload = writes[0]["input"]
        self.assertIn("reduced to a pointer", payload["content"])
        self.assertEqual(payload["pointer_path"], "a.txt")
        self.assertIn("a.txt", payload["content"])

    def test_below_the_pressure_threshold_the_write_call_is_untouched(self):
        workspace = self.workspace()
        provider = self.provider(
            [
                tool_turn("Write", {"path": "a.txt", "content": "y" * 100}),
                text_turn("done"),
            ]
        )
        runtime = self.runtime(
            provider=provider,
            workspace=workspace,
            allowed_tools=("Write",),
            can_use_tool=lambda *_args: True,
            context_thresholds=ContextThresholds(
                context_window_tokens=200_000, window_pressure_fraction=0.85
            ),
        )
        self.drive(runtime)
        request = provider.last_request()
        writes = [
            block
            for message in request.messages
            for block in message.get("content", [])
            if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") == "Write"
        ]
        self.assertEqual(writes[0]["input"]["content"], "y" * 100)


class RealPathCompactionTests(RuntimeTestCase):
    """Offload happens before the summary, and the re-read budgets apply."""

    def _drive_with_compaction(self, *, thresholds: ContextThresholds, workspace):
        provider = self.provider(
            [
                tool_turn("Big", {}),
                tool_turn("Big", {}),
                text_turn("done"),
            ]
        )
        runtime = self.runtime(
            provider=provider,
            workspace=workspace,
            tools=registry_with_result(huge_result()),
            allowed_tools=("Big",),
            compaction_threshold_tokens=600,
            compaction_keep_messages=1,
            context_thresholds=thresholds,
        )
        report = self.drive(runtime)
        return runtime, report, provider

    def test_a_compaction_offloads_before_it_summarises(self):
        """The compactor sees pointers, not the raw 30k-token result.

        Offload first means the summary is only written over content that
        offloading could not free -- the raw bytes are still on disk and
        still in the durable transcript.
        """
        workspace = self.workspace()
        runtime, report, _provider = self._drive_with_compaction(
            thresholds=ContextThresholds(), workspace=workspace
        )
        performed = [row for row in report.compactions if row.get("performed")]
        self.assertTrue(performed, "the run must have compacted")
        self.assertTrue(runtime.context_controller.offloads, "an offload must have happened")
        # The summary is written over the *offloaded* copy: it is a summary
        # of pointers, so it cannot carry 30k tokens of raw result.
        row = performed[0]
        self.assertLess(row["summary_chars"], 30_000)
        # The offload is what freed the space: the compactor's input was
        # already down to pointers before the summary was written.
        self.assertGreater(row["offload_tokens_saved"], 0)
        self.assertLess(row["tokens_after_offload"], row["tokens_before_offload"])
        # The raw bytes are still on disk and still in the durable transcript.
        offloaded = runtime.context_controller.offloads[0]
        self.assertTrue(Path(offloaded.path).exists())

    def test_after_a_compaction_a_big_file_comes_back_as_a_path_only(self):
        workspace = self.workspace({"big.txt": "q" * 40_000, "small.txt": "s" * 100})
        runtime, report, _provider = self._drive_with_compaction(
            thresholds=ContextThresholds(), workspace=workspace
        )
        controller = runtime.context_controller
        self.assertTrue(controller.compacted, "the run must have compacted")
        kinds = {record.kind for record in controller.injected}
        self.assertIn("reread", kinds)
        for record in controller.injected:
            if record.kind == "reread" and record.path.endswith("big.txt"):
                self.assertTrue(record.path_only)
                self.assertIn("Read", record.text)
            if record.kind == "reread" and record.path.endswith("small.txt"):
                self.assertFalse(record.path_only)

    def test_a_compaction_rereads_at_most_five_files(self):
        files = {f"file-{index}.txt": "x" * 100 for index in range(9)}
        workspace = self.workspace(files)
        runtime, report, _provider = self._drive_with_compaction(
            thresholds=ContextThresholds(), workspace=workspace
        )
        rereads = [record for record in runtime.context_controller.injected if record.kind == "reread"]
        self.assertLessEqual(len(rereads), 5)
        self.assertEqual(len(rereads), 5)

    def test_the_memory_tax_is_booked_and_its_ratio_is_computable(self):
        workspace = self.workspace({"big.txt": "q" * 40_000})
        runtime, report, _provider = self._drive_with_compaction(
            thresholds=ContextThresholds(), workspace=workspace
        )
        tax = report.context["memory_tax"]
        self.assertGreater(tax["injected_tokens"], 0, "the re-read must be booked")
        self.assertGreater(tax["total_input_tokens"], 0)
        self.assertGreater(tax["tax_ratio"], 0.0)
        self.assertLess(tax["tax_ratio"], 1.0)


if __name__ == "__main__":
    unittest.main()
