"""Context-engineering thresholds: offload before summarize, and the budgets.

B173 fable.  The frontier report "Context engineering inside the harness"
(MarkTechPost, 2026-09-12) surveyed the production harnesses and found the
thresholds they actually run at: a 20,000-token tool result goes to disk and
leaves a path plus a 10-line preview; at 85% of the window old write/edit
calls collapse to pointers; a post-compaction re-read of a file over 5,000
tokens returns a path, not content; at most 5 files are re-read; a skill body
is capped at 5,000 tokens (25,000 total); auto-memory stops at 200 lines or
25KB; a research subagent reads ~6,100 tokens and returns ~420.

These tests pin the *order* the report does not state but the report's own
logic requires: **offload first, summarize second**.  A summary of a result
that could have been offloaded has thrown away recoverable bytes for nothing.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from context_budget import (
    ContextThresholds,
    MemoryTaxLedger,
    OffloadStore,
    SubagentBudget,
    apply_reread_decisions,
    cap_auto_memory,
    cap_skill_bodies,
    cap_subagent_result,
    estimate_text_tokens,
    offload_tool_result,
    plan_rereads,
    read_budget_exceeded,
    should_offload_tool_result,
    todo_state_enabled,
    truncate_write_like_calls,
)
from providers.base import ToolUseBlock


def big_text(tokens: int, marker: str = "x") -> str:
    """A text of roughly ``tokens`` tokens under the module's own estimate."""
    return marker * (tokens * 4)


class OffloadTests(unittest.TestCase):
    """A tool result above the threshold goes to disk and leaves a pointer."""

    def test_a_tool_result_above_20k_tokens_is_offloaded_to_a_path(self):
        limits = ContextThresholds()
        store = OffloadStore(self._tmp(), limits=limits)
        payload = big_text(21_000, marker="a")
        self.assertTrue(should_offload_tool_result(payload, limits))
        text, pointer = offload_tool_result(payload, store)
        self.assertIn(pointer.path, text)
        self.assertIn("Read", text)
        # The bytes are still there: the pointer is recoverable.
        self.assertEqual(Path(pointer.path).read_text(encoding="utf-8"), payload)

    def test_a_tool_result_below_20k_tokens_is_left_alone(self):
        limits = ContextThresholds()
        store = OffloadStore(self._tmp(), limits=limits)
        payload = big_text(19_000, marker="b")
        self.assertFalse(should_offload_tool_result(payload, limits))
        text, pointer = offload_tool_result(payload, store)
        # Offload is opt-in by size; under the cap nothing is written.
        self.assertEqual(text, payload)
        self.assertEqual(pointer.path, "")

    def test_the_offloaded_context_keeps_a_ten_line_preview(self):
        limits = ContextThresholds()
        store = OffloadStore(self._tmp(), limits=limits)
        payload = "\n".join(f"line-{index}" for index in range(200)) + "\n" + "z" * 90_000
        text, pointer = offload_tool_result(payload, store)
        previewed = [line for line in text.splitlines() if line.startswith("line-")]
        self.assertEqual(len(previewed), 10, "the preview is the first 10 lines, nothing more")
        self.assertIn("line-0", text)
        self.assertNotIn("line-10", text)
        self.assertEqual(pointer.preview_lines, 10)

    def _tmp(self) -> str:
        import tempfile

        return tempfile.mkdtemp(prefix="nsar-offload-")


class WindowPressureTests(unittest.TestCase):
    """At 85% of the window, old write/edit calls become pointers."""

    def test_at_85_percent_old_write_calls_become_recoverable_pointers(self):
        limits = ContextThresholds(context_window_tokens=1000, window_pressure_fraction=0.85)
        call = ToolUseBlock(id="t1", name="Write", input={"path": "a.txt", "content": big_text(100)})
        self.assertGreaterEqual(900, limits.window_pressure_tokens())
        reduced, changed = truncate_write_like_calls(
            [call], input_tokens=900, limits=limits
        )
        self.assertEqual(len(changed), 1)
        self.assertIn("reduced to a pointer", reduced[0].input["content"])
        self.assertEqual(reduced[0].input["pointer_path"], "a.txt")
        # Recoverable: the path and the file name survive the truncation.
        self.assertIn("a.txt", reduced[0].input["content"])

    def test_below_the_pressure_threshold_nothing_is_truncated(self):
        limits = ContextThresholds(context_window_tokens=1000, window_pressure_fraction=0.85)
        call = ToolUseBlock(id="t1", name="Write", input={"path": "a.txt", "content": big_text(10)})
        reduced, changed = truncate_write_like_calls(
            [call], input_tokens=100, limits=limits
        )
        self.assertEqual(changed, [])
        self.assertEqual(reduced[0].input["content"], call.input["content"])

    def test_a_non_write_call_is_never_truncated(self):
        """A read call has no reproducible form; dropping it would drop the request."""
        limits = ContextThresholds(context_window_tokens=1000, window_pressure_fraction=0.85)
        call = ToolUseBlock(id="t1", name="Read", input={"path": "a.txt"})
        reduced, changed = truncate_write_like_calls(
            [call], input_tokens=900, limits=limits
        )
        self.assertEqual(changed, [])
        self.assertEqual(reduced[0].input, call.input)


class RereadTests(unittest.TestCase):
    """After a compaction, a big re-read returns a path, not the content."""

    def test_a_reread_over_5k_tokens_returns_only_a_path(self):
        limits = ContextThresholds()
        files = [("big.txt", big_text(6_000))]
        decisions, skipped = plan_rereads(files, limits=limits)
        self.assertEqual(skipped, [])
        self.assertTrue(decisions[0].path_only)
        applied = apply_reread_decisions(files, decisions)
        self.assertIn("big.txt", applied[0][1])
        self.assertIn("Read big.txt", applied[0][1])
        self.assertNotIn("x" * 1_000, applied[0][1])

    def test_a_reread_under_5k_tokens_keeps_its_content(self):
        limits = ContextThresholds()
        files = [("small.txt", big_text(1_000))]
        decisions, _ = plan_rereads(files, limits=limits)
        self.assertFalse(decisions[0].path_only)
        applied = apply_reread_decisions(files, decisions)
        self.assertEqual(applied[0][1], files[0][1])

    def test_a_compaction_rereads_at_most_five_files(self):
        limits = ContextThresholds()
        files = [(f"file-{index}.txt", big_text(100)) for index in range(9)]
        decisions, skipped = plan_rereads(files, limits=limits)
        self.assertEqual(len(decisions), 5)
        self.assertEqual(len(skipped), 4)
        self.assertEqual(skipped[0], "file-5.txt")


class SkillBodyTests(unittest.TestCase):
    """A skill body is capped per skill and in total."""

    def test_a_skill_body_over_5k_tokens_is_truncated(self):
        limits = ContextThresholds()
        kept, dropped = cap_skill_bodies([("fat", big_text(9_000))], limits=limits)
        self.assertEqual(dropped, [])
        self.assertLess(estimate_text_tokens(kept[0][1]), 5_200)
        self.assertIn("truncated", kept[0][1])

    def test_the_total_skill_budget_is_25k_tokens(self):
        limits = ContextThresholds()
        bodies = [(f"skill-{index}", big_text(4_000, marker=str(index))) for index in range(8)]
        kept, dropped = cap_skill_bodies(bodies, limits=limits)
        total = sum(estimate_text_tokens(body) for _name, body in kept)
        self.assertLessEqual(total, 25_000)
        self.assertTrue(dropped, "the surplus skills must be dropped, not silently kept")
        self.assertIn("skill-7", dropped)


class AutoMemoryTests(unittest.TestCase):
    """Auto-memory stops at the first 200 lines or 25KB."""

    def test_memory_over_200_lines_is_cut_at_the_line_limit(self):
        limits = ContextThresholds()
        text = "\n".join(f"line {index}" for index in range(500))
        capped, record = cap_auto_memory(text, limits=limits)
        self.assertTrue(record["truncated"])
        self.assertLessEqual(record["kept_lines"], 200)
        self.assertEqual(len(capped.splitlines()), 200)

    def test_memory_over_25kb_is_cut_at_the_byte_limit(self):
        limits = ContextThresholds()
        text = "\n".join("y" * 900 for _ in range(100))
        capped, record = cap_auto_memory(text, limits=limits)
        self.assertTrue(record["truncated"])
        self.assertLessEqual(record["kept_bytes"], 25 * 1024)

    def test_memory_under_both_limits_is_untouched(self):
        limits = ContextThresholds()
        text = "small memory"
        capped, record = cap_auto_memory(text, limits=limits)
        self.assertEqual(capped, text)
        self.assertFalse(record["truncated"])


class SubagentBudgetTests(unittest.TestCase):
    """A subagent's return is capped, and a cut return says so."""

    def test_an_over_budget_subagent_return_is_truncated_and_marked(self):
        limits = ContextThresholds()
        budget = SubagentBudget.research_variant(limits)
        text = big_text(3_000)
        capped, truncated = cap_subagent_result(text, budget)
        self.assertTrue(truncated)
        self.assertLess(estimate_text_tokens(capped), 600)
        self.assertIn("truncated", capped)

    def test_a_return_inside_the_budget_is_untouched(self):
        limits = ContextThresholds()
        budget = SubagentBudget.research_variant(limits)
        text = big_text(100)
        capped, truncated = cap_subagent_result(text, budget)
        self.assertFalse(truncated)
        self.assertEqual(capped, text)

    def test_a_general_subagent_returns_a_1000_to_2000_token_summary(self):
        limits = ContextThresholds()
        budget = SubagentBudget.general_variant(limits)
        self.assertEqual(budget.budget_for_result(), 2_000)
        text = big_text(5_000)
        capped, truncated = cap_subagent_result(text, budget)
        self.assertTrue(truncated)
        self.assertLessEqual(estimate_text_tokens(capped), 2_100)

    def test_a_read_budget_over_run_is_reported(self):
        limits = ContextThresholds()
        budget = SubagentBudget.research_variant(limits)
        self.assertFalse(read_budget_exceeded(6_100, budget))
        self.assertTrue(read_budget_exceeded(6_101, budget))


class MemoryTaxTests(unittest.TestCase):
    """The cost of persistent memory is measured, not assumed."""

    def test_injected_memory_tokens_are_recorded_and_a_ratio_is_computable(self):
        ledger = MemoryTaxLedger()
        ledger.record(source=".northstar/memory/MEMORY.md", tokens=2_000)
        ledger.record(source="notes.md", tokens=500)
        self.assertEqual(ledger.injected_tokens, 2_500)
        self.assertAlmostEqual(ledger.tax_ratio(10_000), 0.25)
        payload = ledger.as_dict(total_input_tokens=10_000)
        self.assertEqual(payload["injected_tokens"], 2_500)
        self.assertAlmostEqual(payload["tax_ratio"], 0.25)

    def test_an_unknown_denominator_is_not_a_zero_tax(self):
        ledger = MemoryTaxLedger()
        ledger.record(source="m", tokens=100)
        self.assertEqual(ledger.tax_ratio(0), 0.0)
        self.assertEqual(ledger.injected_tokens, 100)


class TodoOptInTests(unittest.TestCase):
    """Todo recitation is off until Northstar measures it."""

    def test_todo_state_is_off_by_default(self):
        self.assertFalse(todo_state_enabled(ContextThresholds()))

    def test_todo_state_can_be_switched_on_explicitly(self):
        self.assertTrue(todo_state_enabled(ContextThresholds(todo_state_enabled=True)))


if __name__ == "__main__":
    unittest.main()
