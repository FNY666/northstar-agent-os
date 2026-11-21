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

import random
import re
import sys
import types
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


class ContextGuardSecondHalfTests(unittest.TestCase):
    """The SECOND half of each context-budget guard.

    Every guard here is a double guard: a TYPE half joined to a second
    half -- a POSITIVITY half, a RANGE half, a DEFAULTING half, a
    CHARACTER-SET half -- by `or` or `and`.  The fable slice's own suite
    drove only ONE half of each, so flipping the connective left the
    suite green: the planted faults or@82, or@90, lt@92, gt@144, or@241,
    or@246, or@247 and gt@291 all SURVIVED it.

      or@82    isinstance(value, bool) or not isinstance(value, int)
               The second half is the POSITIVITY half: a valid int that
               is zero or negative must still be refused.
      or@90    isinstance(value, bool) or not isinstance(value, (int, float))
               The same for a fraction: a number outside (0, 1] must be
               refused.
      lt@92    not 0 < float(value) <= 1
               The RANGE half: zero must be refused and one accepted.
      gt@144   subagent_summary_min_tokens > subagent_summary_max_tokens
               The bound half: the two summary budgets must be ordered.
      or@241   limits or ContextThresholds()
               The DEFAULTING half: an explicitly supplied limits object
               must be USED, not replaced by a default.
      or@246   character.isalnum() or character in "-_."
               The CHARACTER-SET half: the other characters of the
               allowed set must survive the safe-name mapping.
      or@247   safe.strip("._") or "tool-result"
               The DEFAULTING half: a name that reduces to nothing must
               fall back to the default, not become an empty path stem.
      gt@291   estimate_text_tokens(text) > tool_result_offload_tokens
               The bound half: a result exactly AT the cap must NOT be
               offloaded.

    Each test here fails when its planted fault is applied alone.
    """

    def test_a_zero_token_threshold_is_refused(self):
        """`or@82`: the POSITIVITY half of the int guard.

        Zero is an int, so the type half passes it; the positivity half
        is what refuses it.
        """
        with self.assertRaises(ValueError):
            ContextThresholds(tool_result_offload_tokens=0)

    def test_a_negative_token_threshold_is_refused(self):
        """`or@82`: the positivity half, from the other side."""
        with self.assertRaises(ValueError):
            ContextThresholds(tool_result_offload_tokens=-1)

    def test_a_positive_token_threshold_is_accepted(self):
        """`or@82`: the control."""
        self.assertEqual(ContextThresholds(tool_result_offload_tokens=7).tool_result_offload_tokens, 7)

    def test_a_boolean_token_threshold_is_refused(self):
        """`or@82`: the BOOLEAN half, and the one the mutant hides.

        `isinstance(value, bool) or not isinstance(value, int)` -- a bool
        IS an int in Python, so the two halves say different things.  With
        the connective flipped to `and`, a boolean would satisfy "is a
        bool" AND "is not an int" only if it were not an int -- and it
        is -- so the guard would wave a boolean through and store it as
        a threshold.
        """
        with self.assertRaises(ValueError):
            ContextThresholds(tool_result_offload_tokens=True)

    def test_a_boolean_fraction_is_refused(self):
        """`or@90`: the BOOLEAN half of the fraction guard.

        `isinstance(value, bool) or not isinstance(value, (int, float))`
        -- the same shape.  A boolean fraction would be waved through
        with the connective flipped, and `float(True)` is 1.0, so it
        would silently become a valid threshold.
        """
        with self.assertRaises(ValueError):
            ContextThresholds(window_pressure_fraction=True)

    def test_a_zero_fraction_is_refused(self):
        """`or@90` / `lt@92`: the RANGE half of the fraction guard.

        Zero is a number, so the type half passes it; the range half is
        what refuses it.  With `lt -> le` the guard would accept 0.
        """
        with self.assertRaises(ValueError):
            ContextThresholds(window_pressure_fraction=0)

    def test_a_fraction_above_one_is_refused(self):
        """`or@90`: the range half, from the other side."""
        with self.assertRaises(ValueError):
            ContextThresholds(window_pressure_fraction=1.5)

    def test_a_fraction_of_exactly_one_is_accepted(self):
        """`lt@92`: the upper edge is INSIDE the range."""
        self.assertEqual(ContextThresholds(window_pressure_fraction=1.0).window_pressure_fraction, 1.0)

    def test_a_fraction_just_above_zero_is_accepted(self):
        """`lt@92`: the lower edge is OUTSIDE the range, but only just.

        A fraction of 0.001 is inside (0, 1] and must be accepted -- the
        guard is a strict lower bound.
        """
        self.assertEqual(ContextThresholds(window_pressure_fraction=0.001).window_pressure_fraction, 0.001)

    def test_summary_min_may_equal_summary_max(self):
        """`gt@144`: the bound half, at the equal point.

        The rule is "must not exceed", so equal budgets are legal.  With
        `> -> >=` they would be refused.
        """
        thresholds = ContextThresholds(subagent_summary_min_tokens=100, subagent_summary_max_tokens=100)
        self.assertEqual(thresholds.subagent_summary_min_tokens, 100)

    def test_summary_min_may_not_exceed_summary_max(self):
        """`gt@144`: the bound half, from the other side."""
        with self.assertRaises(ValueError):
            ContextThresholds(subagent_summary_min_tokens=101, subagent_summary_max_tokens=100)

    def test_an_explicit_limits_object_is_used(self):
        """`or@241`: the DEFAULTING half.

        The store must keep the limits it was given.  With the
        connective flipped to `and`, an explicitly supplied object would
        be replaced by a fresh default -- and the caller would never
        know its thresholds were ignored.
        """
        import tempfile

        limits = ContextThresholds(tool_result_offload_tokens=1234)
        with tempfile.TemporaryDirectory() as workspace:
            store = OffloadStore(workspace, limits=limits)
            self.assertEqual(store.limits.tool_result_offload_tokens, 1234)

    def test_a_store_without_limits_uses_the_defaults(self):
        """`or@241`: the control -- no limits means the defaults."""
        import tempfile

        with tempfile.TemporaryDirectory() as workspace:
            store = OffloadStore(workspace)
            self.assertEqual(store.limits.tool_result_offload_tokens, ContextThresholds().tool_result_offload_tokens)

    def test_the_allowed_character_set_survives_the_safe_name(self):
        """`or@246`: the CHARACTER-SET half.

        The safe-name mapping keeps alphanumerics and the characters
        "-_." and replaces everything else with "_".  The suite drove
        only the alphanumeric half, so a name spelled with "-" or "_"
        was never exercised: flipping the connective would replace
        those too.
        """
        import tempfile

        with tempfile.TemporaryDirectory() as workspace:
            store = OffloadStore(workspace)
            path = store.path_for(name="a-b_c.d")
            self.assertTrue(path.name.startswith("a-b_c.d-"), path.name)

    def test_a_name_that_reduces_to_nothing_falls_back(self):
        """`or@247`: the DEFAULTING half of the safe-name guard.

        A name made only of "." and "_" is stripped to nothing, so the
        default "tool-result" must take over.  With the connective
        flipped to `and`, the stem would be empty and the path would
        lose its name.
        """
        import tempfile

        with tempfile.TemporaryDirectory() as workspace:
            store = OffloadStore(workspace)
            path = store.path_for(name="._")
            self.assertTrue(path.name.startswith("tool-result-"), path.name)

    def test_a_tool_result_exactly_at_the_cap_is_not_offloaded(self):
        """`gt@291`: the bound half, at the exact cap.

        The rule is "strictly bigger than the cap", so a result whose
        estimate is exactly the cap must NOT be offloaded.  With
        `> -> >=` it would be.  The estimate is one token per four
        bytes, so 40 bytes is exactly 10 tokens -- the cap here.
        """
        limits = ContextThresholds(tool_result_offload_tokens=10)
        text = "x" * 40
        self.assertEqual(estimate_text_tokens(text), 10)
        self.assertFalse(should_offload_tool_result(text, limits))

    def test_a_tool_result_one_token_over_the_cap_is_offloaded(self):
        """`gt@291`: the bound half, from the other side."""
        limits = ContextThresholds(tool_result_offload_tokens=10)
        text = "x" * 44  # exactly 11 tokens
        self.assertEqual(estimate_text_tokens(text), 11)
        self.assertTrue(should_offload_tool_result(text, limits))


if __name__ == "__main__":
    unittest.main()


class ContextBudgetSecondHalfTests(unittest.TestCase):
    """The second half of each guard in the context-budget module.

    Every surviving mutant here is one arm of a two-armed conditional or
    one half of a conjunction, and the rest of the suite drove only the
    other half.  These tests drive the missing half.
    """

    def _pressured_limits(self) -> ContextThresholds:
        return ContextThresholds(context_window_tokens=1000, window_pressure_fraction=0.85)

    # -- or@386: the "and the payload is a mapping" half ---------------

    def test_a_write_call_with_a_non_mapping_payload_is_not_truncated(self):
        """`or@386`: the payload half of the write-call guard.

        The suite drove the tool-name half (a Read call is never
        truncated).  A WRITE-like call whose payload is not a mapping has
        no content to reduce, so it is left alone.
        """
        limits = self._pressured_limits()
        call = ToolUseBlock(id="t1", name="Write", input="not a mapping")
        reduced, changed = truncate_write_like_calls(
            [call], input_tokens=900, limits=limits
        )
        self.assertEqual(changed, [])
        self.assertEqual(reduced[0].input, call.input)

    # -- or@390: the "and the content is non-empty" half ----------------

    def test_a_write_call_with_empty_content_is_not_truncated(self):
        """`or@390`: the content half of the write-call guard.

        An empty content string has no tokens to save, so the call is
        left alone rather than replaced by a pointer.
        """
        limits = self._pressured_limits()
        call = ToolUseBlock(id="t1", name="Write", input={"path": "a.txt", "content": ""})
        reduced, changed = truncate_write_like_calls(
            [call], input_tokens=900, limits=limits
        )
        self.assertEqual(changed, [])
        self.assertEqual(reduced[0].input["content"], "")

    def test_a_write_call_with_a_non_string_content_is_not_truncated(self):
        """`or@390`: the type half of the content guard."""
        limits = self._pressured_limits()
        call = ToolUseBlock(id="t1", name="Write", input={"path": "a.txt", "content": 42})
        reduced, changed = truncate_write_like_calls(
            [call], input_tokens=900, limits=limits
        )
        self.assertEqual(changed, [])
        self.assertEqual(reduced[0].input["content"], 42)

    # -- gt@487: the strictness of the path-only threshold --------------

    def test_a_reread_at_exactly_the_threshold_keeps_its_content(self):
        """`gt@487`: the lower edge of the path-only band.

        The band is ``tokens > threshold``: a file AT the threshold keeps
        its content.  A mutant that turns ``>`` into ``>=`` would strip
        this file's content, and this test says it does not.
        """
        limits = ContextThresholds(reread_path_only_tokens=100)
        content = "x" * (100 * 4)
        self.assertEqual(estimate_text_tokens(content), 100)
        decisions, skipped = plan_rereads([("a.txt", content)], limits=limits)
        self.assertEqual(decisions[0].tokens, 100)
        self.assertFalse(decisions[0].path_only)
        self.assertEqual(skipped, [])

    def test_a_reread_one_token_over_the_threshold_is_path_only(self):
        """`gt@487`: inside the band -- one token over is path-only."""
        limits = ContextThresholds(reread_path_only_tokens=100)
        content = "x" * (101 * 4)
        decisions, _skipped = plan_rereads([("a.txt", content)], limits=limits)
        self.assertTrue(decisions[0].path_only)

    # -- gt@530 / gt@533: the skill-body cap's edges --------------------

    def test_a_skill_body_at_exactly_the_cap_is_not_truncated(self):
        """`gt@530`: the lower edge of the per-skill cap.

        The cap is ``tokens > max``: a body AT the cap is kept whole.
        A mutant that turns ``>`` into ``>=`` truncates it, and this
        test says it must not.
        """
        limits = ContextThresholds(skill_body_max_tokens=100)
        body = "x" * (100 * 4)
        kept, dropped = cap_skill_bodies([("s", body)], limits=limits)
        self.assertEqual(dropped, [])
        self.assertEqual(kept[0][1], body)
        self.assertNotIn("truncated", kept[0][1])

    def test_a_skill_body_one_token_over_the_cap_is_truncated(self):
        """`gt@530`: inside the cap band -- one token over is truncated."""
        limits = ContextThresholds(skill_body_max_tokens=100)
        body = "x" * (101 * 4)
        kept, dropped = cap_skill_bodies([("s", body)], limits=limits)
        self.assertEqual(dropped, [])
        self.assertIn("truncated", kept[0][1])

    def test_a_skill_body_at_exactly_the_total_cap_is_kept(self):
        """`gt@533`: the lower edge of the total budget.

        The total is ``spent + tokens > total_max``: a body that brings
        the running total exactly TO the cap is still kept.
        """
        limits = ContextThresholds(
            skill_body_max_tokens=1_000,
            skill_body_total_max_tokens=100,
        )
        body = "x" * (100 * 4)
        kept, dropped = cap_skill_bodies([("s", body)], limits=limits)
        self.assertEqual(dropped, [])
        self.assertEqual(len(kept), 1)

    def test_a_skill_body_one_token_over_the_total_cap_is_dropped(self):
        """`gt@533`: inside the budget band -- one token over is dropped."""
        limits = ContextThresholds(
            skill_body_max_tokens=1_000,
            skill_body_total_max_tokens=100,
        )
        body = "x" * (101 * 4)
        kept, dropped = cap_skill_bodies([("s", body)], limits=limits)
        self.assertEqual(kept, [])
        self.assertEqual(dropped, ["s"])

    # -- lt@579: the byte cap of auto-memory ---------------------------

    def test_auto_memory_at_exactly_the_byte_limit_is_not_cut(self):
        """`lt@579`: the lower edge of the byte cap.

        The byte cap is ``bytes_kept < body_bytes``: a body of exactly
        the cap is kept whole.  A mutant that turns ``<`` into ``<=``
        cuts it, and this test says it must not.
        """
        limits = ContextThresholds(auto_memory_max_bytes=100)
        text = "y" * 100
        capped, record = cap_auto_memory(text, limits=limits)
        self.assertEqual(capped, text)
        self.assertFalse(record["truncated"])
        self.assertEqual(record["kept_bytes"], 100)

    def test_auto_memory_one_byte_over_the_limit_is_cut(self):
        """`lt@579`: inside the cap band -- one byte over is cut."""
        limits = ContextThresholds(auto_memory_max_bytes=100)
        text = "y" * 101
        capped, record = cap_auto_memory(text, limits=limits)
        self.assertEqual(len(capped.encode("utf-8")), 100)
        self.assertTrue(record["truncated"])

    def test_auto_memory_at_the_byte_limit_is_byte_identical(self):
        """`lt@579`: an EQUIVALENT mutant, recorded.

        The planted fault at this site (``<`` -> ``<=``) is an
        EQUIVALENT mutant, and provably so:

        * ``bytes_kept = min(body_bytes, auto_memory_max_bytes)``, so
          ``bytes_kept == body_bytes`` exactly when the body already
          fits the byte cap;
        * under the mutant the cut branch runs one extra time in that
          case, but the cut is
          ``body.encode("utf-8")[:bytes_kept].decode("utf-8", ...)``
          with ``bytes_kept == len(body.encode("utf-8"))`` -- slicing
          a string to exactly its own length is the IDENTITY, and the
          re-decode of well-formed UTF-8 is the identity too;
        * the mutant branch also assigns ``body_bytes = bytes_kept``,
          which is the value it already had.

        So at ``bytes_kept == body_bytes`` the two versions agree
        exactly, and the ``truncated`` flag is computed from
        ``bytes_kept`` and ``bytes_total``, neither of which the mutant
        touches.  It is an EQUIVALENT mutant, not a gap in the suite,
        and no test can distinguish it.  It is recorded here so the
        next person does not spend a round looking for one.

        This test pins the behaviour the equivalence depends on: a body
        that fits the byte cap comes back BYTE-IDENTICAL, including
        multibyte UTF-8.
        """
        limits = ContextThresholds(auto_memory_max_bytes=100)
        for text in ("y" * 100, "é" * 50, "a\nb", "漢" * 25):
            capped, record = cap_auto_memory(text, limits=limits)
            self.assertEqual(capped, text)
            self.assertEqual(len(capped.encode("utf-8")), len(text.encode("utf-8")))
            self.assertFalse(record["truncated"])

    # -- or@686: the type half of the memory-tax source guard ----------

    def test_a_non_string_source_is_refused(self):
        """`or@686`: the type half of the source guard."""
        ledger = MemoryTaxLedger()
        with self.assertRaises(ValueError) as ctx:
            ledger.record(source=42, tokens=10)
        self.assertIn("source must be a non-empty string", str(ctx.exception))

    def test_an_empty_source_is_refused(self):
        """`or@686`: the emptiness half of the source guard."""
        ledger = MemoryTaxLedger()
        with self.assertRaises(ValueError):
            ledger.record(source="", tokens=10)

    # -- lt@688: the sign of the memory-tax token count ----------------

    def test_a_negative_token_count_is_refused(self):
        """`lt@688`: the sign half of the token-count guard."""
        ledger = MemoryTaxLedger()
        with self.assertRaises(ValueError) as ctx:
            ledger.record(source="m", tokens=-1)
        self.assertIn("tokens must be a non-negative int", str(ctx.exception))

    def test_a_zero_token_count_is_allowed(self):
        """`lt@688`: the boundary -- zero tokens is not a negative count."""
        ledger = MemoryTaxLedger()
        self.assertEqual(ledger.record(source="m", tokens=0), 0)
        self.assertEqual(ledger.injected_tokens, 0)

    def test_a_boolean_token_count_is_refused(self):
        """`or@688`: the type half of the token-count guard, on a bool.

        A bool IS an int in Python, so only the isinstance(..., bool)
        half can catch it.
        """
        ledger = MemoryTaxLedger()
        with self.assertRaises(ValueError):
            ledger.record(source="m", tokens=True)

    def test_a_float_token_count_is_refused(self):
        """`or@688`: the other type half -- a float is not an int."""
        ledger = MemoryTaxLedger()
        with self.assertRaises(ValueError):
            ledger.record(source="m", tokens=10.0)


class AutoMemoryByteCapEquivalentMutantTests(unittest.TestCase):
    """``lt@579``: the auto-memory byte cap -- an EQUIVALENT mutant.

    The planted fault at this site (``<`` -> ``<=``) survives the slice's
    suite, and it is **not killable, and provably so**.

    The site is inside ``cap_auto_memory``::

        bytes_kept = min(body_bytes, limits.auto_memory_max_bytes)
        if bytes_kept < body_bytes:
            body = body.encode("utf-8")[:bytes_kept].decode("utf-8", errors="ignore")
            body_bytes = bytes_kept

    The mutant turns the bound into ``<=``, so the cut branch runs one
    extra time -- at ``bytes_kept == body_bytes`` exactly.

    That extra run is a no-op, because:

    * ``bytes_kept = min(body_bytes, auto_memory_max_bytes)``, so
      ``bytes_kept == body_bytes`` exactly when the body already fits
      the byte cap;
    * under the mutant the cut is
      ``body.encode("utf-8")[:bytes_kept].decode("utf-8", errors="ignore")``
      with ``bytes_kept == len(body.encode("utf-8"))`` -- slicing a
      string to exactly its own length is the IDENTITY, and re-decoding
      well-formed UTF-8 is the identity too;
    * the mutant branch also assigns ``body_bytes = bytes_kept``, which
      is the value it already had.

    The ``truncated`` flag is computed from ``lines_kept`` and
    ``bytes_kept`` against ``bytes_total``, none of which the mutant
    touches.  So the two versions agree at every input.

    This class PROVES that by differential testing: it loads the module
    twice -- once as it is, once with the bound mutated -- and compares
    the two across a randomised sweep of line counts, byte limits and
    multibyte contents.  A single behavioural difference anywhere in the
    sweep fails the test.

    It is an EQUIVALENT mutant, not a gap in the suite, and no test can
    distinguish it.  It is recorded here so the next person does not
    spend a round looking for one.
    """

    #: The exact source line the mutation targets.
    _BOUND_RE = re.compile(r"if bytes_kept (?P<op>[<>]=?) body_bytes:")

    def _load_with_bound(self, op: str):
        """Load ``context_budget`` with the byte-cap bound set to ``op``.

        The module is re-executed from its own source with the one
        comparison rewritten, in a fresh module object, so the two
        versions coexist in one process and can be called side by side.
        """
        import context_budget

        source = Path(context_budget.__file__).read_text(encoding="utf-8")
        matches = self._BOUND_RE.findall(source)
        self.assertEqual(
            len(matches), 1, f"expected exactly one byte cap, found {matches}"
        )
        mutated = self._BOUND_RE.sub(
            f"if bytes_kept {op} body_bytes:", source, count=1
        )
        name = f"_context_budget_bound_{op.replace('<', 'lt').replace('>', 'gt')}"
        module = types.ModuleType(name)
        module.__file__ = str(Path(context_budget.__file__))
        sys.modules[name] = module
        exec(compile(mutated, module.__file__, "exec"), module.__dict__)
        return module

    def _cap(self, module, text: str, max_lines: int, max_bytes: int):
        limits = module.ContextThresholds(
            auto_memory_max_lines=max_lines, auto_memory_max_bytes=max_bytes
        )
        body, record = module.cap_auto_memory(text, limits=limits)
        # The record is a dict, so it compares by value; the body is a str.
        return (body, tuple(sorted(record.items())))

    # -- the proof -------------------------------------------------------

    def test_the_mutated_bound_behaves_identically_across_a_sweep(self):
        """``lt@579``: the differential proof of equivalence.

        The sweep is randomised but seeded, so a failure is
        reproducible.  It covers ASCII and multibyte content, bodies
        under and over both the line cap and the byte cap, and bodies
        exactly AT the byte cap -- the boundary the mutant reaches.
        """
        original = self._load_with_bound("<")
        mutant = self._load_with_bound("<=")

        rng = random.Random(20261121)
        alphabet = "ab c\n\té漢"
        cases = 0
        for _ in range(2000):
            line_count = rng.randint(0, 12)
            lines = [
                "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))
                for _ in range(line_count)
            ]
            text = "\n".join(lines)
            max_lines = rng.randint(1, 15)
            max_bytes = rng.randint(1, 60)
            cases += 1
            before = self._cap(original, text, max_lines, max_bytes)
            after = self._cap(mutant, text, max_lines, max_bytes)
            if before != after:
                self.fail(
                    f"the mutated bound changed the behaviour for "
                    f"text={text!r} max_lines={max_lines} "
                    f"max_bytes={max_bytes}: {before!r} != {after!r}"
                )
        self.assertGreater(cases, 0)

    def test_the_boundary_is_reached_exactly_at_the_byte_cap(self):
        """``lt@579``: the sweep reaches the boundary the mutant adds.

        The mutant's extra branch runs only when the body is EXACTLY the
        byte cap.  This test drives that point directly and shows the
        body comes back byte-identical -- so the extra branch has
        nothing to do.
        """
        limits = ContextThresholds(auto_memory_max_bytes=100)
        text = "y" * 100
        capped, record = cap_auto_memory(text, limits=limits)
        self.assertEqual(capped, text)
        self.assertEqual(record["kept_bytes"], 100)
        self.assertFalse(record["truncated"])


class AutoMemoryByteAccountingTests(unittest.TestCase):
    """The auto-memory record reports the bytes that were ACTUALLY kept.

    The byte cap cuts the body on a byte boundary, so the cut can land
    INSIDE a multibyte character.  When it does, the character is
    dropped whole -- the half-character is not decodable -- so the body
    that survives holds FEWER bytes than the budget allowed.

    The record must report the bytes that were really kept.  Reporting
    the budget instead overstates what stayed in the context: a run that
    books its memory tax from this record would bill itself for bytes
    that were never there.
    """

    def test_kept_bytes_matches_the_body_when_the_cut_splits_a_character(self):
        """A cut inside a multibyte character drops the whole character.

        ``"é"`` is two bytes in UTF-8.  A cap of nine bytes cuts the
        fifth character in half, so only four whole characters survive --
        eight bytes, not the nine the cap allowed.
        """
        limits = ContextThresholds(auto_memory_max_bytes=9)
        text = "é" * 10
        capped, record = cap_auto_memory(text, limits=limits)
        self.assertEqual(capped, "éééé")
        self.assertEqual(len(capped.encode("utf-8")), 8)
        self.assertEqual(record["kept_bytes"], len(capped.encode("utf-8")))
        self.assertTrue(record["truncated"])

    def test_the_recorded_dropped_bytes_are_the_bytes_actually_dropped(self):
        """``original_bytes`` minus ``kept_bytes`` is what was dropped.

        The two numbers must describe the same text: what is gone is
        exactly the difference.
        """
        limits = ContextThresholds(auto_memory_max_bytes=9)
        text = "é" * 10
        capped, record = cap_auto_memory(text, limits=limits)
        dropped = record["original_bytes"] - record["kept_bytes"]
        self.assertEqual(dropped, len(text.encode("utf-8")) - len(capped.encode("utf-8")))

    def test_an_ascii_body_is_unchanged_by_the_accounting(self):
        """The control -- ASCII has no split character, so nothing moves.

        An ASCII byte is one byte and one character, so the cut always
        lands on a character boundary and the kept bytes equal the
        budget exactly.
        """
        limits = ContextThresholds(auto_memory_max_bytes=100)
        text = "y" * 101
        capped, record = cap_auto_memory(text, limits=limits)
        self.assertEqual(len(capped.encode("utf-8")), 100)
        self.assertEqual(record["kept_bytes"], 100)
        self.assertTrue(record["truncated"])

    def test_a_multibyte_body_that_fits_is_untouched(self):
        """The control -- a body that fits the cap keeps every byte."""
        limits = ContextThresholds(auto_memory_max_bytes=100)
        text = "é" * 50
        capped, record = cap_auto_memory(text, limits=limits)
        self.assertEqual(capped, text)
        self.assertEqual(record["kept_bytes"], 100)
        self.assertFalse(record["truncated"])

