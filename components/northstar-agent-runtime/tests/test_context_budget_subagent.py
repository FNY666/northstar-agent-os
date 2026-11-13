"""The subagent return budget on the real delegation path.

B173 fable.  A research subagent reads about 6,100 tokens and returns about
420 to its parent; a general subagent returns a distilled 1,000-2,000 token
summary.  The rule that matters for a long-horizon agent is the last one:
**an over-budget return is truncated and marked, never silently dropped.**

Silently dropping is the failure mode that matters.  A parent that receives
a short answer and cannot tell it was cut will act on a partial picture,
and the run's own evidence will say the subagent "found nothing" when in
fact the finding was there and the budget ate it.

These tests drive a real delegation: the parent calls ``Task``, the child
runs, and the tool result the parent is shown is asserted on.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agents import AgentDefinition, AgentRegistry, general_agent
from context_budget import ContextThresholds
from support import RuntimeTestCase, text_turn, tool_turn


def fat_report(tokens: int = 3_000, marker: str = "w") -> str:
    return marker * (tokens * 4)


class SubagentBudgetPathTests(RuntimeTestCase):
    """The parent's tool result carries the capped and marked return."""

    def _drive(self, *, child_text: str, tags=("builtin", "general"), thresholds=ContextThresholds()):
        parent = self.provider(
            [
                tool_turn("Task", {"agent": "worker", "prompt": "investigate"}),
                text_turn("done"),
            ]
        )
        child = self.provider([text_turn(child_text)])
        agents = AgentRegistry(
            [
                general_agent(),
                AgentDefinition(
                    name="worker",
                    description="a delegated worker",
                    prompt="investigate and report",
                    tools=("Read", "Grep", "LS"),
                    provider="child",
                    max_turns=4,
                    tags=tuple(tags),
                ),
            ]
        )
        runtime = self.runtime(
            provider=parent,
            providers={"child": child},
            agents=agents,
            workspace=self.workspace(),
            allowed_tools=("Task", "Read"),
            can_use_tool=lambda *_args: True,
            context_thresholds=thresholds,
        )
        report = self.drive(runtime)
        return runtime, report, parent

    def _task_result(self, parent) -> str:
        """The text of the Task result the parent was shown."""
        for block in parent.sent_tool_results():
            content = block.get("content")
            if isinstance(content, str) and "subagent" in content:
                return content
        raise AssertionError("the Task result must have reached the parent")

    def test_an_over_budget_return_is_truncated(self):
        _runtime, report, parent = self._drive(child_text=fat_report())
        self.assertTrue(report.subagents, "the subagent must have run")
        text = self._task_result(parent)
        # The child's 3,000-token answer did not arrive whole.
        self.assertLess(len(text), 3_000 * 4)

    def test_an_over_budget_return_is_marked_as_truncated(self):
        _runtime, _report, parent = self._drive(child_text=fat_report())
        text = self._task_result(parent)
        self.assertIn(
            "truncated to the subagent return budget",
            text,
            "an over-budget return must say that it was cut",
        )

    def test_a_return_inside_the_budget_is_untouched(self):
        _runtime, _report, parent = self._drive(child_text="a short and complete answer")
        text = self._task_result(parent)
        self.assertIn("a short and complete answer", text)
        self.assertNotIn("truncated to the subagent return budget", text)

    def test_a_research_subagent_gets_the_smaller_budget(self):
        """A research subagent returns ~420 tokens, not ~2,000."""
        _runtime, _report, parent = self._drive(
            child_text=fat_report(1_000), tags=("builtin", "research")
        )
        text = self._task_result(parent)
        self.assertLess(len(text), 1_000 * 4)
        self.assertIn("truncated to the subagent return budget", text)

    def test_a_general_subagent_gets_the_larger_budget(self):
        """The general budget is 1,000-2,000 tokens: more than research."""
        _runtime, _report, parent = self._drive(
            child_text=fat_report(1_000), tags=("builtin", "general")
        )
        text = self._task_result(parent)
        # 1,000 tokens is inside the general budget of 2,000, so it is
        # not cut -- this is what separates the two variants.
        self.assertNotIn("truncated to the subagent return budget", text)

    def test_without_the_rules_the_return_is_not_capped(self):
        _runtime, _report, parent = self._drive(child_text=fat_report(), thresholds=None)
        text = self._task_result(parent)
        self.assertGreater(len(text), 3_000 * 4 // 2)
        self.assertNotIn("truncated to the subagent return budget", text)


if __name__ == "__main__":
    unittest.main()
