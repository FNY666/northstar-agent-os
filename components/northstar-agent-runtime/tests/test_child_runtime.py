"""``AgentRuntime._child_runtime()``, one row per parent/definition combination.

A delegated child must not loosen what the host decided for the run and must not silently
tighten what the host already approved. The rules live in one comment in ``loop.py``; this
table turns each of them into a named row:

- permission mode: inherited, except that a ``plan`` definition always runs in ``plan``;
- allowed tools: the parent's list, limited to what the definition declared;
- disallowed tools: the union of the parent's and the definition's, plus ``Task`` whenever
  the child may not delegate again - a denial can never be undone;
- budget: the lower of the definition's own cap and what the parent has left;
- turns and tool calls: the definition's own ceilings (documented: "own ceilings");
- everything else the parent governs (halt_on_denial, output size, tool limits, hooks, the
  approval callback, the workspace) is carried over unchanged.
"""
from __future__ import annotations

import unittest
from dataclasses import dataclass, field
from typing import Any

import support  # noqa: F401
from support import RuntimeTestCase, text_turn, tool_turn

from agents import AgentDefinition, AgentRegistry, general_agent, planner_agent
from budget import Budget
from loop import TASK_TOOL_NAME, _RunState

EXPLORER_DENIES = ("Edit", "Shell", "Write")

WRITER = AgentDefinition(name="writer", tools=("Read", "Write", "Edit"), max_turns=5, max_tool_calls=7)
READER = AgentDefinition(name="reader", tools=("Read", "Grep"), disallowed_tools=("Shell",), max_turns=3, max_tool_calls=4)
CAPPED = AgentDefinition(name="capped", tools=("Read",), max_budget_usd=0.2)
COMPACTING = AgentDefinition(name="compacting", tools=("Read",), compaction_threshold_tokens=5_000)
MODELLED = AgentDefinition(name="modelled", tools=("Read",), model="claude-haiku-4-5")
DELEGATOR = AgentDefinition(name="delegator", tools=("Read", TASK_TOOL_NAME), allow_delegation=True)


@dataclass(frozen=True)
class Row:
    name: str
    definition: AgentDefinition
    parent: dict[str, Any] = field(default_factory=dict)
    spent: float = 0.0
    #: Only the keys a row names are checked; see ``observed()`` for the full set.
    expect: dict[str, Any] = field(default_factory=dict)


ROWS: tuple[Row, ...] = (
    # -- permission mode -------------------------------------------------------------
    Row("default parent, default definition", WRITER, expect={"mode": "default"}),
    Row("acceptEdits is inherited", WRITER, {"permission_mode": "acceptEdits"}, expect={"mode": "acceptEdits"}),
    Row("bypassPermissions is inherited", WRITER, {"permission_mode": "bypassPermissions"},
        expect={"mode": "bypassPermissions"}),
    Row("plan parent keeps a default definition in plan", WRITER, {"permission_mode": "plan"}, expect={"mode": "plan"}),
    Row("plan definition under a default parent", planner_agent(), expect={"mode": "plan"}),
    Row("plan definition under a bypass parent", planner_agent(), {"permission_mode": "bypassPermissions"},
        expect={"mode": "plan"}),
    # -- allowed tools -----------------------------------------------------------------
    Row("no parent approvals, none for the child", WRITER, expect={"allowed": ()}),
    Row("parent approvals limited to the declared tools", WRITER, {"allowed_tools": ("Read", "Write", "Grep", "Shell")},
        expect={"allowed": ("Read", "Write")}),
    Row("the child never gains an approval the parent lacks", READER, {"allowed_tools": ("Read",)},
        expect={"allowed": ("Read",)}),
    Row("Task is never on the child's allow list", DELEGATOR,
        {"allowed_tools": ("Read", TASK_TOOL_NAME), "allow_nested_delegation": True, "max_subagent_depth": 2},
        expect={"allowed": ("Read",)}),
    # -- disallowed tools --------------------------------------------------------------
    Row("a leaf child is denied Task", WRITER, expect={"disallowed": (TASK_TOOL_NAME,)}),
    Row("parent and definition denials are unioned", READER, {"disallowed_tools": ("Write",)},
        expect={"disallowed": ("Shell", TASK_TOOL_NAME, "Write")}),
    Row("definition's own denials", general_agent().override(name="g2", disallowed_tools=EXPLORER_DENIES),
        expect={"disallowed": (*EXPLORER_DENIES, TASK_TOOL_NAME)}),
    Row("a parent approval does not undo a definition denial", READER, {"allowed_tools": ("Read", "Shell")},
        expect={"allowed": ("Read",), "disallowed": ("Shell", TASK_TOOL_NAME)}),
    Row("a delegating definition without nested delegation is still denied Task", DELEGATOR,
        expect={"disallowed": (TASK_TOOL_NAME,), "may_delegate": False}),
    Row("nested delegation within the depth ceiling keeps Task", DELEGATOR,
        {"allow_nested_delegation": True, "max_subagent_depth": 2},
        expect={"disallowed": (), "may_delegate": True}),
    Row("nested delegation at the depth ceiling is denied Task", DELEGATOR,
        {"allow_nested_delegation": True, "max_subagent_depth": 1},
        expect={"disallowed": (TASK_TOOL_NAME,), "may_delegate": False}),
    # -- budget --------------------------------------------------------------------------
    Row("no caps anywhere", WRITER, expect={"budget": None}),
    Row("parent remainder becomes the child's cap", WRITER, {"max_budget_usd": 1.0}, spent=0.4, expect={"budget": 0.6}),
    Row("definition cap below the remainder", CAPPED, {"max_budget_usd": 1.0}, spent=0.4, expect={"budget": 0.2}),
    Row("remainder below the definition cap", CAPPED, {"max_budget_usd": 1.0}, spent=0.9, expect={"budget": 0.1}),
    Row("definition cap under an unlimited parent", CAPPED, expect={"budget": 0.2}),
    # -- the child's own ceilings --------------------------------------------------------
    Row("turns and tool calls come from the definition", READER, {"max_turns": 25, "max_tool_calls": 50},
        expect={"max_turns": 3, "max_tool_calls": 4}),
    # -- carried over from the parent --------------------------------------------------
    Row("halt_on_denial is inherited", WRITER, {"halt_on_denial": True}, expect={"halt_on_denial": True}),
    Row("max_output_tokens is inherited", WRITER, {"max_output_tokens": 1234}, expect={"max_output_tokens": 1234}),
    Row("parent compaction threshold when the definition has none", WRITER, {"compaction_threshold_tokens": 9_000},
        expect={"compaction": 9_000}),
    Row("definition compaction threshold wins", COMPACTING, {"compaction_threshold_tokens": 9_000},
        expect={"compaction": 5_000}),
    Row("parent model when the definition names none", WRITER, {"model": "claude-sonnet-4-5"},
        expect={"model": "claude-sonnet-4-5"}),
    Row("definition model wins", MODELLED, {"model": "claude-sonnet-4-5"}, expect={"model": "claude-haiku-4-5"}),
    Row("depth is one below the parent", WRITER, expect={"depth": 1}),
)


class ChildRuntimeTableTests(RuntimeTestCase):
    def build(self, row: Row) -> tuple[Any, Any, Any, str]:
        parent_kwargs = dict(row.parent)
        budget = None
        if "max_budget_usd" in parent_kwargs:
            budget = Budget(max_budget_usd=parent_kwargs["max_budget_usd"], total_cost_usd=row.spent)
        agents = AgentRegistry([row.definition])
        parent = self.runtime(agents=agents, budget=budget, can_use_tool=lambda *_: True, **parent_kwargs)
        child, config, mode = parent._child_runtime(row.definition, parent.provider, _RunState(session_id="s-test"))
        return parent, child, config, mode

    @staticmethod
    def observed(child: Any, config: Any, mode: str) -> dict[str, Any]:
        return {
            "mode": mode,
            "allowed": config.allowed_tools,
            "disallowed": config.disallowed_tools,
            "may_delegate": config.allow_delegation,
            "budget": config.max_budget_usd,
            "max_turns": config.max_turns,
            "max_tool_calls": config.max_tool_calls,
            "halt_on_denial": config.halt_on_denial,
            "max_output_tokens": config.max_output_tokens,
            "compaction": config.compaction_threshold_tokens,
            "model": config.model,
            "depth": config.depth,
        }

    def test_every_row(self):
        self.assertEqual(len({row.name for row in ROWS}), len(ROWS), "row names must be unique")
        for row in ROWS:
            with self.subTest(row.name):
                _parent, child, config, mode = self.build(row)
                seen = self.observed(child, config, mode)
                unknown = set(row.expect) - set(seen)
                self.assertFalse(unknown, f"row checks keys observed() does not report: {unknown}")
                for key, want in row.expect.items():
                    if key in ("allowed", "disallowed"):
                        self.assertEqual(sorted(seen[key]), sorted(want), key)
                    elif key == "budget" and want is not None:
                        self.assertAlmostEqual(seen[key], want, places=9, msg=key)
                    else:
                        self.assertEqual(seen[key], want, key)

    def test_every_row_keeps_the_child_engine_and_config_in_step(self):
        # The child is governed by its PermissionEngine, and reported through its config.
        # If the two ever disagree the audit record describes a policy that was not enforced.
        for row in ROWS:
            with self.subTest(row.name):
                _parent, child, config, mode = self.build(row)
                engine = child.permissions.config
                self.assertEqual(engine.mode, mode)
                self.assertEqual(config.permission_mode, mode)
                self.assertEqual(engine.allowed_tools, config.allowed_tools)
                self.assertEqual(engine.disallowed_tools, config.disallowed_tools)
                self.assertEqual(child.budget.max_budget_usd, config.max_budget_usd)
                self.assertEqual(child.budget.total_cost_usd, 0.0)

    def test_every_row_never_loosens_the_parent(self):
        for row in ROWS:
            with self.subTest(row.name):
                parent, child, config, mode = self.build(row)
                # A denial the parent holds stays a denial.
                self.assertLessEqual(set(parent.config.disallowed_tools), set(config.disallowed_tools))
                # An approval the child holds is one the parent held.
                self.assertLessEqual(set(config.allowed_tools), set(parent.permissions.config.allowed_tools))
                # The mode is the parent's, or plan.
                self.assertIn(mode, {parent.permissions.mode, "plan"})
                # The child can reach only what it declared, and never a tool the parent lacks.
                self.assertLessEqual(set(child.tools.names()), set(row.definition.tools))
                self.assertLessEqual(set(child.tools.names()) - {TASK_TOOL_NAME}, set(parent.tools.names()))
                # Spending is capped by what the parent has left.
                remaining = parent.budget.remaining()
                if remaining is not None:
                    self.assertIsNotNone(config.max_budget_usd)
                    self.assertLessEqual(config.max_budget_usd, remaining)

    def test_every_row_shares_the_parents_governance_objects(self):
        for row in ROWS:
            with self.subTest(row.name):
                parent, child, config, _mode = self.build(row)
                self.assertIs(child.hooks, parent.hooks)
                self.assertIs(child.permissions.config.can_use_tool, parent.permissions.config.can_use_tool)
                self.assertIs(config.tool_limits, parent.limits)
                self.assertEqual(config.workspace, str(parent.sandbox.root_real))
                self.assertIs(child.tracer, parent.tracer)
                self.assertEqual(config.session_id, "s-test")
                self.assertEqual(config.agent, row.definition.name)
                self.assertFalse(config.include_describe_tool)


class ChildRuntimeKnownDefectTests(RuntimeTestCase):
    """Known defect, pinned so that fixing it flips this test (an unexpected success fails).

    The budget is checked before each generation, so one turn can overspend and still ask
    for ``Task``. ``_child_runtime()`` then hands the child ``remaining() == 0.0`` as its
    cap, ``RuntimeConfig`` refuses a zero cap, and the run ends as
    ``error_during_execution`` ("unexpected runtime failure") instead of reporting that the
    budget ran out. Nothing runs that should not - the child is never built - but the
    operator and exit code (1, not 4) blame the runtime instead of the ceiling.
    """

    @unittest.expectedFailure
    def test_delegating_after_the_budget_ran_out_is_a_budget_stop(self):
        turns = [
            tool_turn(TASK_TOOL_NAME, {"subagent_type": "explorer", "prompt": "look", "description": "d"},
                      usage={"input_tokens": 2_000_000}),
            text_turn("child answer"),
            text_turn("done"),
        ]
        report = self.drive(self.runtime(turns, max_budget_usd=1.0))
        self.assertEqual(report.result.subtype, "error_max_budget_usd", report.result.errors)


if __name__ == "__main__":
    unittest.main()
