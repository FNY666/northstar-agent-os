"""Tests for effort_scaling (complexity -> parallelism mapping).

The Anthropic numbers under test are the ones quoted verbatim in the
module docstring of ``effort_scaling.py`` (Anthropic Engineering, "How we
built our multi-agent research system", 2025-06-13).

The suite is written with ``unittest.TestCase`` classes so that the
acceptance mutant probe (``python -m unittest test_effort_scaling``) can
execute it.
"""

import json
import unittest

import effort_scaling
from effort_scaling import (
    COMPLEXITY_COMPLEX,
    COMPLEXITY_MODERATE,
    COMPLEXITY_SIMPLE,
    DEPENDENCY_HIGH,
    DEPENDENCY_NONE,
    EFFORT_SCALING_TABLE,
    LEAD_PARALLEL_SPAWN_MAX,
    LEAD_PARALLEL_SPAWN_MIN,
    REASON_DEPENDENCIES,
    REASON_NOT_PARALLELIZABLE,
    REASON_SHARED_CONTEXT,
    TOOLS_PER_SUBAGENT_MIN,
    WINDOW_CARD_LIMIT,
    EffortScalingError,
    TaskSignals,
    check_applicability,
    classify_complexity,
    effort_scaling_for,
    parallel_plan_for,
    plan_effort,
)


class ClassifierTests(unittest.TestCase):
    """The complexity grading function."""

    def test_classify_simple_one_direction(self):
        """One independent direction and one tool: the simple band."""
        assessment = classify_complexity(
            TaskSignals(independent_directions=1, tool_complexity=1)
        )
        self.assertEqual(assessment.complexity, COMPLEXITY_SIMPLE)
        self.assertEqual(assessment.rank, 0)
        self.assertTrue(assessment.reasons)

    def test_classify_moderate_band(self):
        """Two to four directions: the moderate band."""
        assessment = classify_complexity(
            TaskSignals(independent_directions=3, tool_complexity=1)
        )
        self.assertEqual(assessment.complexity, COMPLEXITY_MODERATE)
        self.assertEqual(assessment.rank, 1)

    def test_classify_complex_band(self):
        """More than four directions: the complex band."""
        assessment = classify_complexity(
            TaskSignals(independent_directions=7, tool_complexity=1)
        )
        self.assertEqual(assessment.complexity, COMPLEXITY_COMPLEX)
        self.assertEqual(assessment.rank, 2)

    def test_classify_boundaries_are_inclusive(self):
        """Exactly 1 -> simple, exactly 2 and 4 -> moderate, exactly 5 -> complex."""
        self.assertEqual(
            classify_complexity(TaskSignals(independent_directions=1)).complexity,
            COMPLEXITY_SIMPLE,
        )
        self.assertEqual(
            classify_complexity(TaskSignals(independent_directions=2)).complexity,
            COMPLEXITY_MODERATE,
        )
        self.assertEqual(
            classify_complexity(TaskSignals(independent_directions=4)).complexity,
            COMPLEXITY_MODERATE,
        )
        self.assertEqual(
            classify_complexity(TaskSignals(independent_directions=5)).complexity,
            COMPLEXITY_COMPLEX,
        )

    def test_classify_info_over_window_raises_to_at_least_moderate(self):
        """Information beyond one context window bumps a one-direction task."""
        assessment = classify_complexity(
            TaskSignals(independent_directions=1, info_exceeds_context_window=True)
        )
        self.assertEqual(assessment.complexity, COMPLEXITY_MODERATE)
        self.assertTrue(
            any("context window" in reason for reason in assessment.reasons)
        )

    def test_classify_tool_complexity_bumps_one_step(self):
        """Three or more complex tools raise the tier one step."""
        bumped = classify_complexity(
            TaskSignals(independent_directions=1, tool_complexity=3)
        )
        self.assertEqual(bumped.complexity, COMPLEXITY_MODERATE)
        twice = classify_complexity(
            TaskSignals(independent_directions=2, tool_complexity=3)
        )
        self.assertEqual(twice.complexity, COMPLEXITY_COMPLEX)

    def test_classify_high_dependency_caps_at_moderate(self):
        """High inter-agent dependency forbids the complex tier."""
        assessment = classify_complexity(
            TaskSignals(independent_directions=9, dependency_degree=DEPENDENCY_HIGH)
        )
        self.assertEqual(assessment.complexity, COMPLEXITY_MODERATE)
        self.assertTrue(
            any("dependency" in reason for reason in assessment.reasons)
        )

    def test_classify_rejects_malformed_signals(self):
        """Bad dependency degree and bad types are refused, not coerced."""
        with self.assertRaises(EffortScalingError):
            TaskSignals(dependency_degree="somewhat")
        with self.assertRaises(EffortScalingError):
            TaskSignals(independent_directions=-1)
        with self.assertRaises(EffortScalingError):
            TaskSignals(truly_parallelizable="yes")
        with self.assertRaises(EffortScalingError):
            classify_complexity("not-a-signals-object")


class EffortScalingTableTests(unittest.TestCase):
    """Anthropic's effort-scaling table, row by row."""

    def test_table_simple_row_matches_anthropic(self):
        """Anthropic: "Simple fact-finding requires just 1 agent with 3-10 tool calls"."""
        row = effort_scaling_for(COMPLEXITY_SIMPLE)
        self.assertEqual(row.agent_band, "1")
        self.assertEqual(row.tool_calls_band, "3-10")
        self.assertEqual(row.subagent_count, 1)
        self.assertFalse(row.is_multi_agent)
        self.assertTrue(row.source_quote.startswith("Simple fact-finding requires just 1 agent"))

    def test_table_moderate_row_matches_anthropic(self):
        """Anthropic: "direct comparisons might need 2-4 subagents with 10-15 calls each"."""
        row = effort_scaling_for(COMPLEXITY_MODERATE)
        self.assertEqual(row.agent_band, "2-4")
        self.assertEqual(row.tool_calls_band, "10-15")
        self.assertTrue(2 <= row.subagent_count <= 4)
        self.assertTrue(row.is_multi_agent)
        self.assertIn("2-4 subagents", row.source_quote)

    def test_table_complex_row_matches_anthropic(self):
        """Anthropic: "complex research might use more than 10 subagents"."""
        row = effort_scaling_for(COMPLEXITY_COMPLEX)
        self.assertEqual(row.agent_band, "10+")
        self.assertGreaterEqual(row.subagent_count, 10)
        self.assertIn("more than 10 subagents", row.source_quote)
        self.assertIn("divided responsibilities", row.division_of_labour)

    def test_table_has_exactly_three_rows_and_rejects_unknown(self):
        """The table is closed: three tiers, no silent fallback."""
        self.assertEqual(
            set(EFFORT_SCALING_TABLE),
            {COMPLEXITY_SIMPLE, COMPLEXITY_MODERATE, COMPLEXITY_COMPLEX},
        )
        with self.assertRaises(EffortScalingError):
            effort_scaling_for("extremely-complex")

    def test_table_total_tool_calls_is_the_product(self):
        """The row's total is the per-agent count times the agent count."""
        row = effort_scaling_for(COMPLEXITY_MODERATE)
        self.assertEqual(
            row.total_tool_calls(), row.subagent_count * row.tools_per_subagent
        )


class ParallelizationTests(unittest.TestCase):
    """The two levels of parallelization."""

    def test_parallel_level_one_lead_spawns_three_to_five(self):
        """Anthropic: "the lead agent spins up 3-5 subagents in parallel".

        Measured with enough window cards to hold the whole row, so the
        card degradation does not narrow the fan-out.
        """
        plan = parallel_plan_for(
            effort_scaling_for(COMPLEXITY_COMPLEX), window_cards=12
        )
        self.assertGreaterEqual(plan.parallel_spawn_count, LEAD_PARALLEL_SPAWN_MIN)
        self.assertLessEqual(plan.parallel_spawn_count, LEAD_PARALLEL_SPAWN_MAX)
        self.assertEqual(plan.parallel_spawn_count, LEAD_PARALLEL_SPAWN_MAX)
        self.assertFalse(plan.degraded)

    def test_parallel_level_two_three_or_more_tools_per_subagent(self):
        """Anthropic: "the subagents use 3+ tools in parallel"."""
        for tier in (COMPLEXITY_SIMPLE, COMPLEXITY_MODERATE, COMPLEXITY_COMPLEX):
            plan = parallel_plan_for(effort_scaling_for(tier))
            self.assertGreaterEqual(plan.tools_per_subagent, TOOLS_PER_SUBAGENT_MIN)
            self.assertGreaterEqual(plan.tools_per_subagent, 3)

    def test_parallel_scale_pair_is_returned(self):
        """The plan hands back the (subagent_count, tools_per_subagent) pair."""
        plan = parallel_plan_for(
            effort_scaling_for(COMPLEXITY_MODERATE), window_cards=4
        )
        self.assertEqual(plan.scale, (plan.subagent_count, plan.tools_per_subagent))
        self.assertEqual(plan.scale[0], 4)
        self.assertEqual(plan.scale[1], 10)

    def test_parallel_single_agent_row_spawns_one(self):
        """A one-agent row spawns exactly one agent and no lead fan-out."""
        plan = parallel_plan_for(effort_scaling_for(COMPLEXITY_SIMPLE))
        self.assertEqual(plan.subagent_count, 1)
        self.assertEqual(plan.parallel_spawn_count, 1)
        self.assertEqual(plan.scale, (1, 3))
        self.assertFalse(plan.degraded)

    def test_parallel_rejects_non_scaling_input(self):
        """The plan refuses a non-row input and a non-positive card count."""
        with self.assertRaises(EffortScalingError):
            parallel_plan_for("simple")
        with self.assertRaises(EffortScalingError):
            parallel_plan_for(effort_scaling_for(COMPLEXITY_SIMPLE), window_cards=0)


class ApplicabilityGateTests(unittest.TestCase):
    """The multi-agent applicability gate."""

    def test_gate_shared_context_required_is_inapplicable(self):
        """Anthropic: agents that "require all agents to share the same context"."""
        applicability = check_applicability(
            TaskSignals(independent_directions=6, shared_context_required=True)
        )
        self.assertFalse(applicability.applicable)
        self.assertIn(REASON_SHARED_CONTEXT, applicability.reasons)

    def test_gate_many_agent_dependencies_is_inapplicable(self):
        """Anthropic: tasks that "involve many dependencies between agents"."""
        applicability = check_applicability(
            TaskSignals(independent_directions=6, dependency_degree=DEPENDENCY_HIGH)
        )
        self.assertFalse(applicability.applicable)
        self.assertIn(REASON_DEPENDENCIES, applicability.reasons)

    def test_gate_not_truly_parallelizable_is_inapplicable(self):
        """Anthropic: work that cannot actually be run in parallel."""
        applicability = check_applicability(
            TaskSignals(independent_directions=6, truly_parallelizable=False)
        )
        self.assertFalse(applicability.applicable)
        self.assertIn(REASON_NOT_PARALLELIZABLE, applicability.reasons)

    def test_gate_all_three_reasons_are_reported(self):
        """Every disqualifier is named, not just the first one."""
        applicability = check_applicability(
            TaskSignals(
                independent_directions=6,
                shared_context_required=True,
                dependency_degree=DEPENDENCY_HIGH,
                truly_parallelizable=False,
            )
        )
        self.assertFalse(applicability.applicable)
        self.assertEqual(
            set(applicability.reasons),
            {
                REASON_SHARED_CONTEXT,
                REASON_DEPENDENCIES,
                REASON_NOT_PARALLELIZABLE,
            },
        )

    def test_gate_passes_an_ordinary_task(self):
        """A task with no disqualifier keeps the multi-agent shape."""
        applicability = check_applicability(
            TaskSignals(independent_directions=6, dependency_degree=DEPENDENCY_NONE)
        )
        self.assertTrue(applicability.applicable)
        self.assertEqual(applicability.reasons, ())


class CardDegradationTests(unittest.TestCase):
    """The window-card degradation rule."""

    def test_card_degradation_reduces_to_the_card_count(self):
        """12 requested subagents against 3 window cards degrade to 3."""
        plan = parallel_plan_for(effort_scaling_for(COMPLEXITY_COMPLEX))
        self.assertEqual(plan.requested_subagent_count, 12)
        self.assertEqual(plan.subagent_count, WINDOW_CARD_LIMIT)
        self.assertTrue(plan.degraded)
        self.assertTrue(plan.degradation_reasons)
        self.assertIn("window", plan.degradation_reasons[0])

    def test_card_degradation_does_not_change_the_cap(self):
        """The cap stays 3; only this mapping is reduced."""
        plan = parallel_plan_for(
            effort_scaling_for(COMPLEXITY_COMPLEX), window_cards=WINDOW_CARD_LIMIT
        )
        self.assertEqual(plan.window_cards, 3)
        self.assertEqual(plan.subagent_count, 3)

    def test_no_degradation_when_the_row_fits(self):
        """A row that fits the cards is not degraded."""
        plan = parallel_plan_for(
            effort_scaling_for(COMPLEXITY_SIMPLE), window_cards=WINDOW_CARD_LIMIT
        )
        self.assertFalse(plan.degraded)
        self.assertEqual(plan.degradation_reasons, ())


class RealPathTests(unittest.TestCase):
    """The three paths the task book asks to be driven for real."""

    def test_real_path_simple_query_stays_single_agent(self):
        """(a) A simple query: 1 agent, 3-10 tool calls, no subagent."""
        plan = plan_effort(
            TaskSignals(
                independent_directions=1,
                info_exceeds_context_window=False,
                tool_complexity=1,
                dependency_degree=DEPENDENCY_NONE,
            )
        )
        self.assertEqual(plan.assessment.complexity, COMPLEXITY_SIMPLE)
        self.assertEqual(plan.scaling.agent_band, "1")
        self.assertEqual(plan.scaling.tool_calls_band, "3-10")
        self.assertEqual(plan.scale[0], 1)
        self.assertEqual(plan.parallel_spawn_count, 1)
        self.assertFalse(plan.multi_agent)

    def test_real_path_complex_query_maps_to_ten_plus_subagents(self):
        """(b) A complex query: 10+ subagents and both parallel levels."""
        plan = plan_effort(
            TaskSignals(
                independent_directions=9,
                info_exceeds_context_window=True,
                tool_complexity=4,
                dependency_degree=DEPENDENCY_NONE,
            )
        )
        self.assertEqual(plan.assessment.complexity, COMPLEXITY_COMPLEX)
        self.assertGreaterEqual(plan.scaling.subagent_count, 10)
        self.assertGreaterEqual(plan.parallel_spawn_count, LEAD_PARALLEL_SPAWN_MIN)
        self.assertLessEqual(plan.parallel_spawn_count, LEAD_PARALLEL_SPAWN_MAX)
        self.assertGreaterEqual(plan.parallel.tools_per_subagent, 3)
        self.assertTrue(plan.multi_agent)

    def test_real_path_complex_query_is_degraded_by_the_card_cap(self):
        """The complex path is degraded to the 3-card cap and records it."""
        plan = plan_effort(
            TaskSignals(
                independent_directions=9,
                info_exceeds_context_window=True,
                tool_complexity=4,
            )
        )
        self.assertTrue(plan.parallel.degraded)
        self.assertEqual(plan.parallel.subagent_count, WINDOW_CARD_LIMIT)
        self.assertGreaterEqual(plan.parallel.requested_subagent_count, 10)
        self.assertTrue(plan.degradation_reasons)

    def test_real_path_inapplicable_task_falls_back_to_one_agent(self):
        """(c) An inapplicable task never gets a multi-agent shape."""
        plan = plan_effort(
            TaskSignals(
                independent_directions=9,
                info_exceeds_context_window=True,
                tool_complexity=4,
                shared_context_required=True,
                dependency_degree=DEPENDENCY_HIGH,
                truly_parallelizable=False,
            )
        )
        self.assertFalse(plan.multi_agent)
        self.assertEqual(plan.scale[0], 1)
        self.assertEqual(plan.parallel_spawn_count, 1)
        self.assertEqual(
            set(plan.degradation_reasons),
            {
                REASON_SHARED_CONTEXT,
                REASON_DEPENDENCIES,
                REASON_NOT_PARALLELIZABLE,
            },
        )


class BudgetSeamTests(unittest.TestCase):
    """The seam to budget.py / agents.py ceilings."""

    def test_remaining_budget_clamps_the_tool_count(self):
        """[Northstar] The row's tool calls are clamped to what is left."""
        plan = plan_effort(
            TaskSignals(independent_directions=9),
            window_cards=3,
            remaining_tool_call_budget=12,
        )
        self.assertTrue(plan.tool_calls_clamped)
        self.assertLessEqual(plan.parallel.total_tool_calls, 12)
        self.assertTrue(plan.degradation_reasons)

    def test_plan_as_dict_is_json_shaped(self):
        """The plan serialises to plain data."""
        plan = plan_effort(TaskSignals(independent_directions=9))
        payload = json.loads(json.dumps(plan.as_dict()))
        self.assertEqual(payload["assessment"]["complexity"], COMPLEXITY_COMPLEX)
        self.assertEqual(payload["schema"], effort_scaling.EFFORT_SCALING_SCHEMA)

    def test_module_self_check_runs(self):
        """The module's own end-to-end self-check passes."""
        effort_scaling.main()


if __name__ == "__main__":
    unittest.main()
