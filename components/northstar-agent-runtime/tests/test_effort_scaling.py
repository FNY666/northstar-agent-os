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
    EffortScaling,
    EffortScalingError,
    ParallelPlan,
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


class GuardArmsAndBoundariesTests(unittest.TestCase):
    """The arm of each guard and the boundary each bound is drawn at.

    Seven planted faults survived this slice's suite:

      or@174   the ``bool`` half of the positive-int guard
      or@180   the ``bool`` half of the non-negative-int guard
      lt@180   the lower bound of the non-negative-int guard
      gt@606   the card-degradation bound
      lt@616   the parallel-spawn band's lower edge
      gt@756   the remaining-budget bound
      eq@861   the ``__main__`` guard

    The first six are driven below; ``eq@861`` is driven in
    :class:`MainGuardTests``.

    Why the existing suite missed them
    ----------------------------------

    Each of the first four is one arm of a three-way disjunction, and the
    existing suite drove only the arm that was easy to reach from the
    public API:

      or@174 / or@180   ``isinstance(value, bool) or not isinstance(value,
                       int) or <bound>``.  Under the mutant the ``bool``
                       arm is gone, so a BOOLEAN slips through as the
                       integer 1 (or 0).  The existing suite fed
                       negative numbers and floats, which the ``not an
                       int`` arm catches; it never fed a bool.  The
                       killer is a boolean.
      lt@180           ``value < 0`` -> ``value <= 0``.  Zero is a LEGAL
                       non-negative count, so the mutant refuses a value
                       the original accepts.  The killer is exactly zero.
      gt@606           ``requested > window_cards``.  The mutant degrades
                       a plan that fits EXACTLY.  The killer is a card
                       count equal to the requested subagent count.
      lt@616           ``subagents < LEAD_PARALLEL_SPAWN_MIN``.  The
                       mutant treats exactly-3 as "below the band".  The
                       killer is a plan that lands on exactly 3.
      gt@756           ``total_tool_calls > remaining``.  The mutant
                       clamps a plan that fits EXACTLY.  The killer is a
                       remaining budget equal to the row's total.
    """

    # --- or@174: the `bool` half of the positive-int guard --------------
    def test_a_boolean_subagent_count_is_refused(self):
        """`or@174`: **a bool IS an int in Python**.

        The guard is ``isinstance(value, bool) or not isinstance(value,
        int) or value < 1``.  The "not an int" half never refuses a
        bool -- only the explicit ``bool`` half does.  Under the mutant
        (``or`` -> ``and``) a boolean subagent count is accepted and
        used as the integer 1, so a caller asking for "one agent" with a
        boolean gets a plan instead of a refusal.
        """
        with self.assertRaises(EffortScalingError):
            EffortScaling(
                complexity=COMPLEXITY_SIMPLE,
                agent_band="1",
                tool_calls_band="3-10",
                subagent_count=True,
                tools_per_subagent=3,
                source_quote="q",
            )

    def test_a_false_boolean_subagent_count_is_refused_too(self):
        """`or@174`: the other boolean."""
        with self.assertRaises(EffortScalingError):
            EffortScaling(
                complexity=COMPLEXITY_SIMPLE,
                agent_band="1",
                tool_calls_band="3-10",
                subagent_count=False,
                tools_per_subagent=3,
                source_quote="q",
            )

    def test_a_boolean_parallel_spawn_count_is_refused(self):
        """`or@174`: the same guard on a second positive-int field."""
        with self.assertRaises(EffortScalingError):
            ParallelPlan(
                subagent_count=1,
                tools_per_subagent=3,
                parallel_spawn_count=True,
                window_cards=3,
            )

    def test_a_float_subagent_count_is_refused(self):
        """`or@174`: the other half, as the control."""
        with self.assertRaises(EffortScalingError):
            EffortScaling(
                complexity=COMPLEXITY_SIMPLE,
                agent_band="1",
                tool_calls_band="3-10",
                subagent_count=1.5,
                tools_per_subagent=3,
                source_quote="q",
            )

    # --- lt@174: the lower bound of the positive-int guard --------------
    def test_exactly_one_window_card_is_accepted(self):
        """`lt@174`: one is the smallest legal card count.

        A host with a single context-window card can still run a plan;
        the guard is ``value < 1``, so exactly one is inside the bound.
        Under the mutant (``< 1`` -> ``<= 1``) a single-card host would
        be refused, which would make the module unusable for the
        smallest legal deployment.
        """
        plan = parallel_plan_for(
            effort_scaling_for(COMPLEXITY_SIMPLE), window_cards=1
        )
        self.assertEqual(plan.window_cards, 1)
        self.assertEqual(plan.subagent_count, 1)
        self.assertEqual(plan.parallel_spawn_count, 1)

    def test_zero_window_cards_is_still_refused(self):
        """`lt@174`: the other side of the bound, as the control."""
        with self.assertRaises(EffortScalingError):
            parallel_plan_for(
                effort_scaling_for(COMPLEXITY_SIMPLE), window_cards=0
            )

    # --- or@180: the `bool` half of the non-negative-int guard ----------
    def test_a_boolean_independent_direction_count_is_refused(self):
        """`or@180`: **a bool IS an int in Python**, again.

        The guard is ``isinstance(value, bool) or not isinstance(value,
        int) or value < 0``.  Under the mutant a boolean is accepted and
        read as 1 (or 0), so a caller who passes ``True`` instead of an
        integer gets a classified task instead of a refusal.
        """
        with self.assertRaises(EffortScalingError):
            TaskSignals(independent_directions=True)

    def test_a_false_boolean_independent_direction_count_is_refused(self):
        """`or@180`: the other boolean."""
        with self.assertRaises(EffortScalingError):
            TaskSignals(independent_directions=False)

    def test_a_boolean_tool_complexity_is_refused(self):
        """`or@180`: the same guard on the second non-negative-int field."""
        with self.assertRaises(EffortScalingError):
            TaskSignals(tool_complexity=True)

    def test_a_float_independent_direction_count_is_refused(self):
        """`or@180`: the other half, as the control."""
        with self.assertRaises(EffortScalingError):
            TaskSignals(independent_directions=1.5)

    # --- lt@180: the lower bound is INCLUSIVE --------------------------
    def test_zero_independent_directions_is_accepted(self):
        """`lt@180`: zero is a legal non-negative count.

        A task with no independent directions is degenerate but not
        malformed: the count is a non-negative int, and zero is one.
        Under the mutant (``< 0`` -> ``<= 0``) it would be refused, so
        the module would reject a value the contract allows.
        """
        signals = TaskSignals(independent_directions=0, tool_complexity=0)
        self.assertEqual(signals.independent_directions, 0)
        self.assertEqual(signals.tool_complexity, 0)
        self.assertEqual(
            classify_complexity(signals).complexity, COMPLEXITY_SIMPLE
        )

    def test_zero_tool_complexity_is_accepted(self):
        """`lt@180`: the same bound on the second field."""
        signals = TaskSignals(tool_complexity=0)
        self.assertEqual(signals.tool_complexity, 0)

    def test_a_negative_direction_count_is_still_refused(self):
        """`lt@180`: the other side of the bound, as the control."""
        with self.assertRaises(EffortScalingError):
            TaskSignals(independent_directions=-1)

    # --- gt@606: the card-degradation bound is STRICT --------------------
    def test_a_plan_that_exactly_fills_the_cards_is_not_degraded(self):
        """`gt@606`: the bound is STRICT.

        A row whose requested subagent count EQUALS the number of
        context-window cards fits exactly -- there is nothing to
        degrade.  Under the mutant (``>`` -> ``>=``) the plan would be
        marked degraded and would record a "requested 12 subagents
        exceeds the 12 context-window cards" reason, which is false: 12
        does not exceed 12.
        """
        row = effort_scaling_for(COMPLEXITY_COMPLEX)
        plan = parallel_plan_for(row, window_cards=row.subagent_count)
        self.assertFalse(plan.degraded)
        self.assertEqual(plan.degradation_reasons, ())
        self.assertEqual(plan.subagent_count, row.subagent_count)
        self.assertEqual(plan.requested_subagent_count, row.subagent_count)

    def test_a_plan_that_exceeds_the_cards_is_still_degraded(self):
        """`gt@606`: the other side of the bound, as the control."""
        row = effort_scaling_for(COMPLEXITY_COMPLEX)
        plan = parallel_plan_for(row, window_cards=row.subagent_count - 1)
        self.assertTrue(plan.degraded)
        self.assertTrue(plan.degradation_reasons)

    # --- lt@616: the parallel-spawn band's lower edge is INCLUSIVE ------
    def test_a_plan_of_exactly_three_subagents_is_inside_the_band(self):
        """`lt@616`: exactly three IS inside Anthropic's 3-5 band.

        "the lead agent spins up 3-5 subagents in parallel" -- three is
        the band's lower edge, so a plan that lands on three is inside
        the band and must NOT be reported as below it.  Under the mutant
        (``<`` -> ``<=``) the plan would carry a spurious "below
        Anthropic's 3-5 parallel spawn band" reason and the spawn count
        would be clamped to the subagent count instead of the band.
        """
        row = effort_scaling_for(COMPLEXITY_COMPLEX)
        plan = parallel_plan_for(row, window_cards=LEAD_PARALLEL_SPAWN_MIN)
        self.assertEqual(plan.subagent_count, LEAD_PARALLEL_SPAWN_MIN)
        self.assertEqual(plan.parallel_spawn_count, LEAD_PARALLEL_SPAWN_MIN)
        self.assertFalse(
            any("parallel spawn band" in reason for reason in plan.degradation_reasons),
            plan.degradation_reasons,
        )

    def test_a_plan_of_exactly_two_subagents_is_below_the_band(self):
        """`lt@616`: the other side of the bound, as the control."""
        row = effort_scaling_for(COMPLEXITY_COMPLEX)
        plan = parallel_plan_for(row, window_cards=LEAD_PARALLEL_SPAWN_MIN - 1)
        self.assertEqual(plan.subagent_count, LEAD_PARALLEL_SPAWN_MIN - 1)
        self.assertEqual(plan.parallel_spawn_count, LEAD_PARALLEL_SPAWN_MIN - 1)
        self.assertTrue(
            any("parallel spawn band" in reason for reason in plan.degradation_reasons),
            plan.degradation_reasons,
        )

    # --- gt@756: the remaining-budget bound is STRICT --------------------
    def test_a_row_that_exactly_fits_the_remaining_budget_is_not_clamped(self):
        """`gt@756`: the bound is STRICT.

        When the row's total tool-call count EQUALS what is left, the
        plan fits exactly and nothing needs clamping.  Under the mutant
        (``>`` -> ``>=``) the plan would be marked clamped and would
        record a "exceed the remaining budget" reason, which is false.
        """
        signals = TaskSignals(independent_directions=9)
        plan = plan_effort(signals, window_cards=3)
        exact = plan.parallel.total_tool_calls
        fitted = plan_effort(
            signals, window_cards=3, remaining_tool_call_budget=exact
        )
        self.assertFalse(fitted.tool_calls_clamped)
        self.assertEqual(fitted.parallel.total_tool_calls, exact)
        self.assertFalse(
            any("remaining budget" in reason for reason in fitted.degradation_reasons),
            fitted.degradation_reasons,
        )

    def test_a_row_that_exceeds_the_remaining_budget_is_still_clamped(self):
        """`gt@756`: the other side of the bound, as the control."""
        signals = TaskSignals(independent_directions=9)
        plan = plan_effort(signals, window_cards=3)
        exact = plan.parallel.total_tool_calls
        tight = plan_effort(
            signals, window_cards=3, remaining_tool_call_budget=exact - 1
        )
        self.assertTrue(tight.tool_calls_clamped)
        self.assertLess(tight.parallel.total_tool_calls, exact)
        self.assertTrue(
            any("remaining budget" in reason for reason in tight.degradation_reasons),
            tight.degradation_reasons,
        )


class MainGuardTests(unittest.TestCase):
    """`eq@861`: the ``__main__`` guard.

    The last line of the module is::

        if __name__ == "__main__":
            main()

    Under the planted fault (``==`` -> ``!=``) the guard is INVERTED: the
    self-check runs when the module is IMPORTED, and does NOT run when
    the module is executed as a script.

    That inversion is invisible to a suite that only imports the module,
    because the import path already calls ``main()`` -- and the mutant
    calls it a second time, which prints the banner again and still
    passes every assertion.  The killer is the other direction: the
    module must be SILENT when it is imported.

    The technique is ``runpy.run_path`` with ``run_name`` set to
    anything other than ``"__main__"``.  That runs the module body
    exactly as an import would, without importing it, and captures
    whatever it prints.
    """

    def test_importing_the_module_prints_nothing(self):
        """`eq@861`: an import is silent.

        A module that prints on import is a module that corrupts the
        output of every tool that imports it.  Under the mutant the
        banner is printed on import.
        """
        import runpy
        from io import StringIO
        from contextlib import redirect_stdout

        stream = StringIO()
        with redirect_stdout(stream):
            runpy.run_path(
                effort_scaling.__file__, run_name="effort_scaling_import_probe"
            )
        self.assertEqual(
            stream.getvalue(),
            "",
            "the module must be silent when it is imported",
        )

    def test_running_the_module_as_a_script_prints_the_banner(self):
        """`eq@861`: the other side of the guard.

        Executed as a script, the module DOES run its self-check and
        DOES print the banner.  Under the mutant the banner never
        appears, because the inverted guard skips it.
        """
        import runpy
        from io import StringIO
        from contextlib import redirect_stdout

        stream = StringIO()
        with redirect_stdout(stream):
            runpy.run_path(effort_scaling.__file__, run_name="__main__")
        self.assertIn("effort-scaling OK", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
