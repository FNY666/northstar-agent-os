"""Tests for planner_budget_combo: planner gates + per-call budget composed."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from per_call_budget import BudgetExhausted, PerCallBudget
from planner_budget_combo import (
    GUARD_BUDGET,
    GUARD_CRITIC,
    GUARD_STRUCTURE,
    PLANNER_BUDGET_COMBO_VERSION,
    SCHEMA_PIN,
    GatedPlan,
    PlanCost,
    PlanRefused,
    PlannerBudgetGate,
)
from planner_gates import CriticVerdict, Subgoal


def _subgoals():
    return [
        Subgoal(id="fetch", description="fetch messages", on_failure="abort"),
        Subgoal(
            id="summarize",
            description="summarize threads",
            depends_on=("fetch",),
            on_failure="escalate",
        ),
    ]


def _gate(max_budget_usd=1.0):
    return PlannerBudgetGate(PerCallBudget(max_budget_usd=max_budget_usd))


class TestVersion(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(PLANNER_BUDGET_COMBO_VERSION, "planner-budget-combo.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.planner-budget-combo.v1")
        self.assertEqual(GUARD_STRUCTURE, "structure")
        self.assertEqual(GUARD_CRITIC, "critic")
        self.assertEqual(GUARD_BUDGET, "budget")


class TestHappyPath(unittest.TestCase):
    def test_propose_and_commit(self):
        gate = _gate()
        gated = gate.propose(
            "summarize inbox",
            _subgoals(),
            estimated_steps=10,
            costs={"fetch": 0.001, "summarize": 0.02},
            call_types={"fetch": "tool", "summarize": "model"},
            planner_cost_usd=0.005,
        )
        self.assertIsInstance(gated, GatedPlan)
        self.assertAlmostEqual(gated.total_cost_usd, 0.026)
        self.assertAlmostEqual(gate.reserved_usd, 0.026)
        self.assertEqual(gate.outstanding, 1)
        charges = gate.commit(gated)
        self.assertEqual(len(charges), 3)  # model (planner) + 2 subgoals
        self.assertEqual(gate.outstanding, 0)
        self.assertAlmostEqual(gate.reserved_usd, 0.0)

    def test_default_call_type_is_tool(self):
        gate = _gate()
        gated = gate.propose(
            "goal", _subgoals(), estimated_steps=5,
            costs={"fetch": 0.001, "summarize": 0.001},
        )
        self.assertEqual([c.call_type for c in gated.costs], ["tool", "tool"])

    def test_frozen_records(self):
        gate = _gate()
        gated = gate.propose(
            "goal", _subgoals(), estimated_steps=5,
            costs={"fetch": 0.001, "summarize": 0.001},
        )
        with self.assertRaises(Exception):
            gated.total_cost_usd = 99.0  # type: ignore[misc]
        with self.assertRaises(Exception):
            gated.costs[0].estimated_cost_usd = 99.0  # type: ignore[misc]

    def test_as_dict_shape(self):
        gate = _gate()
        gated = gate.propose(
            "goal", _subgoals(), estimated_steps=5,
            costs={"fetch": 0.001, "summarize": 0.001},
        )
        d = gated.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(len(d["costs"]), 2)
        self.assertIn("plan", d)
        self.assertIn("total_cost_usd", d)


class TestStructureGuard(unittest.TestCase):
    def test_too_many_subgoals_refused(self):
        gate = _gate()
        many = [
            Subgoal(id=f"s{i}", description="d", on_failure="abort")
            for i in range(6)
        ]
        with self.assertRaises(PlanRefused) as ctx:
            gate.propose("goal", many, 10, costs={f"s{i}": 0.001 for i in range(6)})
        self.assertEqual(ctx.exception.guard, GUARD_STRUCTURE)

    def test_invalid_plan_refused(self):
        gate = _gate()
        dupes = [
            Subgoal(id="a", description="d", on_failure="abort"),
            Subgoal(id="a", description="d2", on_failure="abort"),
        ]
        with self.assertRaises(PlanRefused) as ctx:
            gate.propose("goal", dupes, 10, costs={"a": 0.001})
        self.assertEqual(ctx.exception.guard, GUARD_STRUCTURE)


class TestCriticGuard(unittest.TestCase):
    def test_needs_revision_refused(self):
        gate = _gate()
        no_failure = [Subgoal(id="a", description="d")]  # no on_failure
        with self.assertRaises(PlanRefused) as ctx:
            gate.propose("goal", no_failure, 10, costs={"a": 0.001})
        self.assertEqual(ctx.exception.guard, GUARD_CRITIC)
        self.assertIn("needs_revision", ctx.exception.reason)

    def test_circular_dependency_refused(self):
        gate = _gate()
        circular = [
            Subgoal(id="a", description="d", depends_on=("b",), on_failure="abort"),
            Subgoal(id="b", description="d", depends_on=("a",), on_failure="abort"),
        ]
        with self.assertRaises(PlanRefused) as ctx:
            gate.propose("goal", circular, 10, costs={"a": 0.001, "b": 0.001})
        self.assertEqual(ctx.exception.guard, GUARD_CRITIC)
        self.assertIn("reject", ctx.exception.reason)


class TestBudgetGuard(unittest.TestCase):
    def test_unpriced_subgoal_refused(self):
        gate = _gate()
        with self.assertRaises(PlanRefused) as ctx:
            gate.propose(
                "goal", _subgoals(), 5, costs={"fetch": 0.001}
            )
        self.assertEqual(ctx.exception.guard, GUARD_BUDGET)
        self.assertIn("unpriced", ctx.exception.reason)

    def test_extra_cost_keys_refused(self):
        gate = _gate()
        with self.assertRaises(PlanRefused) as ctx:
            gate.propose(
                "goal", _subgoals(), 5,
                costs={"fetch": 0.001, "summarize": 0.001, "ghost": 0.5},
            )
        self.assertEqual(ctx.exception.guard, GUARD_BUDGET)

    def test_unknown_call_type_refused(self):
        gate = _gate()
        with self.assertRaises(PlanRefused) as ctx:
            gate.propose(
                "goal", _subgoals(), 5,
                costs={"fetch": 0.001, "summarize": 0.001},
                call_types={"fetch": "teleport"},
            )
        self.assertEqual(ctx.exception.guard, GUARD_BUDGET)

    def test_per_call_ceiling_refused(self):
        gate = _gate()
        with self.assertRaises(PlanRefused) as ctx:
            gate.propose(
                "goal", _subgoals(), 5,
                costs={"fetch": 0.001, "summarize": 99.0},
                call_types={"summarize": "tool"},  # tool ceiling is 0.01
            )
        self.assertEqual(ctx.exception.guard, GUARD_BUDGET)
        self.assertIn("per-call ceiling", ctx.exception.reason)

    def test_run_budget_refused(self):
        gate = PlannerBudgetGate(PerCallBudget(max_budget_usd=0.01))
        with self.assertRaises(PlanRefused) as ctx:
            gate.propose(
                "goal", _subgoals(), 5,
                costs={"fetch": 0.006, "summarize": 0.006},
                call_types={"fetch": "tool", "summarize": "tool"},
            )
        self.assertEqual(ctx.exception.guard, GUARD_BUDGET)
        self.assertIn("effective remaining", ctx.exception.reason)

    def test_planner_cost_over_model_ceiling_refused(self):
        gate = _gate()
        with self.assertRaises(PlanRefused) as ctx:
            gate.propose(
                "goal", _subgoals(), 5,
                costs={"fetch": 0.001, "summarize": 0.001},
                planner_cost_usd=99.0,  # model ceiling is 0.05
            )
        self.assertEqual(ctx.exception.guard, GUARD_BUDGET)


class TestReservations(unittest.TestCase):
    def test_reservation_blocks_double_booking(self):
        gate = PlannerBudgetGate(PerCallBudget(max_budget_usd=0.01))
        first = gate.propose(
            "g1", _subgoals(), 5,
            costs={"fetch": 0.004, "summarize": 0.004},
            call_types={"fetch": "tool", "summarize": "tool"},
        )
        self.assertAlmostEqual(gate.reserved_usd, 0.008)
        # Second plan fits the raw budget but not the reserved remainder.
        with self.assertRaises(PlanRefused) as ctx:
            gate.propose(
                "g2", _subgoals(), 5,
                costs={"fetch": 0.004, "summarize": 0.004},
                call_types={"fetch": "tool", "summarize": "tool"},
            )
        self.assertEqual(ctx.exception.guard, GUARD_BUDGET)
        gate.release(first)
        # After release, the same plan fits again.
        gate.propose(
            "g2", _subgoals(), 5,
            costs={"fetch": 0.004, "summarize": 0.004},
            call_types={"fetch": "tool", "summarize": "tool"},
        )

    def test_release_frees_reservation(self):
        gate = _gate()
        gated = gate.propose(
            "goal", _subgoals(), 5,
            costs={"fetch": 0.001, "summarize": 0.001},
        )
        gate.release(gated)
        self.assertEqual(gate.outstanding, 0)
        self.assertAlmostEqual(gate.reserved_usd, 0.0)
        with self.assertRaises(KeyError):
            gate.release(gated)  # already released

    def test_double_commit_rejected(self):
        gate = _gate()
        gated = gate.propose(
            "goal", _subgoals(), 5,
            costs={"fetch": 0.001, "summarize": 0.001},
        )
        gate.commit(gated)
        with self.assertRaises(KeyError):
            gate.commit(gated)

    def test_commit_after_budget_moved_fails_closed(self):
        budget = PerCallBudget(max_budget_usd=0.01)
        gate = PlannerBudgetGate(budget)
        gated = gate.propose(
            "goal", _subgoals(), 5,
            costs={"fetch": 0.004, "summarize": 0.004},
            call_types={"fetch": "tool", "summarize": "tool"},
        )
        # Someone else spends the money directly on the budget.
        budget.check_and_charge("tool", 0.004)
        with self.assertRaises(BudgetExhausted):
            gate.commit(gated)
        # Reservation stays in place for a later retry.
        self.assertEqual(gate.outstanding, 1)

    def test_commit_charges_underlying_budget(self):
        budget = PerCallBudget(max_budget_usd=1.0)
        gate = PlannerBudgetGate(budget)
        gated = gate.propose(
            "goal", _subgoals(), 5,
            costs={"fetch": 0.001, "summarize": 0.001},
            call_types={"fetch": "tool", "summarize": "model"},
        )
        gate.commit(gated)
        self.assertAlmostEqual(budget.total_spent_usd, 0.002)
        self.assertEqual(len(budget.charges_for("tool")), 1)
        self.assertEqual(len(budget.charges_for("model")), 1)


class TestTypeErrors(unittest.TestCase):
    def test_non_mapping_costs(self):
        gate = _gate()
        with self.assertRaises(TypeError):
            gate.propose("goal", _subgoals(), 5, costs=[0.1])  # type: ignore[arg-type]

    def test_commit_non_gated_plan(self):
        gate = _gate()
        with self.assertRaises(TypeError):
            gate.commit("not-a-plan")  # type: ignore[arg-type]

    def test_release_non_gated_plan(self):
        gate = _gate()
        with self.assertRaises(TypeError):
            gate.release("not-a-plan")  # type: ignore[arg-type]

    def test_bad_budget_type(self):
        with self.assertRaises(TypeError):
            PlannerBudgetGate("nope")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
