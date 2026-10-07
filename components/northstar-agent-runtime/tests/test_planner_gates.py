"""Tests for planner_gates: subgoal ceiling, proposal validation, critic review."""
from __future__ import annotations

import unittest

from planner_gates import (
    MAX_ESTIMATED_STEPS,
    MAX_SUBGOALS,
    Critic,
    CriticReview,
    CriticVerdict,
    InvalidPlan,
    PlanError,
    PlanProposal,
    Subgoal,
    TooManySubgoals,
    find_cycle,
    gate_plan,
    propose_plan,
)


def sg(sid, **kw):
    kw.setdefault("description", f"do {sid}")
    kw.setdefault("on_failure", "abort")
    return Subgoal(id=sid, **kw)


class CeilingTests(unittest.TestCase):
    def test_max_subgoals_is_five(self):
        self.assertEqual(MAX_SUBGOALS, 5)

    def test_five_subgoals_ok(self):
        plan = propose_plan("g", [sg(f"s{i}") for i in range(5)], 10)
        self.assertEqual(len(plan.subgoals), 5)

    def test_six_subgoals_raises(self):
        with self.assertRaises(TooManySubgoals):
            propose_plan("g", [sg(f"s{i}") for i in range(6)], 10)

    def test_too_many_is_plan_error(self):
        self.assertTrue(issubclass(TooManySubgoals, PlanError))

    def test_zero_subgoals_ok(self):
        plan = propose_plan("g", [], 1)
        self.assertEqual(plan.subgoals, ())


class ProposalValidationTests(unittest.TestCase):
    def test_blank_goal_rejected(self):
        with self.assertRaises(InvalidPlan):
            propose_plan("  ", [sg("a")], 1)

    def test_duplicate_ids_rejected(self):
        with self.assertRaises(InvalidPlan):
            propose_plan("g", [sg("a"), sg("a")], 1)

    def test_unknown_dependency_rejected(self):
        with self.assertRaises(InvalidPlan):
            propose_plan("g", [sg("a", depends_on=("ghost",))], 1)

    def test_self_dependency_rejected(self):
        with self.assertRaises(InvalidPlan):
            propose_plan("g", [sg("a", depends_on=("a",))], 1)

    def test_non_integer_steps_rejected(self):
        with self.assertRaises(InvalidPlan):
            propose_plan("g", [sg("a")], 2.5)

    def test_bool_steps_rejected(self):
        with self.assertRaises(InvalidPlan):
            propose_plan("g", [sg("a")], True)

    def test_zero_steps_rejected(self):
        with self.assertRaises(InvalidPlan):
            propose_plan("g", [sg("a")], 0)

    def test_steps_over_ceiling_rejected(self):
        with self.assertRaises(InvalidPlan):
            propose_plan("g", [sg("a")], MAX_ESTIMATED_STEPS + 1)

    def test_non_subgoal_rejected(self):
        with self.assertRaises(InvalidPlan):
            propose_plan("g", ["not-a-subgoal"], 1)

    def test_valid_dependency_accepted(self):
        plan = propose_plan(
            "g", [sg("a"), sg("b", depends_on=("a",))], 3
        )
        self.assertEqual(plan.subgoal_ids(), ("a", "b"))


class CycleDetectionTests(unittest.TestCase):
    def test_no_cycle(self):
        self.assertIsNone(find_cycle([sg("a"), sg("b", depends_on=("a",))]))

    def test_two_cycle(self):
        cycle = find_cycle(
            [sg("a", depends_on=("b",)), sg("b", depends_on=("a",))]
        )
        self.assertIsNotNone(cycle)
        self.assertEqual(cycle[0], cycle[-1])

    def test_self_loop_detected_by_find_cycle(self):
        # propose_plan rejects self-deps; find_cycle still sees them if built directly
        s = Subgoal(id="a", description="x", depends_on=("a",), on_failure="abort")
        cycle = find_cycle([s])
        self.assertEqual(cycle, ("a", "a"))

    def test_three_cycle(self):
        cycle = find_cycle(
            [
                sg("a", depends_on=("c",)),
                sg("b", depends_on=("a",)),
                sg("c", depends_on=("b",)),
            ]
        )
        self.assertIsNotNone(cycle)
        self.assertEqual(len(set(cycle)), 3)


class CriticTests(unittest.TestCase):
    def setUp(self):
        self.critic = Critic()

    def test_approves_well_formed_plan(self):
        plan = propose_plan(
            "g",
            [sg("a"), sg("b", depends_on=("a",))],
            5,
        )
        review = self.critic.review(plan)
        self.assertIs(review.verdict, CriticVerdict.APPROVE)
        self.assertEqual(review.reasons, ())

    def test_rejects_circular_dependency(self):
        plan = propose_plan("g", [sg("a"), sg("b")], 5)
        # build a cyclic plan directly (propose_plan allows it; critic catches it)
        a = Subgoal(id="a", description="x", depends_on=("b",), on_failure="abort")
        b = Subgoal(id="b", description="y", depends_on=("a",), on_failure="abort")
        cyclic = PlanProposal(goal="g", subgoals=(a, b), estimated_steps=5)
        review = self.critic.review(cyclic)
        self.assertIs(review.verdict, CriticVerdict.REJECT)
        self.assertTrue(
            any(r.startswith("circular-dependency") for r in review.reasons)
        )

    def test_rejects_unbounded_repeat(self):
        plan = propose_plan(
            "g", [sg("a", repeat=True)], 5  # no max_iterations
        )
        review = self.critic.review(plan)
        self.assertIs(review.verdict, CriticVerdict.REJECT)
        self.assertTrue(
            any(r.startswith("unbounded-loop") for r in review.reasons)
        )

    def test_rejects_repeat_with_zero_cap(self):
        plan = propose_plan(
            "g", [sg("a", repeat=True, max_iterations=0)], 5
        )
        review = self.critic.review(plan)
        self.assertIs(review.verdict, CriticVerdict.REJECT)

    def test_accepts_bounded_repeat(self):
        plan = propose_plan(
            "g", [sg("a", repeat=True, max_iterations=3)], 5
        )
        review = self.critic.review(plan)
        self.assertIs(review.verdict, CriticVerdict.APPROVE)

    def test_needs_revision_missing_failure_handling(self):
        plan = propose_plan(
            "g",
            [Subgoal(id="a", description="x", on_failure="")],
            5,
        )
        review = self.critic.review(plan)
        self.assertIs(review.verdict, CriticVerdict.NEEDS_REVISION)
        self.assertTrue(
            any(r.startswith("missing-failure-handling") for r in review.reasons)
        )

    def test_reject_beats_revision(self):
        a = Subgoal(id="a", description="x", depends_on=("b",), on_failure="")
        b = Subgoal(id="b", description="y", depends_on=("a",), on_failure="abort")
        plan = PlanProposal(goal="g", subgoals=(a, b), estimated_steps=5)
        review = self.critic.review(plan)
        self.assertIs(review.verdict, CriticVerdict.REJECT)

    def test_review_rejects_non_plan(self):
        with self.assertRaises(TypeError):
            self.critic.review("not a plan")

    def test_plan_is_runnable(self):
        good = propose_plan("g", [sg("a")], 2)
        self.assertTrue(self.critic.plan_is_runnable(good))
        bad = propose_plan(
            "g", [Subgoal(id="a", description="x", on_failure="")], 2
        )
        self.assertFalse(self.critic.plan_is_runnable(bad))

    def test_review_reasons_fixed_vocabulary(self):
        allowed = {
            "circular-dependency",
            "unbounded-loop",
            "unbounded-estimate",
            "missing-failure-handling",
        }
        a = Subgoal(id="a", description="x", depends_on=("b",), on_failure="")
        b = Subgoal(id="b", description="y", depends_on=("a",), on_failure="abort")
        plan = PlanProposal(goal="g", subgoals=(a, b), estimated_steps=5)
        review = self.critic.review(plan)
        for reason in review.reasons:
            head = reason.split(":")[0]
            self.assertIn(head, allowed)


class GateHelperTests(unittest.TestCase):
    def test_gate_plan_approve(self):
        plan = propose_plan("g", [sg("a")], 2)
        review = gate_plan(plan)
        self.assertIsInstance(review, CriticReview)
        self.assertIs(review.verdict, CriticVerdict.APPROVE)

    def test_gate_plan_custom_critic(self):
        plan = propose_plan("g", [sg("a")], 2)
        review = gate_plan(plan, critic=Critic())
        self.assertIs(review.verdict, CriticVerdict.APPROVE)

    def test_verdict_values(self):
        self.assertEqual(CriticVerdict.APPROVE.value, "approve")
        self.assertEqual(CriticVerdict.NEEDS_REVISION.value, "needs_revision")
        self.assertEqual(CriticVerdict.REJECT.value, "reject")


class SerializationTests(unittest.TestCase):
    def test_as_dict_round_trip(self):
        plan = propose_plan(
            "g",
            [sg("a"), sg("b", depends_on=("a",), on_failure="retry:3")],
            7,
        )
        d = plan.as_dict()
        self.assertEqual(d["goal"], "g")
        self.assertEqual(len(d["subgoals"]), 2)
        self.assertEqual(d["estimated_steps"], 7)
        self.assertEqual(d["subgoals"][1]["on_failure"], "retry:3")

    def test_review_as_dict(self):
        plan = propose_plan(
            "g", [Subgoal(id="a", description="x", on_failure="")], 2
        )
        review = Critic().review(plan)
        d = review.as_dict()
        self.assertEqual(d["verdict"], "needs_revision")
        self.assertTrue(d["reasons"])

    def test_main_runs(self):
        import subprocess
        import sys
        from pathlib import Path

        mod = Path(__file__).resolve().parent.parent / "planner_gates.py"
        out = subprocess.run(
            [sys.executable, str(mod)], capture_output=True, text=True
        )
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("planner-gates OK", out.stdout)


if __name__ == "__main__":
    unittest.main()
