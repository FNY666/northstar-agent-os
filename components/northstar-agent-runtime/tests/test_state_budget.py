"""Tests for the hard state-size cap absorbed from Jido's StateBudget.

The rules under test (from the slice brief):

* ``max_state_size`` must be a positive int -- a budget without a cap is
  not a budget, so construction fails closed.
* a transition that fits is accepted and ``current_size`` moves.
* a transition that does not fit is explicitly refused (``OverBudget``)
  carrying the current size, the cap and the delta's byte contribution;
  the delta is not applied and ``current_size`` does not move.
* ``check()`` is True inside the budget and False outside;
  ``check_or_raise()`` raises outside and is silent inside.
* the measurement is canonical: key order does not change the byte count.
* ``would_fit()`` agrees with what ``transition()`` actually does;
  ``bytes_over_budget()`` is numerically right.
* the budget is checked **at every transition** -- there is no path that
  accumulates small deltas and only reconciles at a checkpoint.

The last point is the one the other twelve cannot substitute for, so
:class:`FullPathTests` drives one run end to end instead of asserting the
parts in isolation.
"""
from __future__ import annotations

import unittest

import state_budget
from state_budget import (
    OverBudget,
    StateBudget,
    StateBudgetError,
    measure_state,
)


class DeclarationTests(unittest.TestCase):
    """A budget must declare a positive cap."""

    def test_max_state_size_must_be_a_positive_int(self):
        for bad in (0, -1, -100):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    StateBudget(max_state_size=bad)

    def test_max_state_size_must_not_be_a_bool_or_float(self):
        for bad in (True, False, 1.5, "100", None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    StateBudget(max_state_size=bad)

    def test_a_budget_with_a_cap_can_be_declared(self):
        budget = StateBudget(max_state_size=1024)
        self.assertEqual(budget.max_state_size, 1024)
        self.assertEqual(budget.current_size, 0)
        self.assertEqual(budget.unit, "bytes")


class MeasurementTests(unittest.TestCase):
    """The unit is bytes of canonical JSON, and it is reproducible."""

    def test_measurement_is_canonical_across_key_order(self):
        left = {"a": 1, "b": {"x": 1, "y": 2}}
        right = {"b": {"y": 2, "x": 1}, "a": 1}
        self.assertEqual(measure_state(left), measure_state(right))
        self.assertEqual(
            StateBudget(max_state_size=1024).size_of(left),
            StateBudget(max_state_size=1024).size_of(right),
        )

    def test_measurement_is_byte_count_of_canonical_json(self):
        state = {"a": 1}
        self.assertEqual(measure_state(state), len(b'{"a":1}'))

    def test_a_state_that_cannot_be_canonicalized_is_refused(self):
        with self.assertRaises(StateBudgetError):
            measure_state({"bad": object()})


class CheckTests(unittest.TestCase):
    """``check`` and ``check_or_raise`` are the Jido ``check``/``check!`` pair."""

    def test_check_is_true_inside_the_budget_and_false_outside(self):
        budget = StateBudget(max_state_size=len(b'{"a":1}'))
        self.assertTrue(budget.check({"a": 1}))
        self.assertFalse(budget.check({"a": 1, "b": 2}))

    def test_check_or_raise_raises_outside_the_budget(self):
        budget = StateBudget(max_state_size=len(b'{"a":1}'))
        with self.assertRaises(OverBudget) as ctx:
            budget.check_or_raise({"a": 1, "b": 2})
        self.assertEqual(ctx.exception.max_state_size, len(b'{"a":1}'))
        self.assertEqual(ctx.exception.current_size, len(b'{"a":1,"b":2}'))

    def test_check_or_raise_is_silent_inside_the_budget(self):
        budget = StateBudget(max_state_size=1024)
        self.assertIsNone(budget.check_or_raise({"a": 1}))


class TransitionTests(unittest.TestCase):
    """The transition path: accept inside the budget, refuse outside it."""

    def test_transition_inside_the_budget_updates_current_size(self):
        budget = StateBudget(max_state_size=1024)
        result = budget.transition({"a": 1}, {"b": "two"})
        self.assertEqual(result.state, {"a": 1, "b": "two"})
        self.assertEqual(result.current_size, measure_state({"a": 1, "b": "two"}))
        self.assertEqual(result.budget.current_size, result.current_size)

    def test_transition_outside_the_budget_is_refused_and_state_is_untouched(self):
        budget = StateBudget(max_state_size=64)
        before = {"a": 1}
        with self.assertRaises(OverBudget):
            budget.transition(before, {"b": "x" * 200})
        # the caller's state is not mutated in place either
        self.assertEqual(before, {"a": 1})
        self.assertEqual(budget.current_size, 0)

    def test_refusal_carries_current_size_cap_and_delta_bytes(self):
        budget = StateBudget(max_state_size=64)
        state = {"a": 1}
        delta = {"b": "x" * 200}
        with self.assertRaises(OverBudget) as ctx:
            budget.transition(state, delta)
        exc = ctx.exception
        self.assertEqual(exc.current_size, measure_state(state))
        self.assertEqual(exc.max_state_size, 64)
        self.assertEqual(exc.delta_bytes, measure_state({**state, **delta}) - exc.current_size)
        self.assertEqual(exc.projected_size, exc.current_size + exc.delta_bytes)

    def test_try_transition_refuses_with_the_budget_untouched(self):
        budget = StateBudget(max_state_size=64)
        outcome = budget.try_transition({"a": 1}, {"b": "x" * 200})
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.state, {"a": 1})
        self.assertEqual(outcome.budget.current_size, 0)
        self.assertIsInstance(outcome.refusal, OverBudget)
        self.assertEqual(outcome.refusal.delta_bytes, outcome.refusal.projected_size - outcome.refusal.current_size)

    def test_try_transition_accepts_inside_the_budget(self):
        budget = StateBudget(max_state_size=1024)
        outcome = budget.try_transition({"a": 1}, {"b": "two"})
        self.assertTrue(outcome.accepted)
        self.assertIsNone(outcome.refusal)
        self.assertEqual(outcome.state, {"a": 1, "b": "two"})


class PlanningTests(unittest.TestCase):
    """``would_fit`` and ``bytes_over_budget`` are the caller's planning tools."""

    def test_would_fit_agrees_with_the_actual_transition(self):
        budget = StateBudget(max_state_size=64)
        state = {"a": 1}
        fitting = {"b": "x" * 10}
        too_big = {"b": "x" * 200}
        self.assertTrue(budget.would_fit(state, fitting))
        self.assertFalse(budget.would_fit(state, too_big))
        # and the transition agrees with the prediction, both ways
        self.assertEqual(budget.transition(state, fitting).state, {**state, **fitting})
        with self.assertRaises(OverBudget):
            budget.transition(state, too_big)

    def test_bytes_over_budget_is_numerically_right(self):
        state = {"a": 1}
        size = measure_state(state)
        tight = StateBudget(max_state_size=size - 5)
        self.assertEqual(tight.bytes_over_budget(state), 5)
        loose = StateBudget(max_state_size=size)
        self.assertEqual(loose.bytes_over_budget(state), 0)

    def test_module_level_measure_helper_is_exported(self):
        self.assertIs(state_budget.measure_state, measure_state)


class FullPathTests(unittest.TestCase):
    """One run, driven end to end -- the budget is a per-transition cap.

    This is the test that matters: the parts above could each be right
    while the *system* still deferred the check to a checkpoint.  Here a run
    grows state by small deltas and the transition that would cross the cap
    is refused **at that transition** -- the state before it is intact and
    ``current_size`` has not moved past the cap.
    """

    def test_the_cap_is_enforced_at_every_transition_not_at_a_checkpoint(self):
        budget = StateBudget(max_state_size=512)
        state: dict = {}

        # (a) three transitions that fit -- each one checked, each one accepted.
        for index in range(3):
            delta = {"step": index, "note": "n" * 40}
            self.assertTrue(budget.would_fit(state, delta))
            result = budget.transition(state, delta)
            state = result.state
            self.assertEqual(result.budget.current_size, measure_state(state))
            self.assertLessEqual(result.current_size, 512)

        # (b) a transition that does not fit is refused at the transition.
        state_before = dict(state)
        size_before = measure_state(state)
        with self.assertRaises(OverBudget) as ctx:
            budget.transition(state, {"blob": "z" * 600})
        exc = ctx.exception
        self.assertEqual(exc.current_size, size_before)
        self.assertEqual(exc.max_state_size, 512)
        self.assertGreater(exc.delta_bytes, 0)

        # (c) the refused delta was not applied and current_size did not move.
        self.assertEqual(state, state_before)
        self.assertEqual(budget.current_size, size_before)

        # (d) check_or_raise on the over-budget state raises; on the in-budget
        #     state it is silent.
        with self.assertRaises(OverBudget):
            budget.check_or_raise({**state, "blob": "z" * 600})
        self.assertIsNone(budget.check_or_raise(state))

    def test_accumulating_small_deltas_is_refused_on_the_crossing_transition(self):
        # The anti-pattern being ruled out: many small deltas, none of which
        # trips a per-delta check, and the overrun only noticed at the end.
        budget = StateBudget(max_state_size=300)
        state: dict = {}
        accepted = 0
        refused = 0
        for index in range(50):
            delta = {f"k{index}": "p" * 30}
            outcome = budget.try_transition(state, delta)
            if outcome.accepted:
                accepted += 1
                state = outcome.state
                # the cap holds *after every accepted transition*
                self.assertLessEqual(outcome.budget.current_size, 300)
            else:
                refused += 1
                # the refusal happens on the crossing transition, not later
                self.assertEqual(outcome.budget.current_size, measure_state(state))
                break
        self.assertGreater(accepted, 0)
        self.assertEqual(refused, 1)
        self.assertLessEqual(measure_state(state), 300)
        # no transition was ever accepted beyond the cap
        self.assertLessEqual(budget.current_size, 300)


if __name__ == "__main__":
    unittest.main()
