"""Tests for the horizon admission gate: only tasks inside the verified
80% horizon.

The rules under test (from the slice brief):

* the gate is declared with three mandatory inputs -- the verified 80%
  horizon in human minutes, the horizon's interval, and the number of
  tasks that pinned the horizon down.  Missing any one of them is a
  refusal: a horizon with no interval and no sample size is not a
  verified horizon.
* only the 80% horizon is an admission line; a 50% horizon is refused at
  construction with the reason stated.
* a horizon longer than 960 minutes (16 hours) is refused: such a
  measurement isn't reliable with the current tasks.
* a task within the 80% horizon is ADMITTED, with the task minutes, the
  horizon and the interval in the verdict.
* a task longer than the 80% horizon is REFUSED, with the overage and a
  "decompose it or route it to a human" recommendation; nothing is taken
  in.
* a task inside the interval but close to its upper bound is FLAGGED, with
  the reason and an "enhanced monitoring" recommendation.
* the verdict is a three-state value (ADMITTED / FLAGGED / REFUSED), not a
  boolean.
* the report states the horizon, its interval and its task count, and
  says whether the horizon is pinned: not pinned below 30 tasks,
  basically pinned at 150 or more, pinned at 1,000 or more.

:class:`FullPathTests` drives the three real paths end to end rather than
asserting the parts in isolation.
"""
from __future__ import annotations

import unittest

import horizon_gate
from horizon_gate import (
    AdmissionStatus,
    BadTaskDuration,
    HorizonDeclarationError,
    HorizonGate,
    HorizonGateError,
    pinning_verdict,
)

# A gate used across the tests: 80% horizon of 60 minutes, interval
# 38-74 minutes, pinned down by 150 tasks.  The interval values are the
# source's own table (150 tasks -> 38-74min for a 60-minute horizon).
H = 60
LOW = 38
HIGH = 74
COUNT = 150


def make_gate(**overrides) -> HorizonGate:
    """A valid gate, with optional overrides."""
    kwargs = {
        "verified_80_horizon_minutes": H,
        "horizon_interval": (LOW, HIGH),
        "task_count": COUNT,
    }
    kwargs.update(overrides)
    return HorizonGate(**kwargs)


class DeclarationTests(unittest.TestCase):
    """The gate must be declared with a verified horizon, or not exist."""

    def test_a_valid_gate_can_be_declared(self):
        gate = make_gate()
        self.assertEqual(gate.verified_80_horizon_minutes, 60.0)
        self.assertEqual(gate.horizon_interval, (38.0, 74.0))
        self.assertEqual(gate.task_count, 150)
        self.assertEqual(gate.horizon_percentile, 80)
        self.assertEqual(gate.unit, "human_minutes")

    def test_missing_interval_is_refused(self):
        with self.assertRaises(HorizonDeclarationError) as ctx:
            HorizonGate(
                verified_80_horizon_minutes=H,
                horizon_interval=None,
                task_count=COUNT,
            )
        self.assertIn("interval", str(ctx.exception))

    def test_missing_task_count_is_refused(self):
        with self.assertRaises(HorizonDeclarationError) as ctx:
            HorizonGate(
                verified_80_horizon_minutes=H,
                horizon_interval=(LOW, HIGH),
                task_count=None,
            )
        self.assertIn("task_count", str(ctx.exception))

    def test_missing_horizon_is_refused(self):
        with self.assertRaises(HorizonDeclarationError):
            HorizonGate(
                verified_80_horizon_minutes=None,
                horizon_interval=(LOW, HIGH),
                task_count=COUNT,
            )

    def test_zero_or_negative_task_count_is_refused(self):
        for bad in (0, -1):
            with self.subTest(bad=bad):
                with self.assertRaises(HorizonDeclarationError):
                    make_gate(task_count=bad)

    def test_a_50_percent_horizon_is_refused_with_the_reason(self):
        with self.assertRaises(HorizonDeclarationError) as ctx:
            make_gate(horizon_percentile=50)
        message = str(ctx.exception)
        self.assertIn("50", message)
        self.assertIn("80", message)
        self.assertIn("headline", message)

    def test_a_horizon_above_960_minutes_is_refused(self):
        with self.assertRaises(HorizonDeclarationError) as ctx:
            make_gate(
                verified_80_horizon_minutes=961,
                horizon_interval=(600, 1200),
                task_count=1000,
            )
        self.assertIn("960", str(ctx.exception))
        self.assertIn("reliable", str(ctx.exception))

    def test_exactly_960_minutes_is_still_allowed(self):
        gate = make_gate(
            verified_80_horizon_minutes=960,
            horizon_interval=(700, 1200),
            task_count=1000,
        )
        self.assertEqual(gate.verified_80_horizon_minutes, 960.0)

    def test_an_interval_that_excludes_the_point_estimate_is_refused(self):
        with self.assertRaises(HorizonDeclarationError):
            make_gate(horizon_interval=(70, 90))

    def test_a_zero_width_interval_is_refused(self):
        with self.assertRaises(HorizonDeclarationError):
            make_gate(horizon_interval=(60, 60))

    def test_a_reversed_interval_is_refused(self):
        with self.assertRaises(HorizonDeclarationError):
            make_gate(horizon_interval=(74, 38))

    def test_every_refusal_is_a_horizon_gate_error(self):
        with self.assertRaises(HorizonGateError):
            make_gate(task_count=None)


class AdmissionTests(unittest.TestCase):
    """The three admission decisions."""

    def test_task_within_the_horizon_is_admitted(self):
        gate = make_gate()
        verdict = gate.admit(30)
        self.assertIs(verdict.status, AdmissionStatus.ADMITTED)
        self.assertEqual(verdict.task_human_minutes, 30.0)
        self.assertEqual(verdict.verified_80_horizon_minutes, 60.0)
        self.assertEqual(verdict.interval_low_minutes, 38.0)
        self.assertEqual(verdict.interval_high_minutes, 74.0)
        self.assertIsNone(verdict.overage_minutes)

    def test_task_exactly_at_the_horizon_is_admitted(self):
        gate = make_gate()
        verdict = gate.admit(60)
        self.assertIs(verdict.status, AdmissionStatus.ADMITTED)

    def test_task_over_the_horizon_is_refused_with_the_overage(self):
        gate = make_gate()
        verdict = gate.admit(180)
        self.assertIs(verdict.status, AdmissionStatus.REFUSED)
        self.assertEqual(verdict.overage_minutes, 120.0)
        self.assertIn("120", verdict.reason)
        self.assertIn("decompose", verdict.recommendation.lower())
        self.assertIn("human", verdict.recommendation.lower())

    def test_a_refusal_takes_no_task_in(self):
        gate = make_gate()
        gate.admit(180)
        self.assertEqual(gate.admitted_count, 0)
        self.assertEqual(gate.flagged_count, 0)
        self.assertEqual(gate.refused_count, 1)

    def test_task_inside_the_interval_but_close_to_the_top_is_flagged(self):
        gate = make_gate()
        verdict = gate.admit(70)
        self.assertIs(verdict.status, AdmissionStatus.FLAGGED)
        self.assertIn("70", verdict.reason)
        self.assertIn("monitor", verdict.recommendation.lower())
        self.assertIsNone(verdict.overage_minutes)

    def test_a_flagged_task_is_still_taken_in(self):
        gate = make_gate()
        gate.admit(70)
        self.assertEqual(gate.admitted_count, 0)
        self.assertEqual(gate.flagged_count, 1)
        self.assertEqual(gate.refused_count, 0)

    def test_the_verdict_is_three_states_not_a_boolean(self):
        statuses = {
            make_gate().admit(30).status,
            make_gate().admit(70).status,
            make_gate().admit(180).status,
        }
        self.assertEqual(len(statuses), 3)
        self.assertIsInstance(AdmissionStatus.ADMITTED, str)
        for status in statuses:
            self.assertNotIsInstance(status, bool)

    def test_a_task_just_outside_the_margin_is_admitted(self):
        # 74 - 10 (margin) = 64; 55 is not "within 10 of 74", and 55 is
        # under the 60-minute horizon, so it is simply admitted.
        gate = make_gate()
        verdict = gate.admit(55)
        self.assertIs(verdict.status, AdmissionStatus.ADMITTED)

    def test_the_margin_is_caller_supplied(self):
        # The same task: with a 20-minute margin 55 is within the margin of
        # the interval's top (74 - 55 = 19) and gets flagged; with the
        # default 10-minute margin it is not.
        self.assertIs(
            make_gate(margin_minutes=20).admit(55).status,
            AdmissionStatus.FLAGGED,
        )
        self.assertIs(
            make_gate(margin_minutes=10).admit(55).status,
            AdmissionStatus.ADMITTED,
        )

    def test_a_task_above_the_interval_top_is_refused_not_flagged(self):
        # 80 is over the horizon and past the interval's top bound of 74:
        # the flag band is inside the interval, so this is a refusal.
        gate = make_gate()
        verdict = gate.admit(80)
        self.assertIs(verdict.status, AdmissionStatus.REFUSED)
        self.assertEqual(verdict.overage_minutes, 20.0)

    def test_a_task_below_the_interval_low_is_still_admitted(self):
        # 30 is under the interval's low bound of 38 but under the 80%
        # horizon too: shorter than the horizon is not a risk.
        gate = make_gate()
        verdict = gate.admit(30)
        self.assertIs(verdict.status, AdmissionStatus.ADMITTED)

    def test_a_bad_task_duration_is_refused(self):
        gate = make_gate()
        for bad in (0, -5, None, "60", True):
            with self.subTest(bad=bad):
                with self.assertRaises(BadTaskDuration):
                    gate.admit(bad)

    def test_the_verdict_serialises_with_its_evidence(self):
        verdict = make_gate().admit(30)
        payload = verdict.as_dict()
        self.assertEqual(payload["status"], "admitted")
        self.assertEqual(payload["task_human_minutes"], 30.0)
        self.assertEqual(payload["verified_80_horizon_minutes"], 60.0)
        self.assertEqual(payload["interval_low_minutes"], 38.0)
        self.assertEqual(payload["interval_high_minutes"], 74.0)
        self.assertEqual(payload["task_count"], 150)
        self.assertEqual(payload["unit"], "human_minutes")


class ReportTests(unittest.TestCase):
    """The report states the horizon, its interval, and how firm it is."""

    def test_report_carries_horizon_interval_and_task_count(self):
        report = make_gate().report()
        self.assertEqual(report.verified_80_horizon_minutes, 60.0)
        self.assertEqual(report.interval_low_minutes, 38.0)
        self.assertEqual(report.interval_high_minutes, 74.0)
        self.assertEqual(report.interval_width_minutes, 36.0)
        self.assertEqual(report.task_count, 150)
        self.assertEqual(report.percentile, 80)

    def test_fewer_than_30_tasks_is_not_pinned(self):
        report = make_gate(task_count=29).report()
        self.assertEqual(report.pinned, "not_pinned")
        self.assertIn("NOT pinned", report.pinning_note)
        self.assertIn("27min-2.3h", report.pinning_note)

    def test_150_tasks_is_basically_pinned(self):
        report = make_gate(task_count=150).report()
        self.assertEqual(report.pinned, "basically_pinned")
        self.assertIn("38-74min", report.pinning_note)

    def test_1000_tasks_is_pinned(self):
        report = make_gate(task_count=1000).report()
        self.assertEqual(report.pinned, "pinned")
        self.assertIn("58-73min", report.pinning_note)

    def test_the_pinning_ladder_boundaries_are_exact(self):
        self.assertEqual(pinning_verdict(29)[0], "not_pinned")
        self.assertEqual(pinning_verdict(30)[0], "not_pinned")
        self.assertEqual(pinning_verdict(149)[0], "not_pinned")
        self.assertEqual(pinning_verdict(150)[0], "basically_pinned")
        self.assertEqual(pinning_verdict(999)[0], "basically_pinned")
        self.assertEqual(pinning_verdict(1000)[0], "pinned")

    def test_report_serialises(self):
        payload = make_gate().report().as_dict()
        self.assertEqual(payload["task_count"], 150)
        self.assertEqual(payload["percentile"], 80)
        self.assertIn("pinned", payload)


class FullPathTests(unittest.TestCase):
    """The three real paths, driven end to end.

    These are the paths the slice brief names: an admitted task, a refused
    task, and a flagged task.  Each one is driven through a real gate and
    checked on what the gate recorded, not on a part in isolation.
    """

    def test_path_a_a_task_inside_the_horizon_is_taken_in(self):
        gate = make_gate()
        verdict = gate.admit(30)
        self.assertIs(verdict.status, AdmissionStatus.ADMITTED)
        self.assertTrue(verdict.admitted)
        self.assertEqual(gate.admitted_count, 1)
        self.assertEqual(gate.flagged_count, 0)
        self.assertEqual(gate.refused_count, 0)
        # The verdict carries the task minutes, the horizon and the interval.
        self.assertEqual(verdict.task_human_minutes, 30.0)
        self.assertEqual(verdict.verified_80_horizon_minutes, 60.0)
        self.assertEqual(
            (verdict.interval_low_minutes, verdict.interval_high_minutes),
            (38.0, 74.0),
        )
        self.assertEqual(gate.report().task_count, 150)

    def test_path_b_a_task_over_the_horizon_is_not_taken_in(self):
        gate = make_gate()
        verdict = gate.admit(180)
        self.assertIs(verdict.status, AdmissionStatus.REFUSED)
        self.assertFalse(verdict.admitted)
        # Nothing was taken in: the gate holds no admitted task.
        self.assertEqual(gate.admitted_count, 0)
        self.assertEqual(gate.refused_count, 1)
        # The verdict says by how much, and what to do about it.
        self.assertEqual(verdict.overage_minutes, 120.0)
        self.assertIn("120", verdict.reason)
        recommendation = verdict.recommendation.lower()
        self.assertIn("decompose", recommendation)
        self.assertIn("human", recommendation)

    def test_path_c_a_task_near_the_interval_top_is_taken_in_with_a_flag(self):
        gate = make_gate()
        verdict = gate.admit(70)
        self.assertIs(verdict.status, AdmissionStatus.FLAGGED)
        # Flagged is still "taken in", but not silently.
        self.assertTrue(verdict.admitted)
        self.assertEqual(gate.flagged_count, 1)
        self.assertEqual(gate.admitted_count, 0)
        self.assertEqual(gate.refused_count, 0)
        # The verdict carries the reason and the monitoring recommendation.
        self.assertIn("70", verdict.reason)
        self.assertIn("interval", verdict.reason)
        self.assertIn("monitor", verdict.recommendation.lower())

    def test_the_three_paths_on_one_gate_keep_their_accounting(self):
        gate = make_gate()
        verdicts = [gate.admit(30), gate.admit(180), gate.admit(70)]
        self.assertEqual(
            [v.status for v in verdicts],
            [
                AdmissionStatus.ADMITTED,
                AdmissionStatus.REFUSED,
                AdmissionStatus.FLAGGED,
            ],
        )
        self.assertEqual(gate.admitted_count, 1)
        self.assertEqual(gate.refused_count, 1)
        self.assertEqual(gate.flagged_count, 1)
        self.assertEqual(len(gate.decisions()), 3)

    def test_the_gate_reports_its_own_state(self):
        gate = make_gate()
        gate.admit(30)
        gate.admit(180)
        gate.admit(70)
        payload = gate.as_dict()
        self.assertEqual(payload["admitted_count"], 1)
        self.assertEqual(payload["refused_count"], 1)
        self.assertEqual(payload["flagged_count"], 1)
        self.assertEqual(payload["percentile"], 80)
        self.assertEqual(payload["horizon_interval"], [38.0, 74.0])


class ModuleShapeTests(unittest.TestCase):
    """The module's own pins and names."""

    def test_version_and_unit_pins(self):
        self.assertEqual(horizon_gate.UNIT, "human_minutes")
        self.assertEqual(horizon_gate.HORIZON_GATE_VERSION, "horizon-gate.v1")
        self.assertEqual(
            horizon_gate.HORIZON_GATE_SCHEMA, "northstar.horizon-gate.v1"
        )

    def test_the_thresholds_come_from_the_source(self):
        self.assertEqual(horizon_gate.REQUIRED_PERCENTILE, 80)
        self.assertEqual(horizon_gate.MAX_RELIABLE_HORIZON_MINUTES, 960)
        self.assertEqual(horizon_gate.NOT_PINNED_TASK_LIMIT, 30)
        self.assertEqual(horizon_gate.BASICALLY_PINNED_TASK_COUNT, 150)
        self.assertEqual(horizon_gate.PINNED_TASK_COUNT, 1000)
        self.assertEqual(horizon_gate.DEFAULT_MARGIN_MINUTES, 10)


class SecondHalfGuardTests(unittest.TestCase):
    """The second half of each guard in the horizon gate.

    Every guard in this module is a conjunction of two independent
    conditions, and a suite that drives only one of them leaves the
    other half free.  The tests below drive the half the rest of the
    suite does not, so each guard's two halves are both covered.
    """

    # -- lt@250: the sign half of the number guard --------------------

    def test_a_negative_interval_bound_is_refused(self):
        """`lt@250`: the sign half of the non-negative number guard.

        The type half is covered elsewhere; this is the input that is a
        perfectly good number of the right type and is still refused.
        """
        with self.assertRaises(HorizonDeclarationError) as ctx:
            make_gate(horizon_interval=(-1, HIGH))
        self.assertIn("non-negative", str(ctx.exception))

    def test_a_zero_interval_low_is_allowed(self):
        """`lt@250`: the boundary -- zero is non-negative, so it is kept.

        This is the discriminating input: a mutant that turns ``< 0``
        into ``<= 0`` refuses a zero bound, and this test says a zero
        bound is a legal interval.
        """
        gate = make_gate(horizon_interval=(0, HIGH))
        self.assertEqual(gate.interval_low_minutes, 0.0)

    def test_a_negative_interval_top_is_refused(self):
        """`lt@250`: the same guard, on the interval's other bound."""
        with self.assertRaises(HorizonDeclarationError):
            make_gate(horizon_interval=(LOW, -1))

    def test_a_negative_margin_is_refused(self):
        """`lt@403`: the sign half of the non-negative margin guard.

        The margin is an int of the right type; only its sign is wrong.
        """
        with self.assertRaises(HorizonDeclarationError) as ctx:
            make_gate(margin_minutes=-1)
        self.assertIn("non-negative", str(ctx.exception))

    def test_a_zero_margin_is_allowed(self):
        """`lt@403`: the boundary -- zero is non-negative, so it is kept.

        This is the discriminating input: a mutant that turns ``< 0``
        into ``<= 0`` refuses zero, and this test says zero is fine.
        """
        gate = make_gate(margin_minutes=0)
        self.assertEqual(gate.margin_minutes, 0)

    # -- and@284: the sequence half of the interval-shape guard -------

    def test_a_list_of_two_bounds_is_an_interval(self):
        """`and@284`: the "and it is a list" half.

        The suite elsewhere drives the mapping half.  A list of two
        bounds is the other shape the guard accepts.
        """
        gate = make_gate(horizon_interval=[LOW, HIGH])
        self.assertEqual(gate.interval_low_minutes, float(LOW))
        self.assertEqual(gate.interval_high_minutes, float(HIGH))

    def test_a_two_element_tuple_is_an_interval(self):
        """`and@284`: the "and it has two elements" half."""
        gate = make_gate(horizon_interval=(LOW, HIGH))
        self.assertEqual(gate.interval_low_minutes, float(LOW))

    def test_a_one_element_list_is_not_an_interval(self):
        """`and@284`: the length half -- one bound is not an interval."""
        with self.assertRaises(HorizonDeclarationError) as ctx:
            make_gate(horizon_interval=[LOW])
        self.assertIn("pair", str(ctx.exception))

    def test_a_three_element_list_is_not_an_interval(self):
        """`and@284`: the length half -- three bounds are not an interval."""
        with self.assertRaises(HorizonDeclarationError):
            make_gate(horizon_interval=[LOW, HIGH, 90])

    # -- gt@292: the strictness of the ordering guard -----------------

    def test_an_interval_whose_bounds_are_equal_is_refused_for_width(self):
        """`gt@292`: the "low must not exceed high" half.

        With equal bounds the ordering guard must not fire -- the width
        guard is the one that refuses a point estimate.  The message
        names which rule applied.
        """
        with self.assertRaises(HorizonDeclarationError) as ctx:
            make_gate(horizon_interval=(60, 60))
        message = str(ctx.exception)
        self.assertIn("width", message)
        self.assertNotIn("must not exceed", message)

    def test_a_reversed_interval_is_refused_by_the_ordering_rule(self):
        """`gt@292`: the ordering half fires on a genuinely reversed pair.

        The message is the discriminator: the ordering rule says the low
        bound "must not exceed" the high bound.
        """
        with self.assertRaises(HorizonDeclarationError) as ctx:
            make_gate(horizon_interval=(74, 38))
        self.assertIn("must not exceed", str(ctx.exception))

    # -- or@399: the type half of the margin guard --------------------

    def test_a_boolean_margin_is_refused(self):
        """`or@399`: the type half of the margin guard, on a bool.

        A bool IS an int in Python, so the ``isinstance(..., bool)``
        half is the only thing that can catch it.
        """
        with self.assertRaises(HorizonDeclarationError) as ctx:
            make_gate(margin_minutes=True)
        self.assertIn("margin_minutes must be an int", str(ctx.exception))

    def test_a_float_margin_is_refused(self):
        """`or@399`: the other half -- a float is not an int margin."""
        with self.assertRaises(HorizonDeclarationError):
            make_gate(margin_minutes=10.0)

    def test_a_string_margin_is_refused(self):
        """`or@399`: the type guard on a non-numeric margin."""
        with self.assertRaises(HorizonDeclarationError):
            make_gate(margin_minutes="10")
