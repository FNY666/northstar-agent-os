"""Tests for the step reliability budget (``step_reliability_budget``).

The rule under test: **a run's reliability is the product of its steps'**
-- under the independent-steps assumption, a run of ``n`` steps at per-step
success rate ``p`` contains at least one error with probability
``1 - p**n``.  Northstar converts that into three numbers (required step
rate, predicted failure probability, step ceiling) and refuses to start a
run whose measured rate cannot reach the target.

The tests below drive real paths through the module: the OSWorld 2.0
trajectory lengths (30 and 318 tool calls per task) are run through the
arithmetic and checked against reference values computed independently
(``decimal`` logs and an integer-power reference, not the module's own
formulas), and every illegal argument is checked to be refused.
"""
import math
import unittest
from decimal import Decimal, getcontext

from step_reliability_budget import (
    AdmissionVerdict,
    StepReliabilityError,
    admit,
    max_steps,
    required_step_rate,
    run_failure_probability,
)

getcontext().prec = 60


def _reference_failure_probability(p_step: float, n: int) -> float:
    """Independent reference for ``1 - p**n``: exact rational power.

    Uses :class:`fractions.Fraction` so the comparison does not lean on the
    module's own float exponentiation.
    """
    from fractions import Fraction

    exact = 1 - Fraction(p_step).limit_denominator(10**6) ** n
    return float(exact)


def _reference_required_rate(p_target: float, n: int) -> float:
    """Independent reference for ``p_target ** (1/n)`` via decimal logs."""
    target = Decimal(repr(p_target))
    ln = target.ln()
    return float((ln / Decimal(n)).exp())


def _reference_max_steps(p_meas: float, p_target: float) -> int:
    """Independent reference for ``floor(ln(target)/ln(measured))``."""
    num = Decimal(repr(p_target)).ln()
    den = Decimal(repr(p_meas)).ln()
    ratio = num / den
    return int(ratio.to_integral_value(rounding="ROUND_FLOOR"))


class RunFailureProbabilityTests(unittest.TestCase):
    """``1 - p**n``: the probability a run contains at least one error."""

    def test_formula_matches_independent_reference(self):
        """The arithmetic agrees with an independently computed value."""
        for p, n in ((0.95, 30), (0.95, 318), (0.999, 223), (0.5, 10), (1.0, 7)):
            self.assertAlmostEqual(
                run_failure_probability(p, n),
                _reference_failure_probability(p, n),
                delta=1e-9,
                msg=f"p={p} n={n}",
            )

    def test_osworld_2_0_thirty_step_trajectory(self):
        """p=0.95 over 30 steps: about 78.5% of runs contain an error."""
        self.assertAlmostEqual(run_failure_probability(0.95, 30), 0.785, delta=5e-4)
        self.assertAlmostEqual(
            run_failure_probability(0.95, 30),
            _reference_failure_probability(0.95, 30),
            delta=1e-9,
        )

    def test_osworld_2_0_318_step_trajectory_is_near_certain_failure(self):
        """p=0.95 over 318 steps: essentially every run contains an error."""
        value = run_failure_probability(0.95, 318)
        self.assertAlmostEqual(value, 1.0, delta=1e-6)
        self.assertGreater(value, 0.9999)

    def test_zero_steps_is_no_failure(self):
        """An empty run cannot contain an error."""
        self.assertEqual(run_failure_probability(0.95, 0), 0.0)
        self.assertEqual(run_failure_probability(1.0, 0), 0.0)

    def test_perfect_step_rate_never_fails(self):
        """p=1: no failure probability at any length."""
        self.assertEqual(run_failure_probability(1.0, 30), 0.0)
        self.assertEqual(run_failure_probability(1.0, 318), 0.0)

    def test_probability_increases_with_length(self):
        """Longer runs are riskier under the model."""
        short = run_failure_probability(0.95, 30)
        long = run_failure_probability(0.95, 318)
        self.assertLess(short, long)

    def test_illegal_arguments_are_refused(self):
        """Fail-closed: bad inputs raise, they do not return a number."""
        for bad_p in (0.0, -0.1, 1.5, float("nan"), float("inf")):
            with self.assertRaises(StepReliabilityError):
                run_failure_probability(bad_p, 30)
        with self.assertRaises(StepReliabilityError):
            run_failure_probability(0.95, -1)
        with self.assertRaises(StepReliabilityError):
            run_failure_probability(0.95, 30.5)
        with self.assertRaises(StepReliabilityError):
            run_failure_probability(0.95, True)
        with self.assertRaises(StepReliabilityError):
            run_failure_probability("0.95", 30)


class RequiredStepRateTests(unittest.TestCase):
    """``p_target ** (1/n)``: the per-step rate a run needs."""

    def test_formula_matches_independent_reference(self):
        """The arithmetic agrees with an independently computed value."""
        for target, n in ((0.8, 318), (0.8, 30), (0.95, 100), (0.5, 2)):
            self.assertAlmostEqual(
                required_step_rate(target, n),
                _reference_required_rate(target, n),
                delta=1e-9,
                msg=f"target={target} n={n}",
            )

    def test_osworld_2_0_target_requires_9993(self):
        """Target 0.8 over 318 steps needs p_req ~= 0.9993."""
        value = required_step_rate(0.8, 318)
        self.assertAlmostEqual(value, 0.9993, delta=5e-4)
        self.assertGreater(value, 0.999)
        self.assertLess(value, 1.0)

    def test_zero_steps_requires_nothing_and_succeeds(self):
        """n=0: the required rate is 1.0 and the run cannot fail."""
        self.assertEqual(required_step_rate(0.8, 0), 1.0)
        self.assertEqual(required_step_rate(0.1, 0), 1.0)

    def test_perfect_target_is_perfect_rate(self):
        """A target of 1.0 needs a flawless step."""
        self.assertEqual(required_step_rate(1.0, 30), 1.0)
        self.assertEqual(required_step_rate(1.0, 318), 1.0)

    def test_required_rate_is_the_inverse_of_the_failure_probability(self):
        """At the required rate the run-level success rate is the target."""
        required = required_step_rate(0.8, 318)
        self.assertAlmostEqual(
            1.0 - run_failure_probability(required, 318),
            0.8,
            delta=1e-9,
        )

    def test_illegal_arguments_are_refused(self):
        """Fail-closed on the target and the step count."""
        for bad_target in (0.0, -1.0, 1.01, float("nan")):
            with self.assertRaises(StepReliabilityError):
                required_step_rate(bad_target, 30)
        with self.assertRaises(StepReliabilityError):
            required_step_rate(0.8, -3)
        with self.assertRaises(StepReliabilityError):
            required_step_rate(0.8, 2.0)


class MaxStepsTests(unittest.TestCase):
    """``floor(ln(target) / ln(measured))``: the step ceiling."""

    def test_formula_matches_independent_reference(self):
        """The arithmetic agrees with an independently computed value."""
        for measured, target in ((0.999, 0.8), (0.95, 0.8), (0.9, 0.5), (0.99, 0.95)):
            self.assertEqual(
                max_steps(measured, target),
                _reference_max_steps(measured, target),
                msg=f"measured={measured} target={target}",
            )

    def test_measured_0999_allows_223_steps(self):
        """p_meas=0.999 with target 0.8: ceiling is 223 steps."""
        self.assertEqual(max_steps(0.999, 0.8), 223)

    def test_ceiling_is_the_last_length_that_still_meets_the_target(self):
        """One step past the ceiling breaks the target; the ceiling holds."""
        measured, target = 0.999, 0.8
        ceiling = max_steps(measured, target)
        self.assertGreaterEqual(measured**ceiling, target)
        self.assertLess(measured ** (ceiling + 1), target)

    def test_flawless_rate_is_unbounded(self):
        """p_meas >= 1: no finite ceiling -- represented as None."""
        self.assertIsNone(max_steps(1.0, 0.8))
        self.assertIsNone(max_steps(1.0, 1.0))

    def test_perfect_target_needs_no_steps(self):
        """A target of 1.0 is met by any length only if the rate is 1.0."""
        self.assertEqual(max_steps(0.9, 1.0), 0)

    def test_illegal_arguments_are_refused(self):
        """Fail-closed: a zero rate reaches no target below 1."""
        with self.assertRaises(StepReliabilityError):
            max_steps(0.0, 0.8)
        with self.assertRaises(StepReliabilityError):
            max_steps(-0.5, 0.8)
        with self.assertRaises(StepReliabilityError):
            max_steps(0.999, 0.0)
        with self.assertRaises(StepReliabilityError):
            max_steps(0.999, 1.5)


class AdmissionTests(unittest.TestCase):
    """Fail-closed admission: start the run, or refuse with the numbers."""

    def test_admits_when_measured_rate_meets_the_requirement(self):
        """p_meas >= p_req admits."""
        verdict = admit(0.999, 0.8, 100)
        self.assertTrue(verdict.admitted)
        self.assertEqual(verdict.gap, 0.0)
        self.assertGreaterEqual(verdict.measured_step_rate, verdict.required_step_rate)

    def test_refuses_osworld_2_0_trajectory_with_gap_and_prediction(self):
        """p=0.95 at 318 steps against target 0.8: refused, with the gap."""
        verdict = admit(0.95, 0.8, 318)
        self.assertFalse(verdict.admitted)
        self.assertAlmostEqual(verdict.required_step_rate, 0.9993, delta=5e-4)
        self.assertAlmostEqual(verdict.gap, 0.0493, delta=5e-4)
        self.assertAlmostEqual(verdict.predicted_failure_probability, 1.0, delta=1e-6)

    def test_refusal_is_data_not_an_exception(self):
        """A refusal returns a verdict; it does not raise."""
        verdict = admit(0.95, 0.8, 318)
        self.assertIsInstance(verdict, AdmissionVerdict)
        self.assertFalse(bool(verdict))
        self.assertIn("refusing to start", verdict.reason)

    def test_gap_is_the_shortfall_of_the_required_rate(self):
        """gap = p_req - p_meas, exactly."""
        verdict = admit(0.95, 0.8, 318)
        self.assertAlmostEqual(
            verdict.gap,
            verdict.required_step_rate - verdict.measured_step_rate,
            delta=1e-12,
        )

    def test_step_ceiling_refuses_a_trajectory_that_is_too_long(self):
        """Measured 0.999 at 300 steps exceeds the 223-step ceiling."""
        verdict = admit(0.999, 0.8, 300)
        self.assertFalse(verdict.admitted)
        self.assertEqual(verdict.max_steps, 223)
        self.assertGreater(verdict.steps, verdict.max_steps)

    def test_zero_step_run_is_admitted(self):
        """No steps: nothing can fail, so the run is admitted."""
        verdict = admit(0.95, 0.8, 0)
        self.assertTrue(verdict.admitted)
        self.assertEqual(verdict.predicted_failure_probability, 0.0)

    def test_illegal_arguments_are_refused(self):
        """Fail-closed on every argument of the gate."""
        with self.assertRaises(StepReliabilityError):
            admit(0.0, 0.8, 318)
        with self.assertRaises(StepReliabilityError):
            admit(0.95, 1.5, 318)
        with self.assertRaises(StepReliabilityError):
            admit(0.95, 0.8, -1)
        with self.assertRaises(StepReliabilityError):
            admit(0.95, 0.8, 1.5)


class SourceMappingTests(unittest.TestCase):
    """The three real paths, driven end to end."""

    def test_path_a_osworld_2_0_trajectory_lengths(self):
        """30 steps: ~79% risky. 318 steps: essentially certain."""
        self.assertAlmostEqual(run_failure_probability(0.95, 30), 0.785, delta=5e-4)
        self.assertAlmostEqual(run_failure_probability(0.95, 318), 1.0, delta=1e-6)

    def test_path_b_target_08_over_318_steps_refuses_measured_095(self):
        """Target 0.8 at 318 steps: measured 0.95 is refused with the gap."""
        required = required_step_rate(0.8, 318)
        self.assertAlmostEqual(required, 0.9993, delta=5e-4)
        verdict = admit(0.95, 0.8, 318)
        self.assertFalse(verdict.admitted)
        self.assertAlmostEqual(verdict.gap, required - 0.95, delta=1e-12)
        self.assertAlmostEqual(verdict.predicted_failure_probability, 1.0, delta=1e-6)

    def test_path_c_measured_0999_target_08_gives_223_step_ceiling(self):
        """Measured 0.999, target 0.8: ceiling 223 steps, 224 is over."""
        self.assertEqual(max_steps(0.999, 0.8), 223)
        self.assertTrue(admit(0.999, 0.8, 223).admitted)
        self.assertFalse(admit(0.999, 0.8, 224).admitted)

    def test_functions_are_deterministic_and_pure(self):
        """Two calls with the same input give the same number."""
        for _ in range(3):
            self.assertEqual(run_failure_probability(0.95, 318), run_failure_probability(0.95, 318))
            self.assertEqual(required_step_rate(0.8, 318), required_step_rate(0.8, 318))
            self.assertEqual(max_steps(0.999, 0.8), max_steps(0.999, 0.8))

    def test_model_matches_the_textbook_closed_form(self):
        """A sanity check against the plain algebraic identity."""
        p, n = 0.97, 77
        self.assertAlmostEqual(
            run_failure_probability(p, n),
            1.0 - math.exp(n * math.log(p)),
            delta=1e-12,
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
