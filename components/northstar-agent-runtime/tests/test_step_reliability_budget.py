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

import step_reliability_budget
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


class StepReliabilityBudgetSecondHalfTests(unittest.TestCase):
    """The SECOND half of each guard in ``step_reliability_budget``.

    Two planted faults survived this slice's suite:

      or@83   the ``isinf`` half of the "must be finite" guard
      lt@152  the ``measured < 1.0`` bound inside ``max_steps``

    The first is killable and is driven below.

    ``lt@152`` is **not killable, and provably so**: the line is
    ``return math.floor(0.0 / math.log(measured)) if measured < 1.0 else
    None``, but the guard three lines above it already returns ``None``
    for every ``measured >= 1.0``.  So ``measured`` is *always* strictly
    below 1.0 at that point, the ``else None`` arm is UNREACHABLE, and
    ``measured < 1.0`` and ``measured <= 1.0`` select the same arm for
    every input that can reach the line.  It is an EQUIVALENT mutant,
    not a gap in the suite, and no test can distinguish it.  It is
    recorded here so the next person does not spend a round looking for
    one.
    """

    # --- or@83: the `isinf` half ----------------------------------------
    def test_an_infinite_rate_is_refused_as_non_finite(self):
        """`or@83`: **the ``isinf`` half of the finite guard**.

        The guard is ``if math.isnan(rate) or math.isinf(rate):``.  The
        ``isnan`` half refuses a NaN; only the ``isinf`` half refuses
        an infinity.  Under the mutant (``or`` -> ``and``) an infinity
        is no longer caught by the finite guard at all -- it falls
        through to the range check and is refused *there* instead, with
        a different message ("must be in (0, 1]" rather than "must be
        finite").  The refusal still happens, so the test asserts the
        MESSAGE: a non-finite rate must be reported as non-finite.
        """
        with self.assertRaises(StepReliabilityError) as caught:
            run_failure_probability(float("inf"), 30)
        self.assertIn("finite", str(caught.exception))

    def test_a_negative_infinite_rate_is_refused_as_non_finite(self):
        """`or@83`: the other infinity."""
        with self.assertRaises(StepReliabilityError) as caught:
            run_failure_probability(float("-inf"), 30)
        self.assertIn("finite", str(caught.exception))

    def test_an_infinite_rate_is_refused_as_non_finite_in_every_entry_point(self):
        """`or@83`: the same guard, reached through the other functions.

        Every public function routes its rate argument through
        ``_check_rate``, so the same finite-guard half is on the path of
        each of them.  ``admit`` takes two rates, so both are checked.
        """
        for call in (
            lambda: required_step_rate(float("inf"), 30),
            lambda: max_steps(float("inf"), 0.8),
            lambda: admit(float("inf"), 0.8, 30),
            lambda: admit(0.95, float("inf"), 30),
        ):
            with self.assertRaises(StepReliabilityError) as caught:
                call()
            self.assertIn("finite", str(caught.exception))

    def test_a_nan_rate_is_refused_as_non_finite(self):
        """`or@83`: the control -- the ``isnan`` half, which still works.

        Both halves of the guard refuse a non-finite rate; this pins the
        half the existing suite already covered, so the two tests
        together cover the whole disjunction.
        """
        with self.assertRaises(StepReliabilityError) as caught:
            run_failure_probability(float("nan"), 30)
        self.assertIn("finite", str(caught.exception))

    def test_a_finite_rate_is_not_reported_as_non_finite(self):
        """`or@83`: the control -- a finite rate is not refused at all."""
        self.assertAlmostEqual(run_failure_probability(0.95, 30), 0.785, delta=5e-4)

    # --- lt@152: an EQUIVALENT mutant, recorded ------------------------
    def test_the_perfect_target_gives_zero_steps_for_every_rate_below_one(self):
        """`lt@152`: the behaviour the line produces, and why it is equivalent.

        ``max_steps(p_meas, 1.0)`` is the number of steps a run of
        ``p_meas``-reliable steps may have and still succeed *every*
        time.  A target of 1.0 is met only by a flawless step, so the
        answer is 0 for every rate below 1, and ``None`` (unbounded) for
        a flawless step.

        The planted fault at this site (``<`` -> ``<=``) is an
        EQUIVALENT mutant: the guard three lines above already returns
        ``None`` for every ``measured >= 1.0``, so ``measured`` is
        always strictly below 1.0 when this line is reached, the
        ``else None`` arm is unreachable, and ``<`` and ``<=`` pick the
        same arm for every input that can arrive here.  This test pins
        the behaviour so the equivalence is visible rather than
        assumed.
        """
        for measured in (0.001, 0.01, 0.1, 0.5, 0.9, 0.99, 0.999, 0.9999):
            self.assertEqual(max_steps(measured, 1.0), 0, msg=f"measured={measured}")
        self.assertIsNone(max_steps(1.0, 1.0))

    def test_the_perfect_target_gives_zero_steps_through_admit(self):
        """`lt@152`: the same line, reached through the admission gate."""
        for measured in (0.5, 0.9, 0.999):
            verdict = admit(measured, 1.0, 30)
            self.assertEqual(verdict.max_steps, 0, msg=f"measured={measured}")
        self.assertIsNone(admit(1.0, 1.0, 30).max_steps)

    def test_the_perfect_target_zero_step_ceiling_is_the_last_holding_length(self):
        """`lt@152`: the zero ceiling is consistent with the formula.

        The ceiling is the last length whose run-level success still
        meets the target.  For a target of 1.0 and a rate below 1, only
        the zero-step run qualifies, so the ceiling is 0 and one step is
        over it.
        """
        for measured in (0.5, 0.9, 0.999):
            self.assertEqual(max_steps(measured, 1.0), 0)
            self.assertGreaterEqual(measured**0, 1.0)
            self.assertLess(measured**1, 1.0)

    def test_the_lt_152_mutant_is_differentially_equivalent(self):
        """`lt@152`: PROOF that the planted fault changes nothing.

        The planted fault rewrites ``measured < 1.0`` as
        ``measured <= 1.0``.  This test builds that opposite variant of
        the module and compares the two versions over a large set of
        valid inputs: if the fault changed any result, this test would
        fail.

        It does not: over the grid and 200,000 randomised rate pairs the
        two versions agree on every value and every exception.  That is
        the differential proof that ``lt@152`` is an EQUIVALENT mutant
        and not a gap in the suite.

        The variant is built by swapping the comparison on the ``max_steps``
        line whichever way it currently reads, so the test compares two
        genuinely different sources when the module is unmutated, and
        degrades to comparing the module with itself when it is not --
        it never asserts that the source text differs, because that
        would be a structural check rather than a behavioural one.
        """
        import importlib.util
        import random
        import sys
        import types

        module_path = step_reliability_budget.__file__
        with open(module_path, encoding="utf-8") as handle:
            source = handle.read()

        def opposite_variant(text):
            """Swap ``< 1.0`` / ``<= 1.0`` on the ``max_steps`` line."""
            out_lines = []
            swapped = 0
            for line in text.splitlines(keepends=True):
                if "math.floor(0.0 / math.log(measured)) if measured <" in line:
                    if "measured <= 1.0" in line:
                        line = line.replace("measured <= 1.0", "measured < 1.0")
                    else:
                        line = line.replace("measured < 1.0", "measured <= 1.0")
                    swapped += 1
                out_lines.append(line)
            return "".join(out_lines), swapped

        variant, swapped = opposite_variant(source)
        self.assertEqual(swapped, 1, "the lt@152 mutant site was not found")

        def load(name, text):
            spec = importlib.util.spec_from_loader(name, loader=None)
            module = types.ModuleType(name)
            module.__file__ = f"<{name}>"
            sys.modules[name] = module
            exec(compile(text, module.__file__, "exec"), module.__dict__)
            return module

        original_module = load("srb_original", source)
        variant_module = load("srb_variant", variant)

        def outcome(module, function, *args):
            try:
                return ("ok", getattr(module, function)(*args))
            except Exception as exc:  # noqa: BLE001
                return ("raise", type(exc).__name__, str(exc))

        grid = (0.001, 0.01, 0.05, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99, 0.999, 0.9999, 1.0)
        pairs = [(a, b) for a in grid for b in grid]
        random.seed(7)
        for _ in range(200000):
            measured = min(1.0, random.choice(grid) * random.uniform(0.2, 1.8))
            target = min(1.0, random.choice(grid) * random.uniform(0.2, 1.8))
            pairs.append((measured, target))
        for measured, target in pairs:
            self.assertEqual(
                outcome(original_module, "max_steps", measured, target),
                outcome(variant_module, "max_steps", measured, target),
                msg=f"measured={measured} target={target}",
            )
        self.assertGreater(len(pairs), 200000)
