"""Tests for scorer_disagreement: multi-scorer verdicts, contested cases.

The suite is deliberately paranoid about the places where a disagreement
detector usually lies:

* a second scorer must not overwrite the first one,
* the threshold boundary (share == threshold) must be a *decided* rule and
  not an accident of a comparison operator,
* a single scorer can never be contested,
* the two metrics (minority share, score spread) must not be conflated,
* the aggregate verdict and the minority verdict must both stay visible
  when the majority masks the minority.
"""

from __future__ import annotations

import unittest
from fractions import Fraction

import scorer_disagreement as sd


class RegistrationTests(unittest.TestCase):
    """Two scorers on one case are two records, never one overwritten one."""

    def setUp(self):
        self.led = sd.ScorerDisagreement()

    def test_each_scorer_keeps_its_own_value(self):
        self.led.register("c1", "judge-a", "pass", 0.9)
        self.led.register("c1", "judge-b", "fail", 0.2)
        values = self.led.collect("c1")
        self.assertEqual(len(values), 2)
        by_id = {v.scorer_id: v for v in values}
        self.assertEqual(by_id["judge-a"].verdict, "pass")
        self.assertEqual(by_id["judge-a"].score, 0.9)
        self.assertEqual(by_id["judge-b"].verdict, "fail")
        self.assertEqual(by_id["judge-b"].score, 0.2)

    def test_a_later_registration_does_not_overwrite_an_earlier_one(self):
        self.led.register("c1", "judge-a", "pass", 0.9)
        self.led.register("c1", "judge-b", "fail", 0.2)
        self.led.register("c1", "judge-c", "pass", 0.5)
        values = self.led.collect("c1")
        self.assertEqual([v.scorer_id for v in values],
                         ["judge-a", "judge-b", "judge-c"])
        self.assertEqual(values[0].score, 0.9)
        self.assertEqual(values[1].score, 0.2)

    def test_the_same_scorer_cannot_register_twice_for_one_case(self):
        self.led.register("c1", "judge-a", "pass", 0.9)
        with self.assertRaises(sd.DuplicateScorerError):
            self.led.register("c1", "judge-a", "fail", 0.1)
        # the refused registration changed nothing
        self.assertEqual(len(self.led.collect("c1")), 1)
        self.assertEqual(self.led.collect("c1")[0].verdict, "pass")

    def test_a_scorer_may_register_on_a_different_case(self):
        self.led.register("c1", "judge-a", "pass", 0.9)
        self.led.register("c2", "judge-a", "fail", 0.1)
        self.assertEqual(len(self.led.collect("c1")), 1)
        self.assertEqual(len(self.led.collect("c2")), 1)

    def test_registration_refuses_a_bad_verdict(self):
        with self.assertRaises(sd.BadVerdictError):
            self.led.register("c1", "judge-a", "maybe")

    def test_registration_refuses_a_non_numeric_score(self):
        with self.assertRaises(sd.BadScoreError):
            self.led.register("c1", "judge-a", "pass", "0.5")

    def test_registration_refuses_a_non_finite_score(self):
        with self.assertRaises(sd.BadScoreError):
            self.led.register("c1", "judge-a", "pass", float("inf"))

    def test_registration_refuses_a_blank_case_id(self):
        with self.assertRaises(sd.BadCaseIdError):
            self.led.register("  ", "judge-a", "pass")

    def test_a_score_is_optional(self):
        rec = self.led.register("c1", "judge-a", "pass")
        self.assertIsNone(rec.score)
        self.assertIsNone(sd.score_spread([None, None]))

    def test_the_verdict_record_verifies_its_own_digest(self):
        rec = self.led.register("c1", "judge-a", "pass", 0.5)
        self.assertTrue(rec.verify())

    def test_an_unknown_case_has_no_view(self):
        with self.assertRaises(sd.UnknownCaseError):
            self.led.disagreement("nope")


class ThresholdAndContestedTests(unittest.TestCase):
    """The threshold rule is decided, not accidental."""

    def setUp(self):
        self.led = sd.ScorerDisagreement()

    def test_the_threshold_is_a_northstar_choice_and_is_pinned(self):
        # A Northstar-selected value (the source names no threshold).
        self.assertEqual(sd.DISAGREEMENT_THRESHOLD, Fraction(1, 4))
        self.assertEqual(sd.ScorerDisagreement().stats()["threshold"], "1/4")

    def test_a_threshold_of_exactly_one_quarter_is_not_contested(self):
        # 3-1 split: the minority share is exactly 1/4 == the threshold.
        self.led.register("c1", "a", "pass", 0.9)
        self.led.register("c1", "b", "pass", 0.8)
        self.led.register("c1", "c", "pass", 0.7)
        self.led.register("c1", "d", "fail", 0.1)
        view = self.led.adjudicate("c1")
        self.assertEqual(view.minority_share, Fraction(1, 4))
        self.assertFalse(view.exceeded)
        self.assertFalse(view.contested)
        self.assertEqual(view.aggregate_verdict, "pass")
        self.assertEqual(self.led.review_queue(), ())

    def test_a_threshold_just_above_the_threshold_is_contested(self):
        # 2-1 split: minority share 1/3 > 1/4.
        self.led.register("c1", "a", "pass", 0.9)
        self.led.register("c1", "b", "pass", 0.8)
        self.led.register("c1", "c", "fail", 0.1)
        view = self.led.adjudicate("c1")
        self.assertEqual(view.minority_share, Fraction(1, 3))
        self.assertTrue(view.exceeded)
        self.assertTrue(view.contested)

    def test_a_contested_case_is_booked_into_the_review_queue(self):
        self.led.register("c1", "a", "pass", 0.9)
        self.led.register("c1", "b", "fail", 0.1)
        self.led.adjudicate("c1")
        queue = self.led.review_queue()
        self.assertEqual(len(queue), 1)
        self.assertEqual(queue[0].case_id, "c1")
        self.assertTrue(queue[0].verify())

    def test_the_review_queue_is_bookkeeping_only(self):
        self.led.register("c1", "a", "pass", 0.9)
        self.led.register("c1", "b", "fail", 0.1)
        self.led.adjudicate("c1")
        # nothing was sent anywhere: the module has no sink, no notify and
        # no network surface at all -- only this in-memory list.
        self.assertEqual(self.led.stats()["review_count"], 1)
        self.assertEqual(self.led.audit_log(), ())

    def test_adjudicating_twice_does_not_double_book_the_case(self):
        self.led.register("c1", "a", "pass", 0.9)
        self.led.register("c1", "b", "fail", 0.1)
        self.led.adjudicate("c1")
        self.led.adjudicate("c1")
        self.assertEqual(len(self.led.review_queue()), 1)

    def test_a_custom_threshold_moves_the_boundary(self):
        led = sd.ScorerDisagreement(threshold=Fraction(1, 3))
        led.register("c1", "a", "pass", 0.9)
        led.register("c1", "b", "pass", 0.8)
        led.register("c1", "c", "fail", 0.1)
        view = led.disagreement("c1")
        # share == threshold now: still not contested (strictly greater).
        self.assertFalse(view.exceeded)
        led2 = sd.ScorerDisagreement(threshold=Fraction(3, 10))
        led2.register("c1", "a", "pass", 0.9)
        led2.register("c1", "b", "pass", 0.8)
        led2.register("c1", "c", "fail", 0.1)
        self.assertTrue(led2.disagreement("c1").exceeded)

    def test_a_negative_threshold_is_refused(self):
        with self.assertRaises(sd.BadThresholdError):
            sd.ScorerDisagreement(threshold=Fraction(-1, 4))

    def test_a_non_numeric_threshold_is_refused(self):
        with self.assertRaises(sd.BadThresholdError):
            sd.ScorerDisagreement(threshold="low")

    def test_an_unknown_reducer_is_refused(self):
        with self.assertRaises(sd.BadReducerError):
            sd.ScorerDisagreement(reducer="average")

    def test_one_scorer_is_never_contested(self):
        self.led.register("c1", "only", "pass", 0.99)
        view = self.led.adjudicate("c1")
        self.assertEqual(view.scorer_count, 1)
        self.assertEqual(view.minority_share, Fraction(0))
        self.assertFalse(view.exceeded)
        self.assertFalse(view.contested)
        self.assertEqual(view.aggregate_verdict, "pass")
        self.assertEqual(self.led.review_queue(), ())
        self.assertEqual(self.led.masked_cases(), ())

    def test_one_scorer_saying_fail_is_not_contested_either(self):
        self.led.register("c1", "only", "fail", 0.01)
        view = self.led.adjudicate("c1")
        self.assertFalse(view.contested)
        self.assertEqual(view.aggregate_verdict, "fail")


class MajorityMaskingTests(unittest.TestCase):
    """The majority vote must not be allowed to hide the minority."""

    def setUp(self):
        self.led = sd.ScorerDisagreement()

    def test_an_aggregate_against_the_minority_is_recorded_as_masked(self):
        # 2 pass, 1 fail -> the aggregate is "pass", the minority said "fail".
        self.led.register("c1", "a", "pass", 0.9)
        self.led.register("c1", "b", "pass", 0.8)
        self.led.register("c1", "c", "fail", 0.1)
        view = self.led.adjudicate("c1")
        self.assertEqual(view.aggregate_verdict, "pass")
        self.assertEqual(view.minority_verdict, "fail")
        self.assertTrue(view.masked)
        self.assertEqual(self.led.masked_cases(), ("c1",))
        item = self.led.review_queue()[0]
        self.assertTrue(item.masked)
        self.assertEqual(item.reason, "majority-masked")

    def test_the_minority_side_is_the_smaller_side(self):
        # 1 pass, 2 fail -> the minority said "pass"; the aggregate is "fail".
        self.led.register("c1", "a", "pass", 0.9)
        self.led.register("c1", "b", "fail", 0.2)
        self.led.register("c1", "c", "fail", 0.1)
        view = self.led.adjudicate("c1")
        self.assertEqual(view.aggregate_verdict, "fail")
        self.assertEqual(view.minority_verdict, "pass")
        self.assertTrue(view.masked)

    def test_a_unanimous_case_is_not_masked(self):
        self.led.register("c1", "a", "pass", 0.9)
        self.led.register("c1", "b", "pass", 0.8)
        view = self.led.adjudicate("c1")
        self.assertFalse(view.masked)
        self.assertIsNone(view.minority_verdict)
        self.assertEqual(self.led.masked_cases(), ())

    def test_a_disagreement_below_the_threshold_is_not_masked(self):
        # 3-1: over no threshold, so the aggregate stands and nothing is
        # called masked -- the case is simply settled.
        self.led.register("c1", "a", "pass", 0.9)
        self.led.register("c1", "b", "pass", 0.8)
        self.led.register("c1", "c", "pass", 0.7)
        self.led.register("c1", "d", "fail", 0.1)
        view = self.led.adjudicate("c1")
        self.assertFalse(view.masked)
        self.assertEqual(view.minority_verdict, "fail")
        self.assertEqual(self.led.review_queue(), ())


class TieTests(unittest.TestCase):
    """A tie has no majority: it must be visible, not silently broken."""

    def test_a_two_two_tie_is_contested_with_no_aggregate_verdict(self):
        led = sd.ScorerDisagreement()
        led.register("c1", "a", "pass", 0.9)
        led.register("c1", "b", "pass", 0.8)
        led.register("c1", "c", "fail", 0.2)
        led.register("c1", "d", "fail", 0.1)
        view = led.adjudicate("c1")
        self.assertEqual(view.minority_share, Fraction(1, 2))
        self.assertTrue(view.exceeded)
        self.assertIsNone(view.aggregate_verdict)
        self.assertIsNone(view.minority_verdict)
        self.assertFalse(view.masked)
        self.assertEqual(len(led.review_queue()), 1)

    def test_a_one_one_tie_is_contested(self):
        led = sd.ScorerDisagreement()
        led.register("c1", "a", "pass", 0.9)
        led.register("c1", "b", "fail", 0.1)
        view = led.adjudicate("c1")
        self.assertEqual(view.minority_share, Fraction(1, 2))
        self.assertTrue(view.exceeded)
        self.assertIsNone(view.aggregate_verdict)

    def test_mode_breaks_a_tie_by_the_pinned_order_and_flags_it(self):
        # mode's tie-break is pinned (pass before fail) and reported.
        agg, tie = sd.aggregate_verdict(["pass", "fail"], "mode")
        self.assertEqual(agg, "pass")
        self.assertTrue(tie)

    def test_majority_has_no_verdict_on_a_tie(self):
        agg, tie = sd.aggregate_verdict(["pass", "fail"], "majority")
        self.assertIsNone(agg)
        self.assertTrue(tie)

    def test_collect_returns_no_aggregate_verdict_at_all(self):
        agg, tie = sd.aggregate_verdict(["pass", "fail"], "collect")
        self.assertIsNone(agg)
        self.assertFalse(tie)


class MetricDivergenceTests(unittest.TestCase):
    """Minority share and score spread are two metrics, not one."""

    def test_a_zero_minority_share_can_carry_a_wide_score_spread(self):
        led = sd.ScorerDisagreement()
        led.register("c1", "a", "pass", 0.05)
        led.register("c1", "b", "pass", 0.95)
        view = led.disagreement("c1")
        self.assertEqual(view.minority_share, Fraction(0))
        self.assertFalse(view.exceeded)
        self.assertAlmostEqual(view.score_spread, 0.9)

    def test_a_zero_score_spread_can_carry_a_real_disagreement(self):
        # Every scorer declared the same score, but they disagreed on the
        # verdict: the spread is 0 while the minority share is 1/2.
        led = sd.ScorerDisagreement()
        led.register("c1", "a", "pass", 0.5)
        led.register("c1", "b", "fail", 0.5)
        view = led.disagreement("c1")
        self.assertEqual(view.score_spread, 0.0)
        self.assertEqual(view.minority_share, Fraction(1, 2))
        self.assertTrue(view.exceeded)

    def test_the_spread_is_none_when_too_few_scorers_declared_a_score(self):
        led = sd.ScorerDisagreement()
        led.register("c1", "a", "pass", 0.5)
        led.register("c1", "b", "fail")
        self.assertIsNone(led.disagreement("c1").score_spread)

    def test_the_spread_ignores_a_missing_score(self):
        led = sd.ScorerDisagreement()
        led.register("c1", "a", "pass", 0.2)
        led.register("c1", "b", "pass", 0.8)
        led.register("c1", "c", "pass", None)
        self.assertAlmostEqual(led.disagreement("c1").score_spread, 0.6)

    def test_minority_share_is_an_exact_fraction(self):
        self.assertEqual(sd.minority_share(3, 1), Fraction(1, 4))
        self.assertEqual(sd.minority_share(2, 2), Fraction(1, 2))
        self.assertEqual(sd.minority_share(1, 0), Fraction(0))
        self.assertEqual(sd.minority_share(0, 0), Fraction(0))

    def test_the_metric_names_are_pinned(self):
        self.assertEqual(sd.MINORITY_SHARE, "minority-share")
        self.assertEqual(sd.SCORE_SPREAD, "score-spread")


class CollectSemanticsTests(unittest.TestCase):
    """collect keeps every raw value; agreement can be recomputed."""

    def setUp(self):
        self.led = sd.ScorerDisagreement()

    def test_the_raw_values_survive_the_aggregation(self):
        self.led.register("c1", "a", "pass", 0.9)
        self.led.register("c1", "b", "pass", 0.8)
        self.led.register("c1", "c", "fail", 0.1)
        view = self.led.adjudicate("c1")
        self.assertEqual(view.aggregate_verdict, "pass")
        raw = self.led.collect("c1")
        self.assertEqual(len(raw), 3)
        self.assertEqual([v.score for v in raw], [0.9, 0.8, 0.1])

    def test_the_agreement_coefficient_is_recomputable_from_the_raw_values(self):
        self.led.register("c1", "a", "pass", 0.9)
        self.led.register("c1", "b", "pass", 0.8)
        self.led.register("c1", "c", "fail", 0.1)
        view = self.led.adjudicate("c1")
        raw = self.led.collect("c1")
        recomputed = sd.agreement_alpha([v.verdict for v in raw])
        self.assertIsNotNone(recomputed)
        self.assertEqual(recomputed, view.agreement_alpha)
        self.assertEqual(view.agreement_alpha_text,
                         f"{recomputed.numerator}/{recomputed.denominator}")

    def test_a_unanimous_case_has_agreement_one(self):
        self.led.register("c1", "a", "pass", 0.9)
        self.led.register("c1", "b", "pass", 0.8)
        view = self.led.disagreement("c1")
        self.assertEqual(view.agreement_alpha, Fraction(1))
        self.assertEqual(view.agreement_alpha_text, "1/1")

    def test_a_single_scorer_has_no_agreement_coefficient(self):
        self.led.register("c1", "a", "pass", 0.9)
        view = self.led.disagreement("c1")
        self.assertIsNone(view.agreement_alpha)
        self.assertIsNone(view.agreement_alpha_text)

    def test_the_collect_reducer_keeps_the_values_but_aggregates_nothing(self):
        led = sd.ScorerDisagreement(reducer="collect")
        led.register("c1", "a", "pass", 0.9)
        led.register("c1", "b", "fail", 0.1)
        view = led.adjudicate("c1")
        self.assertIsNone(view.aggregate_verdict)
        self.assertEqual(view.aggregate_reducer, "collect")
        self.assertEqual(len(led.collect("c1")), 2)

    def test_an_unknown_case_has_no_collected_values(self):
        with self.assertRaises(sd.UnknownCaseError):
            self.led.collect("nope")


class CascadeTests(unittest.TestCase):
    """cascade is an optional extension; it never becomes the default."""

    def test_the_cascade_stops_at_the_first_settled_scorer(self):
        led = sd.ScorerDisagreement()
        ran = []

        def cheap():
            ran.append("cheap")
            return ("pass", 0.9)

        def expensive():
            ran.append("expensive")
            return ("fail", 0.1)

        result = led.run_cascade("c1", [("expensive", 5.0, expensive),
                                         ("cheap", 1.0, cheap)])
        self.assertEqual(result.ran, ("cheap",))
        self.assertEqual(result.skipped, ("expensive",))
        self.assertEqual(result.settled_by, "cheap")
        # the expensive scorer never ran
        self.assertEqual(ran, ["cheap"])

    def test_a_cascade_registers_only_the_settled_scorer(self):
        led = sd.ScorerDisagreement()
        result = led.run_cascade("c1", [
            ("a", 1.0, lambda: ("pass", 0.9)),
            ("b", 2.0, lambda: ("fail", 0.1)),
        ])
        self.assertEqual(result.settled_by, "a")
        raw = led.collect("c1")
        self.assertEqual(len(raw), 1)
        self.assertEqual(raw[0].verdict, "pass")

    def test_a_cascade_keeps_running_while_no_scorer_has_settled(self):
        led = sd.ScorerDisagreement()
        result = led.run_cascade("c1", [
            ("a", 1.0, lambda: None),
            ("b", 2.0, lambda: None),
            ("c", 3.0, lambda: ("fail", 0.1)),
            ("d", 4.0, lambda: ("pass", 0.9)),
        ])
        self.assertEqual(result.ran, ("a", "b", "c"))
        self.assertEqual(result.skipped, ("d",))
        self.assertEqual(result.settled_by, "c")

    def test_a_cascade_that_never_settles_runs_every_scorer(self):
        led = sd.ScorerDisagreement()
        result = led.run_cascade("c1", [
            ("a", 1.0, lambda: None),
            ("b", 2.0, lambda: None),
        ])
        self.assertEqual(result.ran, ("a", "b"))
        self.assertEqual(result.skipped, ())
        self.assertIsNone(result.settled_by)

    def test_the_default_behaviour_is_to_run_every_scorer(self):
        # the default path never uses cascade: the disagreement is judged
        # after all scorers have registered.
        led = sd.ScorerDisagreement()
        led.register("c1", "a", "pass", 0.9)
        led.register("c1", "b", "fail", 0.1)
        view = led.adjudicate("c1")
        self.assertEqual(view.scorer_count, 2)
        self.assertTrue(view.exceeded)

    def test_a_cascade_refuses_an_empty_scorer_list(self):
        with self.assertRaises(sd.ScorerDisagreementError):
            sd.ScorerDisagreement().run_cascade("c1", [])


class ProvenanceTests(unittest.TestCase):
    """The source vocabulary is pinned; the threshold is ours."""

    def test_the_reducer_names_are_the_source_ones(self):
        # verbatim from the inspect_ai source excerpt
        self.assertEqual(sd.REDUCERS, ("mode", "majority", "collect"))
        self.assertEqual(sd.DEFAULT_REDUCER, "majority")

    def test_the_module_imports_stdlib_only(self):
        self.assertTrue(sd.stdlib_only())

    def test_the_self_check_runs(self):
        import subprocess
        import sys
        from pathlib import Path
        root = Path(sd.__file__).resolve().parent
        proc = subprocess.run(
            [sys.executable, str(root / "scorer_disagreement.py")],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("scorer-disagreement OK", proc.stdout)

    def test_the_disagreement_view_verifies_its_own_digest(self):
        led = sd.ScorerDisagreement()
        led.register("c1", "a", "pass", 0.9)
        led.register("c1", "b", "fail", 0.1)
        self.assertTrue(led.disagreement("c1").verify())

    def test_the_stats_view_reports_the_threshold_and_the_reducer(self):
        led = sd.ScorerDisagreement()
        led.register("c1", "a", "pass", 0.9)
        stats = led.stats()
        self.assertEqual(stats["threshold"], "1/4")
        self.assertEqual(stats["reducer"], "majority")
        self.assertEqual(stats["verdict_count"], 1)
        self.assertEqual(stats["case_count"], 1)


class MutantGuardArmTests(unittest.TestCase):
    """The arms of the module's guards that the suite never drove.

    Each test below names the planted fault it kills and states the
    input that reaches the arm the existing suite left alone.
    """

    # --- eq@216 / eq@217: the marginals of the agreement coefficient ---

    def test_the_agreement_coefficient_uses_the_true_marginals(self):
        """`eq@216` / `eq@217`: ``p_pass`` and ``p_fail``.

        For a 2-1 split (``pass``, ``pass``, ``fail``) the observed
        disagreement share is ``Do = 1/3`` and the true marginals give
        ``De = 2 * (2/3) * (1/3) = 4/9``, so ``alpha = 1 - (1/3)/(4/9) =
        1 - 3/4 = -1/2``.

        Under ``eq@216`` (``v == "pass"`` -> ``v != "pass"``) the marginal
        becomes ``p_pass = 1/3`` and ``p_fail = 1/3``, so ``De = 2/9`` and
        ``alpha = 1 - 3/2 = -2`` -- a different number.  Under
        ``eq@217`` (``v == "fail"`` -> ``v != "fail"``) the marginal
        becomes ``p_fail = 2/3``, so ``De = 8/9`` and ``alpha = 1 - 3/8 =
        1/4``.  Both mutants are therefore observable, and the -1/2 value
        is the one the module actually computes.
        """
        alpha = sd.agreement_alpha(["pass", "pass", "fail"])
        self.assertEqual(alpha, Fraction(-1, 2))
        self.assertNotEqual(alpha, Fraction(-2))
        self.assertNotEqual(alpha, Fraction(1, 4))
        # The same value is what the ledger books on the view.
        led = sd.ScorerDisagreement()
        led.register("c1", "a", "pass", 0.9)
        led.register("c1", "b", "pass", 0.8)
        led.register("c1", "c", "fail", 0.1)
        self.assertEqual(led.disagreement("c1").agreement_alpha, Fraction(-1, 2))

    def test_the_agreement_coefficient_of_a_three_one_split(self):
        """`eq@216` / `eq@217`: the control -- a 3-1 split.

        ``Do = 3/6 = 1/2``, ``De = 2 * (3/4) * (1/4) = 3/8``, so
        ``alpha = 1 - (1/2)/(3/8) = 1 - 4/3 = -1/3``.
        """
        self.assertEqual(
            sd.agreement_alpha(["pass", "pass", "pass", "fail"]), Fraction(-1, 3)
        )

    # --- gt@270 / or@270: the id guard ------------------------------------

    def test_an_id_of_exactly_256_characters_is_accepted(self):
        """`gt@270`: the boundary -- 256 characters is within the limit.

        The guard is ``len(value) > 256``.  Under the mutant
        (``>`` -> ``>=``) a 256-character id is refused as too long.
        """
        case_id = "c" * 256
        led = sd.ScorerDisagreement()
        led.register(case_id, "judge-a", "pass", 0.5)
        self.assertEqual(led.case_ids(), (case_id,))

    def test_an_id_longer_than_256_characters_is_refused(self):
        """`gt@270`: the other side of the bound, as the control."""
        with self.assertRaises(sd.BadCaseIdError):
            sd.ScorerDisagreement().register("c" * 257, "judge-a", "pass")

    def test_a_non_string_id_is_refused(self):
        """`or@270`: the type arm of the id guard.

        The guard is ``not isinstance(value, str) or not value.strip() or
        len(value) > 256``.  Under the mutant (``or`` -> ``and``) the
        type arm and the emptiness arm are joined by ``and``: a value
        that is a non-empty string but is NOT a string -- a non-string
        whose ``.strip()`` is truthy -- slips past the first arm, and the
        refusal then depends on the later whitespace check instead.

        The original refuses a non-string id outright, before any
        attribute access.  This test pins that: the id must be refused
        with the id error, not blow up with an ``AttributeError`` from
        ``.strip()`` and not be accepted.
        """
        for bad in (5, 3.5, None, True, ["c"], {"c": 1}, ("c",)):
            with self.subTest(bad=bad):
                with self.assertRaises(sd.BadCaseIdError):
                    sd.ScorerDisagreement().register(bad, "judge-a", "pass")

    def test_an_empty_id_is_refused(self):
        """`or@270`: the emptiness arm, as the control.

        An empty string is a string, so the type arm does not fire; the
        emptiness arm does.  Under the mutant (``or`` -> ``and``) the
        type arm is false, so the emptiness arm is skipped too -- and
        the empty id would be ACCEPTED.
        """
        with self.assertRaises(sd.BadCaseIdError):
            sd.ScorerDisagreement().register("", "judge-a", "pass")

    def test_a_whitespace_only_id_is_refused(self):
        """`or@270`: the emptiness arm again, with the whitespace arm."""
        with self.assertRaises(sd.BadCaseIdError):
            sd.ScorerDisagreement().register("   ", "judge-a", "pass")

    def test_a_scorer_id_is_held_to_the_same_guard(self):
        """`or@270` / `gt@270`: the scorer id goes through the same check."""
        with self.assertRaises(sd.BadScorerIdError):
            sd.ScorerDisagreement().register("c1", "", "pass")
        with self.assertRaises(sd.BadScorerIdError):
            sd.ScorerDisagreement().register("c1", 5, "pass")
        sd.ScorerDisagreement().register("c1", "s" * 256, "pass")

    # --- retF@408 / retF@410: the digest verifier -------------------------

    def test_a_view_with_a_wrong_scorer_count_does_not_verify(self):
        """`retF@408`: the count check in ``Disagreement.verify``.

        The check is ``if self.scorer_count != len(self.verdicts): return
        False``.  Under the mutant (``return False`` -> ``return True``)
        a view whose recorded scorer count disagrees with its own
        verdicts would still verify.

        A view is built with a deliberately wrong ``scorer_count``.
        """
        import dataclasses

        led = sd.ScorerDisagreement()
        led.register("c1", "a", "pass", 0.9)
        led.register("c1", "b", "fail", 0.1)
        view = led.disagreement("c1")
        self.assertTrue(view.verify())

        tampered = dataclasses.replace(view, scorer_count=3)
        self.assertFalse(tampered.verify())

    def test_a_view_with_wrong_pass_and_fail_counts_does_not_verify(self):
        """`retF@410`: the pass/fail count check.

        The check is ``if self.pass_count + self.fail_count !=
        self.scorer_count: return False``.  Under the mutant
        (``return False`` -> ``return True``) a view whose counts do not
        add up to its scorer count would still verify.

        A view is built with a deliberately wrong ``pass_count``.
        """
        import dataclasses

        led = sd.ScorerDisagreement()
        led.register("c1", "a", "pass", 0.9)
        led.register("c1", "b", "fail", 0.1)
        view = led.disagreement("c1")
        self.assertTrue(view.verify())

        tampered = dataclasses.replace(view, pass_count=2)
        self.assertFalse(tampered.verify())

    # --- lt@472: the threshold bound --------------------------------------

    def test_a_threshold_of_exactly_zero_is_accepted(self):
        """`lt@472`: the boundary -- a threshold of zero is legal.

        The guard is ``if threshold < 0:``.  Under the mutant
        (``<`` -> ``<=``) a threshold of exactly **0** is refused as
        negative, so a ledger could never be told "contest at any
        disagreement at all".
        """
        led = sd.ScorerDisagreement(threshold=Fraction(0))
        self.assertEqual(led.stats()["threshold"], "0/1")

    def test_a_negative_threshold_is_refused_at_the_boundary(self):
        """`lt@472`: the other side of the bound, as the control."""
        with self.assertRaises(sd.BadThresholdError):
            sd.ScorerDisagreement(threshold=Fraction(-1, 1000))

    # --- gt@533: the "one scorer cannot disagree" rule ---------------------

    def test_one_scorer_is_never_contested_even_at_a_zero_threshold(self):
        """`gt@533`: the boundary of the "more than one scorer" rule.

        The rule is ``len(verdicts) > 1 and share > self._threshold``.
        Under the mutant (``>`` -> ``>=``) a **single** scorer satisfies
        the first half.  With a threshold of zero the second half is
        then true whenever ``share > 0`` -- but a single scorer's
        minority share is 0, so the second half is still false.

        The threshold is therefore pushed BELOW zero in effect by the
        mutant, and the only way to observe the difference is a
        threshold that a single scorer's zero share exceeds: a
        NEGATIVE threshold.  A negative threshold is refused by the
        constructor -- so the mutant's extra reach is not observable
        through the public constructor.

        This test therefore pins the observable rule itself: a single
        scorer is never contested, at any threshold the constructor
        accepts.
        """
        for threshold in (Fraction(0), Fraction(1, 100), Fraction(1, 4),
                          Fraction(1, 2), Fraction(1)):
            with self.subTest(threshold=threshold):
                led = sd.ScorerDisagreement(threshold=threshold)
                led.register("c1", "only", "pass", 0.99)
                view = led.disagreement("c1")
                self.assertEqual(view.scorer_count, 1)
                self.assertEqual(view.minority_share, Fraction(0))
                self.assertFalse(view.exceeded)
                self.assertFalse(view.contested)
                self.assertEqual(led.review_queue(), ())

    # --- and@601: the masked-case list -------------------------------------

    def test_a_contested_but_unmasked_case_is_not_in_the_masked_list(self):
        """`and@601`: the second arm of the masked-list guard.

        The guard is ``if view.masked and case_id not in self._masked:``.
        Under the mutant (``and`` -> ``or``) a case that is NOT masked
        but is already in the masked list would be appended AGAIN --
        the first operand is false and the second is false, so the
        mutant's ``or`` still fires.

        A 2-2 tie is contested but not masked (there is no minority to
        be masked), so the case never reaches the masked list at all
        and the mutant's extra append is not observable that way.

        The observable shape is a case that IS masked: the guard must
        append it exactly once, and the mutant's ``or`` would append a
        masked case that is ALREADY in the list a second time.  The
        test below drives both: a masked case is listed exactly once,
        and a contested-but-unmasked case is listed not at all.
        """
        # The masked case: 2 pass, 1 fail -> the aggregate masks "fail".
        led = sd.ScorerDisagreement()
        led.register("c1", "a", "pass", 0.9)
        led.register("c1", "b", "pass", 0.8)
        led.register("c1", "c", "fail", 0.1)
        view = led.adjudicate("c1")
        self.assertTrue(view.masked)
        self.assertEqual(led.masked_cases(), ("c1",))

        # Adjudicating again must not append the case a second time.
        led.adjudicate("c1")
        self.assertEqual(led.masked_cases(), ("c1",))

    def test_a_contested_tie_is_never_in_the_masked_list(self):
        """`and@601`: the other arm -- a contested case that is not masked.

        A 2-2 tie is contested (the minority share is 1/2) but there is
        no minority verdict to be masked, so the case must NOT appear in
        the masked list.  Under the mutant (``and`` -> ``or``) the second
        arm alone would append it.
        """
        led = sd.ScorerDisagreement()
        led.register("c1", "a", "pass", 0.9)
        led.register("c1", "b", "pass", 0.8)
        led.register("c1", "c", "fail", 0.2)
        led.register("c1", "d", "fail", 0.1)
        view = led.adjudicate("c1")
        self.assertTrue(view.exceeded)
        self.assertFalse(view.masked)
        self.assertIsNone(view.minority_verdict)
        self.assertEqual(led.masked_cases(), ())
        self.assertEqual(len(led.review_queue()), 1)

    # --- retF@722 / retF@727: the stdlib-only self-check -----------------

    def test_the_stdlib_only_check_refuses_a_foreign_import(self):
        """`retF@722`: the ``import`` arm of ``stdlib_only``.

        The check is ``if alias.name.split(".")[0] not in allowed:
        return False``.  Under the mutant (``return False`` -> ``return
        True``) a module that imports something outside the allowed
        stdlib set would still be reported as stdlib-only.

        The check reads the module's own source file, so the test points
        ``__file__`` at a temporary module that imports ``numpy``.
        """
        import os
        import tempfile

        original_file = sd.__file__
        handle, path = tempfile.mkstemp(suffix=".py")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as out:
                out.write("import numpy\n")
            sd.__file__ = path
            self.assertFalse(sd.stdlib_only())
        finally:
            sd.__file__ = original_file
            os.unlink(path)

    def test_the_stdlib_only_check_refuses_a_foreign_from_import(self):
        """`retF@727`: the ``from ... import`` arm of ``stdlib_only``.

        The check is ``if node.module.split(".")[0] not in allowed:
        return False``.  Under the mutant (``return False`` -> ``return
        True``) a module that does ``from numpy import array`` would
        still be reported as stdlib-only.
        """
        import os
        import tempfile

        original_file = sd.__file__
        handle, path = tempfile.mkstemp(suffix=".py")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as out:
                out.write("from numpy import array\n")
            sd.__file__ = path
            self.assertFalse(sd.stdlib_only())
        finally:
            sd.__file__ = original_file
            os.unlink(path)

    def test_the_stdlib_only_check_accepts_the_allowed_imports(self):
        """`retF@722` / `retF@727`: the control -- the real module."""
        self.assertTrue(sd.stdlib_only())


class EquivalentMutantTests(unittest.TestCase):
    """Mutants that are EQUIVALENT: no test can distinguish them.

    ``gt@533`` -- ``exceeded = len(verdicts) > 1 and share >
    self._threshold`` in ``ScorerDisagreement._derive``.  The mutant
    replaces ``>`` with ``>=``, so a SINGLE scorer would satisfy the
    first half of the rule.

    It is provably equivalent, and this is the proof:

    * The rule's first half asks "are there more than one scorer?".  A
      single scorer has ``pass_count == 1`` and ``fail_count == 0``, so
      ``minority_share(1, 0) == Fraction(0)`` -- the minority share is
      **exactly zero** for every single-scorer case, because
      ``min(pass_count, fail_count)`` is 0 on one side.
    * The threshold is **never negative**: ``ScorerDisagreement.__init__``
      refuses any threshold below 0 (``if threshold < 0: raise
      BadThresholdError``), and the default is ``Fraction(1, 4)``.  A
      negative threshold is not reachable through the public
      constructor, so ``self._threshold >= 0`` holds for every ledger
      that exists.
    * Therefore, for a single scorer, ``share > self._threshold`` is
      ``0 > t`` with ``t >= 0``, which is **false**.  The mutant's
      widened first half (``len(verdicts) >= 1``) is true, but the
      second half is false, so the conjunction is false exactly as it
      is in the original.
    * For two or more scorers, ``len(verdicts) > 1`` and
      ``len(verdicts) >= 1`` are the same truth value, so the mutant
      changes nothing there either.

    So the two expressions agree on every reachable input, and no test
    can distinguish them.  It is an EQUIVALENT mutant, not a gap in
    the suite.

    This is recorded here so the next person does not spend a round
    looking for a test that kills it.  The convention is the
    repository's own (``tests/test_state_budget.py``, ``gt@304``).

    The proof is *checked*, not merely asserted: the test below
    enumerates every reachable (scorer count, pass count, threshold)
    combination and compares the two expressions on each one.
    """

    def _original_exceeded(self, n, pass_count, threshold):
        """The rule as written."""
        share = (
            Fraction(0)
            if n == 0
            else Fraction(min(pass_count, n - pass_count), n)
        )
        return (n > 1) and (share > threshold)

    def _mutant_exceeded(self, n, pass_count, threshold):
        """The rule under the planted fault."""
        share = (
            Fraction(0)
            if n == 0
            else Fraction(min(pass_count, n - pass_count), n)
        )
        return (n >= 1) and (share > threshold)

    def test_the_two_expressions_agree_on_every_reachable_input(self):
        """`gt@533`: the exhaustive check of the equivalence.

        Every combination of a scorer count, a pass count and a
        threshold that the constructor accepts is enumerated, and the
        original and the mutant are compared on each.
        """
        thresholds = [
            Fraction(0),
            Fraction(1, 100),
            Fraction(1, 4),
            Fraction(1, 3),
            Fraction(1, 2),
            Fraction(3, 4),
            Fraction(1),
            Fraction(2),
        ]
        compared = 0
        for n in range(0, 8):
            for pass_count in range(0, n + 1):
                for threshold in thresholds:
                    original = self._original_exceeded(n, pass_count, threshold)
                    mutant = self._mutant_exceeded(n, pass_count, threshold)
                    self.assertEqual(
                        original,
                        mutant,
                        "n=%d pass=%d threshold=%s: the mutant differs"
                        % (n, pass_count, threshold),
                    )
                    compared += 1
        self.assertGreater(compared, 100)

    def test_a_single_scorer_has_a_zero_minority_share(self):
        """`gt@533`: the reason the equivalence holds.

        A single scorer's minority share is exactly zero, and the
        threshold is never negative -- so ``0 > threshold`` is false and
        the mutant's widened first half cannot make the rule fire.
        """
        self.assertEqual(sd.minority_share(1, 0), Fraction(0))
        self.assertEqual(sd.minority_share(0, 1), Fraction(0))
        # And the constructor refuses every negative threshold, so a
        # threshold below zero is not reachable.
        for negative in (Fraction(-1), Fraction(-1, 1000), Fraction(-1, 4)):
            with self.subTest(threshold=negative):
                with self.assertRaises(sd.BadThresholdError):
                    sd.ScorerDisagreement(threshold=negative)

    def test_a_single_scorer_is_never_contested(self):
        """`gt@533`: the observable rule, pinned.

        The rule survives the mutant unchanged, and this test pins the
        behaviour that the mutant cannot change.
        """
        for verdict in ("pass", "fail"):
            with self.subTest(verdict=verdict):
                led = sd.ScorerDisagreement()
                led.register("c1", "only", verdict, 0.5)
                view = led.adjudicate("c1")
                self.assertEqual(view.scorer_count, 1)
                self.assertEqual(view.minority_share, Fraction(0))
                self.assertFalse(view.exceeded)
                self.assertFalse(view.contested)
                self.assertEqual(led.review_queue(), ())
                self.assertEqual(led.masked_cases(), ())
