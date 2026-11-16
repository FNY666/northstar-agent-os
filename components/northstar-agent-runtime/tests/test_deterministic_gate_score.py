"""Tests for the deterministic gate-and-score ledger.

Covers the acceptance rules of the deterministic-gate-score slice:

- the pass rule (a case passes iff every named deterministic gate passes;
  a failing gate names itself; an empty gate set and duplicate gate names
  are refused fail-closed);
- the three states (scored / unscored / errored) and their bookkeeping;
- the aggregate denominator (scored cases only; errored and unscored are
  out; all three counts are always reported);
- ``score_on_error`` (partial state scored, failure counted in the
  denominator, the error still recorded);
- retry eligibility (errored may be scored again, unscored does not
  trigger a retry, scored is final);
- the three real paths: an ALE-shaped case with three gates, a scorer that
  dies mid-way with an API error, and a scorer that reaches no verdict.
"""

from __future__ import annotations

import unittest

from deterministic_gate_score import (
    OUTCOME_ERRORED,
    OUTCOME_SCORED,
    OUTCOME_UNSCORED,
    NO_VERDICT,
    CaseOutcome,
    CaseSpec,
    DuplicateCaseError,
    DuplicateGateError,
    EmptyGateSetError,
    Gate,
    GateExecutionError,
    GateScoreLedger,
    BadCaseError,
    BadGateSetError,
    BadMetricError,
    SeqOrderError,
    aggregate,
    is_retryable,
    run_gates,
    score_case,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def digest(seed: str) -> str:
    """A syntactically valid digest pin for a test seed."""
    return "sha256:" + (seed * 64)[:64]


def three_gates():
    """The ALE-shaped gate set: three named deterministic checks."""
    return [
        Gate("artifact_present", lambda a: bool(a.get("artifact")), "artifacts/out.txt"),
        Gate("schema_valid", lambda a: a.get("schema") == "v1", "artifacts/out.json"),
        Gate("no_marker", lambda a: not a.get("marker"), "artifacts/out.txt"),
    ]


def good_artifact():
    return {"artifact": True, "schema": "v1", "marker": False}


class GateSetValidationTests(unittest.TestCase):
    """Fail-closed edges of the gate set."""

    def test_empty_gate_set_is_refused(self):
        ledger = GateScoreLedger()
        with self.assertRaises(EmptyGateSetError):
            ledger.score("case-empty", DIGEST_A, [], good_artifact(), 0)

    def test_duplicate_gate_name_is_refused(self):
        ledger = GateScoreLedger()
        gates = [
            Gate("same", lambda a: True, "e1"),
            Gate("same", lambda a: False, "e2"),
        ]
        with self.assertRaises(DuplicateGateError):
            ledger.score("case-dup", DIGEST_A, gates, good_artifact(), 0)

    def test_non_callable_or_non_bool_gate_is_refused(self):
        with self.assertRaises(BadGateSetError):
            Gate("not-callable", "nope", "e1")
        ledger = GateScoreLedger()
        gates = [Gate("truthy", lambda a: 1, "e1")]
        with self.assertRaises(GateExecutionError):
            ledger.score("case-truthy", DIGEST_A, gates, good_artifact(), 0)

    def test_bad_digest_pin_is_refused(self):
        ledger = GateScoreLedger()
        with self.assertRaises(BadCaseError):
            ledger.score("case-bad-digest", "not-a-pin", three_gates(),
                         good_artifact(), 0)

    def test_seq_must_strictly_increase(self):
        ledger = GateScoreLedger()
        ledger.score("c1", DIGEST_A, three_gates(), good_artifact(), 5)
        with self.assertRaises(SeqOrderError):
            ledger.score("c2", DIGEST_B, three_gates(), good_artifact(), 5)
        with self.assertRaises(SeqOrderError):
            ledger.score("c3", DIGEST_C, three_gates(), good_artifact(), -1)


class PassRuleTests(unittest.TestCase):
    """A case passes iff every named deterministic gate passes."""

    def test_all_gates_pass_means_case_passes(self):
        ledger = GateScoreLedger()
        outcome = ledger.score("case-all-pass", DIGEST_A, three_gates(),
                               good_artifact(), 0)
        self.assertEqual(outcome.outcome, OUTCOME_SCORED)
        self.assertTrue(outcome.passed)
        self.assertEqual(outcome.metric, 1.0)
        self.assertEqual(outcome.failed_gates, ())
        self.assertEqual(outcome.passed_gates,
                         ("artifact_present", "schema_valid", "no_marker"))

    def test_one_failing_gate_fails_case_and_names_itself(self):
        ledger = GateScoreLedger()
        artifact = good_artifact()
        artifact["schema"] = "v0"
        outcome = ledger.score("case-one-fail", DIGEST_A, three_gates(),
                               artifact, 0)
        self.assertEqual(outcome.outcome, OUTCOME_SCORED)
        self.assertFalse(outcome.passed)
        self.assertEqual(outcome.metric, 0.0)
        self.assertEqual(outcome.failed_gates, ("schema_valid",))
        self.assertNotIn("schema_valid", outcome.passed_gates)

    def test_every_failing_gate_is_named(self):
        report = run_gates(three_gates(), {"artifact": False, "schema": "v0"})
        self.assertFalse(report.passed)
        self.assertEqual(report.failed_gates,
                         ("artifact_present", "schema_valid"))

    def test_gate_evidence_pointer_is_kept(self):
        ledger = GateScoreLedger()
        outcome = ledger.score("case-evidence", DIGEST_A, three_gates(),
                               good_artifact(), 0)
        booking = ledger.booking("case-evidence")
        self.assertEqual(booking.outcome.passed_gates,
                         ("artifact_present", "schema_valid", "no_marker"))
        gate = three_gates()[0]
        self.assertEqual(gate.evidence, "artifacts/out.txt")


class TriStateTests(unittest.TestCase):
    """The three states and their bookkeeping."""

    def test_scored_outcome_has_a_metric_and_a_verdict(self):
        outcome = CaseOutcome(case_id="c", outcome=OUTCOME_SCORED,
                              passed=True, metric=0.5)
        self.assertTrue(outcome.scored)
        self.assertFalse(outcome.unscored)
        self.assertFalse(outcome.errored)
        self.assertTrue(outcome.counts_in_denominator)

    def test_unscored_is_nan_and_out_of_the_aggregates(self):
        ledger = GateScoreLedger()
        outcome = ledger.mark_unscored("case-unscored", DIGEST_A,
                                       "solver reached no verdict", 0)
        self.assertEqual(outcome.outcome, OUTCOME_UNSCORED)
        self.assertTrue(outcome.unscored)
        self.assertIsNone(outcome.passed)
        self.assertNotEqual(outcome.metric, outcome.metric)  # NaN
        self.assertFalse(outcome.counts_in_denominator)
        report = ledger.report()
        self.assertEqual(report.unscored_count, 1)
        self.assertEqual(report.scored_count, 0)
        self.assertEqual(report.pass_rate_text, "n/a")

    def test_errored_records_the_error_and_produces_no_score(self):
        ledger = GateScoreLedger()
        outcome = ledger.mark_errored("case-errored", DIGEST_A,
                                       "HTTPError: 503 upstream", 0)
        self.assertEqual(outcome.outcome, OUTCOME_ERRORED)
        self.assertIn("503", outcome.error)
        self.assertIsNone(outcome.passed)
        self.assertNotEqual(outcome.metric, outcome.metric)  # NaN
        self.assertFalse(outcome.counts_in_denominator)
        report = ledger.report()
        self.assertEqual(report.errored_count, 1)
        self.assertEqual(report.pass_rate_text, "n/a")

    def test_errored_and_unscored_stay_out_of_the_denominator(self):
        ledger = GateScoreLedger()
        ledger.score("case-pass", DIGEST_A, three_gates(), good_artifact(), 0)
        ledger.score("case-fail", DIGEST_B, three_gates(),
                     {"artifact": True, "schema": "v0"}, 1)
        ledger.mark_errored("case-err", DIGEST_C, "APIError", 2)
        ledger.mark_unscored("case-unscored", digest("d"), "no verdict", 3)
        report = ledger.report()
        self.assertEqual((report.scored_count, report.passed_count,
                          report.unscored_count, report.errored_count),
                         (2, 1, 1, 1))
        # the denominator is the scored cases only: 1/2, not 1/4
        self.assertEqual(report.pass_rate_text, "1/2")

    def test_report_always_states_all_three_counts(self):
        report = aggregate([
            CaseOutcome(case_id="a", outcome=OUTCOME_SCORED, passed=True,
                        metric=1.0),
            CaseOutcome(case_id="b", outcome=OUTCOME_UNSCORED,
                        metric=float("nan")),
            CaseOutcome(case_id="c", outcome=OUTCOME_ERRORED,
                        metric=float("nan"), error="boom"),
        ])
        as_dict = report.as_dict()
        for key in ("scored_count", "unscored_count", "errored_count"):
            self.assertIn(key, as_dict)
        self.assertEqual(as_dict["scored_count"], 1)
        self.assertEqual(as_dict["unscored_count"], 1)
        self.assertEqual(as_dict["errored_count"], 1)


class ScoreOnErrorTests(unittest.TestCase):
    """Scoring the state the solver had already reached."""

    def test_score_on_error_partial_failure_counts_in_denominator(self):
        ledger = GateScoreLedger()
        outcome = ledger.score("case-partial", DIGEST_A, three_gates(),
                               {"artifact": True, "schema": "v0"},
                               0, error="HTTPError: 503", score_on_error=True)
        self.assertEqual(outcome.outcome, OUTCOME_SCORED)
        self.assertFalse(outcome.passed)
        self.assertEqual(outcome.failed_gates, ("schema_valid",))
        self.assertIn("503", outcome.error)
        report = ledger.report()
        self.assertEqual(report.scored_count, 1)
        self.assertEqual(report.passed_count, 0)
        self.assertEqual(report.errored_count, 0)
        self.assertEqual(report.pass_rate_text, "0/1")

    def test_score_on_error_partial_pass_counts_as_pass(self):
        ledger = GateScoreLedger()
        outcome = ledger.score("case-partial-ok", DIGEST_A, three_gates(),
                               good_artifact(), 0, error="timeout",
                               score_on_error=True)
        self.assertEqual(outcome.outcome, OUTCOME_SCORED)
        self.assertTrue(outcome.passed)
        self.assertIn("timeout", outcome.error)
        self.assertEqual(ledger.report().pass_rate_text, "1/1")

    def test_without_score_on_error_the_error_is_not_scored(self):
        ledger = GateScoreLedger()
        outcome = ledger.score("case-hard-error", DIGEST_A, three_gates(),
                               good_artifact(), 0, error="HTTPError: 503")
        self.assertEqual(outcome.outcome, OUTCOME_ERRORED)
        self.assertFalse(outcome.counts_in_denominator)
        self.assertEqual(ledger.report().pass_rate_text, "n/a")


class RetryEligibilityTests(unittest.TestCase):
    """Who may be scored again."""

    def test_errored_case_is_retryable_and_scored_case_is_not(self):
        ledger = GateScoreLedger()
        ledger.mark_errored("case-err", DIGEST_A, "APIError", 0)
        ledger.score("case-scored", DIGEST_B, three_gates(), good_artifact(), 1)
        self.assertEqual(ledger.retryable_cases(), ("case-err",))
        self.assertTrue(is_retryable(OUTCOME_ERRORED))
        self.assertFalse(is_retryable(OUTCOME_SCORED))
        self.assertFalse(is_retryable(OUTCOME_UNSCORED))

    def test_unscored_case_does_not_trigger_a_retry(self):
        ledger = GateScoreLedger()
        ledger.mark_unscored("case-unscored", DIGEST_A, "no verdict", 0)
        self.assertEqual(ledger.retryable_cases(), ())
        self.assertFalse(ledger.booking("case-unscored").outcome.retryable)
        with self.assertRaises(DuplicateCaseError):
            ledger.mark_unscored("case-unscored", DIGEST_A, "no verdict", 1)

    def test_scored_case_cannot_be_booked_twice(self):
        ledger = GateScoreLedger()
        ledger.score("case-once", DIGEST_A, three_gates(), good_artifact(), 0)
        with self.assertRaises(DuplicateCaseError):
            ledger.score("case-once", DIGEST_A, three_gates(), good_artifact(), 1)

    def test_errored_case_can_be_scored_again(self):
        ledger = GateScoreLedger()
        first = ledger.mark_errored("case-retry", DIGEST_A, "HTTPError: 503", 0)
        self.assertEqual(first.attempt, 1)
        second = ledger.score("case-retry", DIGEST_A, three_gates(),
                              good_artifact(), 1)
        self.assertEqual(second.attempt, 2)
        self.assertEqual(second.outcome, OUTCOME_SCORED)
        self.assertEqual(ledger.booking("case-retry").attempts, 2)
        self.assertEqual(ledger.report().pass_rate_text, "1/1")


class RealPathTests(unittest.TestCase):
    """The three paths this slice exists for, driven end to end."""

    def test_path_a_ale_shape_three_gates_all_pass(self):
        """ALE shape: three deterministic gates, all pass -> case passes."""
        ledger = GateScoreLedger()
        artifact = {"artifact": True, "schema": "v1", "marker": False}
        outcome = score_case(ledger, "ale-001", DIGEST_A, three_gates(),
                             lambda: artifact, 0)
        self.assertEqual(outcome.outcome, OUTCOME_SCORED)
        self.assertTrue(outcome.passed)
        self.assertEqual(outcome.metric, 1.0)
        self.assertEqual(outcome.failed_gates, ())
        report = ledger.report()
        self.assertEqual(report.pass_rate_text, "1/1")
        self.assertEqual(report.errored_count, 0)
        self.assertEqual(report.unscored_count, 0)

    def test_path_a_ale_shape_one_gate_fails_names_itself(self):
        """ALE shape: one failing gate -> case fails and says which gate."""
        ledger = GateScoreLedger()
        artifact = {"artifact": True, "schema": "v1", "marker": "TODO"}
        outcome = score_case(ledger, "ale-002", DIGEST_A, three_gates(),
                             lambda: artifact, 0)
        self.assertEqual(outcome.outcome, OUTCOME_SCORED)
        self.assertFalse(outcome.passed)
        self.assertEqual(outcome.failed_gates, ("no_marker",))
        report = ledger.report()
        self.assertEqual(report.pass_rate_text, "0/1")
        self.assertEqual(report.failure_gates, ("no_marker",))

    def test_path_b_scorer_dies_with_api_error_then_retry_scores(self):
        """Scorer dies mid-way: errored, no score, out of the denominator,
        retryable; the retry scores normally."""
        ledger = GateScoreLedger()

        def dying_solver():
            raise RuntimeError("HTTPError: 503 upstream unavailable")

        first = score_case(ledger, "case-b", DIGEST_A, three_gates(),
                           dying_solver, 0)
        self.assertEqual(first.outcome, OUTCOME_ERRORED)
        self.assertIn("503", first.error)
        self.assertIsNone(first.passed)
        self.assertTrue(first.retryable)
        report = ledger.report()
        self.assertEqual(report.scored_count, 0)
        self.assertEqual(report.errored_count, 1)
        self.assertEqual(report.pass_rate_text, "n/a")
        self.assertEqual(ledger.retryable_cases(), ("case-b",))

        # the retry: the solver works this time
        second = score_case(ledger, "case-b", DIGEST_A, three_gates(),
                            lambda: good_artifact(), 1)
        self.assertEqual(second.outcome, OUTCOME_SCORED)
        self.assertTrue(second.passed)
        self.assertEqual(second.attempt, 2)
        report = ledger.report()
        self.assertEqual(report.scored_count, 1)
        self.assertEqual(report.passed_count, 1)
        self.assertEqual(report.errored_count, 0)
        self.assertEqual(report.pass_rate_text, "1/1")

    def test_path_b_score_on_error_scores_the_reached_state(self):
        """Same failure, but the reached state is scored anyway."""
        ledger = GateScoreLedger()
        reached = {"artifact": True, "schema": "v0", "marker": False}

        def dying_solver():
            raise RuntimeError("HTTPError: 503 upstream unavailable")

        outcome = score_case(ledger, "case-b-soe", DIGEST_A, three_gates(),
                             dying_solver, 0, score_on_error=True,
                             partial=lambda: reached)
        self.assertEqual(outcome.outcome, OUTCOME_SCORED)
        self.assertFalse(outcome.passed)
        self.assertEqual(outcome.failed_gates, ("schema_valid",))
        self.assertIn("503", outcome.error)
        report = ledger.report()
        self.assertEqual(report.scored_count, 1)
        self.assertEqual(report.errored_count, 0)
        self.assertEqual(report.pass_rate_text, "0/1")

    def test_path_c_scorer_reaches_no_verdict_is_unscored(self):
        """No verdict: unscored, out of the aggregates, no retry."""
        ledger = GateScoreLedger()
        outcome = score_case(ledger, "case-c", DIGEST_A, three_gates(),
                             lambda: NO_VERDICT, 0)
        self.assertEqual(outcome.outcome, OUTCOME_UNSCORED)
        self.assertIsNone(outcome.passed)
        self.assertTrue(outcome.unscored)
        self.assertFalse(outcome.retryable)
        self.assertEqual(ledger.retryable_cases(), ())
        report = ledger.report()
        self.assertEqual(report.scored_count, 0)
        self.assertEqual(report.unscored_count, 1)
        self.assertEqual(report.pass_rate_text, "n/a")
        # no retry is triggered: booking it again is refused
        with self.assertRaises(DuplicateCaseError):
            score_case(ledger, "case-c", DIGEST_A, three_gates(),
                       lambda: NO_VERDICT, 1)

    def test_mixed_run_reports_all_three_counts(self):
        """One run with one of each state: the report states all three."""
        ledger = GateScoreLedger()
        score_case(ledger, "m-1", DIGEST_A, three_gates(),
                   lambda: good_artifact(), 0)
        score_case(ledger, "m-2", DIGEST_B, three_gates(),
                   lambda: {"artifact": True, "schema": "v0"}, 1)

        def dying_solver():
            raise RuntimeError("boom")

        score_case(ledger, "m-3", DIGEST_C, three_gates(), dying_solver, 2)
        score_case(ledger, "m-4", digest("d"), three_gates(),
                   lambda: NO_VERDICT, 3)
        report = ledger.report()
        self.assertEqual((report.scored_count, report.passed_count,
                          report.unscored_count, report.errored_count),
                         (2, 1, 1, 1))
        self.assertEqual(report.pass_rate_text, "1/2")


class BookkeepingEdgeTests(unittest.TestCase):
    """The remaining fail-closed edges of the ledger."""

    def test_bad_metric_is_refused(self):
        with self.assertRaises(BadMetricError):
            CaseOutcome(case_id="c", outcome=OUTCOME_SCORED, passed=True,
                        metric=1.5)
        with self.assertRaises(BadMetricError):
            CaseOutcome(case_id="c", outcome=OUTCOME_SCORED, passed=True,
                        metric=float("nan"))

    def test_unscored_and_errored_bookings_need_a_reason(self):
        ledger = GateScoreLedger()
        with self.assertRaises(BadCaseError):
            ledger.mark_unscored("c", DIGEST_A, "  ", 0)
        with self.assertRaises(BadCaseError):
            # a rejected mutation consumes its seq, so the next seq is 1
            ledger.mark_errored("c", DIGEST_A, "", 1)

    def test_unknown_case_booking_is_refused(self):
        ledger = GateScoreLedger()
        with self.assertRaises(BadCaseError):
            ledger.booking("never-booked")

    def test_a_failed_case_must_name_its_failing_gate(self):
        with self.assertRaises(Exception):
            CaseOutcome(case_id="c", outcome=OUTCOME_SCORED, passed=False,
                        metric=0.0, failed_gates=())

    def test_gate_that_raises_is_an_execution_error_not_a_verdict(self):
        def exploding_gate(artifact):
            raise ValueError("artifact unreadable")

        gates = [Gate("explodes", exploding_gate, "artifacts/out.txt")]
        with self.assertRaises(GateExecutionError):
            run_gates(gates, good_artifact())


class PublicSurfaceTests(unittest.TestCase):
    """Every public record type has a test that names it."""

    def test_case_spec_validates_its_pin(self):
        spec = CaseSpec(case_id="c-1", artifact_digest=DIGEST_A)
        self.assertEqual(spec.case_id, "c-1")
        self.assertEqual(spec.as_dict()["artifact_digest"], DIGEST_A)
        with self.assertRaises(BadCaseError):
            CaseSpec(case_id="c-1", artifact_digest="not-a-pin")
        with self.assertRaises(BadCaseError):
            CaseSpec(case_id="", artifact_digest=DIGEST_A)

    def test_case_booking_records_the_attempts_and_the_outcome(self):
        ledger = GateScoreLedger()
        ledger.score("c-1", DIGEST_A, three_gates(), good_artifact(), 0)
        booking = ledger.booking("c-1")
        self.assertEqual(booking.attempts, 1)
        self.assertEqual(booking.artifact_digest, DIGEST_A)
        self.assertEqual(booking.as_dict()["outcome"]["outcome"], OUTCOME_SCORED)
        self.assertEqual(len(ledger.outcomes()), 1)

    def test_ledger_outcomes_are_ordered_by_case_id(self):
        ledger = GateScoreLedger()
        ledger.score("b-case", DIGEST_A, three_gates(), good_artifact(), 0)
        ledger.score("a-case", DIGEST_B, three_gates(), good_artifact(), 1)
        self.assertEqual([o.case_id for o in ledger.outcomes()],
                         ["a-case", "b-case"])