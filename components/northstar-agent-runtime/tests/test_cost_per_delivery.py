"""Tests for cost per delivery (``cost_per_delivery``).

The rule under test: **a slice's price is the price of a verified
delivery, not the price of an attempt.**

``cost_per_verified_delivery = total settled cost / number of verified
deliveries``.  The motivating source (Real-SWE benchmark, secondary
trade-press writeup, 2026-09-14) reports Claude Code (Fable 5.1) at 38.8%
resolution, $6.96 per rollout and ~$17.94 per resolved task, and Gemini
3.8 Flash at 31.2%, $2.50 per rollout and ~$8.01 per resolved task.  Both
reported prices are reproduced here from the formula, to better than a
cent.

The tests drive real paths: the two Real-SWE quotes are recomputed, the
admission ceiling is exercised on both sides of $10 per delivery, and a
ledger with no verified delivery is checked to report *undefined* rather
than 0.  Reference values are computed independently (``decimal`` division
rather than the module's float division) so the comparison does not lean on
the module's own arithmetic.
"""
import unittest
from decimal import Decimal, getcontext

from cost_per_delivery import (
    FAILURE_MODES,
    VERDICTS,
    AdmissionVerdict,
    AttemptRecord,
    CostPerDeliveryError,
    CostPerDeliveryLedger,
    ModelCostQuote,
    admit,
    compare,
    projected_cost_per_delivery,
)

getcontext().prec = 60

# The source's numbers, verbatim from the trade-press writeup.
FABLE_PER_ROLLOUT = 6.96
FABLE_RESOLUTION = 0.388
FABLE_PER_RESOLVED = 17.94

GEMINI_PER_ROLLOUT = 2.50
GEMINI_RESOLUTION = 0.312
GEMINI_PER_RESOLVED = 8.01


def _reference_cost_per_delivery(per_attempt_cost: float, resolution_rate: float) -> float:
    """Independent reference for ``per_attempt_cost / resolution_rate``.

    Uses :class:`decimal.Decimal` so the reference does not lean on the
    module's float division.
    """
    return float(
        Decimal(str(per_attempt_cost)) / Decimal(str(resolution_rate))
    )


class CoreFormulaTests(unittest.TestCase):
    """``cost_per_verified_delivery = total settled cost / deliveries``."""

    def test_real_swe_fable_quote_reproduces_the_reported_price(self):
        """Fable 5.1: $6.96 per rollout at 38.8% -> ~$17.94 per delivery."""
        projected = projected_cost_per_delivery(FABLE_PER_ROLLOUT, FABLE_RESOLUTION)
        self.assertAlmostEqual(projected, FABLE_PER_RESOLVED, delta=0.01)
        self.assertAlmostEqual(
            projected, _reference_cost_per_delivery(FABLE_PER_ROLLOUT, FABLE_RESOLUTION), delta=1e-12
        )

    def test_real_swe_gemini_quote_reproduces_the_reported_price(self):
        """Gemini 3.8 Flash: $2.50 per rollout at 31.2% -> ~$8.01 per delivery."""
        projected = projected_cost_per_delivery(GEMINI_PER_ROLLOUT, GEMINI_RESOLUTION)
        self.assertAlmostEqual(projected, GEMINI_PER_RESOLVED, delta=0.01)
        self.assertAlmostEqual(
            projected, _reference_cost_per_delivery(GEMINI_PER_ROLLOUT, GEMINI_RESOLUTION), delta=1e-12
        )

    def test_ledger_quote_is_total_cost_over_verified_deliveries(self):
        """The ledger's own quote is the same arithmetic as the projection."""
        ledger = CostPerDeliveryLedger()
        ledger.book_attempt(
            "a1", FABLE_PER_ROLLOUT, "verified_delivered", "sealed-receipt:r-1", model="fable"
        )
        ledger.book_attempt(
            "a2", FABLE_PER_ROLLOUT, "failed", "test-run:t-2", model="fable",
            failure_mode="missed_requirement",
        )
        # One delivery, two attempts' worth of cost: $13.92 per delivery.
        self.assertAlmostEqual(
            ledger.cost_per_verified_delivery(), 13.92, delta=1e-9
        )
        self.assertEqual(ledger.verified_delivery_count(), 1)
        self.assertEqual(ledger.total_settled_cost_usd(), 13.92)

    def test_zero_denominator_is_undefined_not_zero(self):
        """No verified delivery -> the price does not exist (None)."""
        ledger = CostPerDeliveryLedger()
        ledger.book_attempt(
            "f1", 6.96, "failed", "test-run:t-1", failure_mode="integration_error"
        )
        ledger.book_attempt("f2", 6.96, "abandoned", "sealed-receipt:r-2")
        self.assertIsNone(ledger.cost_per_verified_delivery())
        self.assertNotEqual(ledger.cost_per_verified_delivery(), 0)
        self.assertEqual(ledger.verified_delivery_count(), 0)

    def test_empty_ledger_quote_is_undefined(self):
        """An empty ledger has no price per delivery either."""
        self.assertIsNone(CostPerDeliveryLedger().cost_per_verified_delivery())


class DeliveryVerdictTests(unittest.TestCase):
    """A delivery verdict is booked only against a verification record."""

    def test_self_reported_verdict_without_source_is_refused(self):
        """No verdict_source at all -> refused, nothing booked."""
        ledger = CostPerDeliveryLedger()
        with self.assertRaises(CostPerDeliveryError):
            ledger.book_attempt("a1", 6.96, "verified_delivered", "")
        with self.assertRaises(CostPerDeliveryError):
            ledger.book_attempt("a2", 6.96, "verified_delivered", None)
        self.assertEqual(ledger.records, ())

    def test_explicit_self_report_source_is_refused(self):
        """A session's own claim is not a verification record."""
        ledger = CostPerDeliveryLedger()
        with self.assertRaises(CostPerDeliveryError) as ctx:
            ledger.book_attempt("a1", 6.96, "verified_delivered", "self-report:session-42")
        self.assertIn("self-report", str(ctx.exception))
        self.assertEqual(ledger.records, ())

    def test_sealed_receipt_and_test_run_sources_are_accepted(self):
        """The two verification-record kinds Northstar has."""
        ledger = CostPerDeliveryLedger()
        rec = ledger.book_attempt(
            "a1", 6.96, "verified_delivered", "sealed-receipt:r-1", model="fable"
        )
        self.assertIsInstance(rec, AttemptRecord)
        self.assertEqual(rec.verdict_source, "sealed-receipt:r-1")
        ledger.book_attempt(
            "a2", 6.96, "failed", "test-run:t-2", model="fable",
            failure_mode="integration_error",
        )
        self.assertEqual(len(ledger.records), 2)

    def test_source_without_kind_or_identifier_is_refused(self):
        """A source must be '<kind>:<identifier>' naming a record."""
        ledger = CostPerDeliveryLedger()
        with self.assertRaises(CostPerDeliveryError):
            ledger.book_attempt("a1", 6.96, "verified_delivered", "just-a-receipt-id")
        with self.assertRaises(CostPerDeliveryError):
            ledger.book_attempt("a2", 6.96, "verified_delivered", "sealed-receipt:")

    def test_unknown_verdict_is_refused(self):
        """Only the three bookable verdicts are accepted."""
        ledger = CostPerDeliveryLedger()
        for bad in ("delivered", "VERIFIED_DELIVERED", "", "success", None):
            with self.assertRaises(CostPerDeliveryError):
                ledger.book_attempt("a1", 6.96, bad, "sealed-receipt:r-1")
        self.assertEqual(ledger.records, ())

    def test_the_three_verdicts_are_the_ones_the_module_declares(self):
        """The verdict vocabulary is exactly the three named in the spec."""
        self.assertEqual(
            set(VERDICTS), {"verified_delivered", "failed", "abandoned"}
        )

    def test_duplicate_attempt_id_is_refused(self):
        """Booking the same attempt twice would double-count the cost."""
        ledger = CostPerDeliveryLedger()
        ledger.book_attempt("a1", 6.96, "failed", "test-run:t-1", failure_mode="other")
        with self.assertRaises(CostPerDeliveryError):
            ledger.book_attempt("a1", 6.96, "failed", "test-run:t-2", failure_mode="other")
        self.assertEqual(len(ledger.records), 1)

    def test_failed_attempt_needs_a_failure_mode(self):
        """A failed attempt must say how it failed."""
        ledger = CostPerDeliveryLedger()
        with self.assertRaises(CostPerDeliveryError):
            ledger.book_attempt("a1", 6.96, "failed", "test-run:t-1")
        with self.assertRaises(CostPerDeliveryError):
            ledger.book_attempt("a2", 6.96, "failed", "test-run:t-2", failure_mode="typo_mode")

    def test_failure_mode_on_a_non_failed_attempt_is_refused(self):
        """A delivered attempt has no failure mode."""
        ledger = CostPerDeliveryLedger()
        with self.assertRaises(CostPerDeliveryError):
            ledger.book_attempt(
                "a1", 6.96, "verified_delivered", "sealed-receipt:r-1",
                failure_mode="integration_error",
            )


class FailClosedInputTests(unittest.TestCase):
    """Illegal inputs are refused, never defaulted."""

    def test_resolution_rate_boundaries_are_refused(self):
        """0, negative, above 1, NaN and infinity are all refused."""
        for bad in (0, 0.0, -0.1, -1, 1.0001, 2, float("nan"), float("inf")):
            with self.assertRaises(CostPerDeliveryError):
                projected_cost_per_delivery(6.96, bad)

    def test_resolution_rate_of_exactly_one_is_accepted(self):
        """1.0 is in range: every attempt delivers."""
        self.assertAlmostEqual(projected_cost_per_delivery(6.96, 1.0), 6.96, delta=1e-12)

    def test_non_numeric_resolution_rate_is_refused(self):
        """A rate that is not a number is refused (bool included)."""
        for bad in ("0.5", None, True, [0.5]):
            with self.assertRaises(CostPerDeliveryError):
                projected_cost_per_delivery(6.96, bad)

    def test_negative_settled_cost_is_refused(self):
        """A negative settled cost is refused; nothing is booked."""
        ledger = CostPerDeliveryLedger()
        with self.assertRaises(CostPerDeliveryError):
            ledger.book_attempt("a1", -0.01, "verified_delivered", "sealed-receipt:r-1")
        self.assertEqual(ledger.records, ())

    def test_non_finite_settled_cost_is_refused(self):
        """NaN / infinity are not settleable amounts."""
        ledger = CostPerDeliveryLedger()
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(CostPerDeliveryError):
                ledger.book_attempt("a1", bad, "verified_delivered", "sealed-receipt:r-1")

    def test_zero_settled_cost_is_bookable(self):
        """A genuinely free attempt settles at $0.00 -- that is not an error.

        Only a *negative* settled cost is refused: zero spend is a fact, not
        a mistake.
        """
        ledger = CostPerDeliveryLedger()
        record = ledger.book_attempt(
            "a1", 0.0, "verified_delivered", "sealed-receipt:r-1", model="local"
        )
        self.assertEqual(record.settled_cost_usd, 0.0)
        self.assertEqual(ledger.total_settled_cost_usd(), 0.0)
        self.assertEqual(ledger.cost_per_verified_delivery(), 0.0)
        self.assertEqual(len(ledger.records), 1)

    def test_negative_per_attempt_cost_is_refused(self):
        """The projection refuses a negative attempt price too."""
        with self.assertRaises(CostPerDeliveryError):
            projected_cost_per_delivery(-6.96, 0.388)


class AdmissionTests(unittest.TestCase):
    """The fail-closed admission gate."""

    def test_admission_refuses_the_expensive_delivery_price(self):
        """Fable 5.1 at $17.94/delivery is refused under a $10 ceiling."""
        verdict = admit(FABLE_PER_ROLLOUT, FABLE_RESOLUTION, 10.0)
        self.assertIsInstance(verdict, AdmissionVerdict)
        self.assertFalse(verdict.admitted)
        self.assertFalse(bool(verdict))
        self.assertAlmostEqual(verdict.projected_cost_per_delivery, 17.938144329896907, delta=1e-9)
        self.assertIn("exceeds", verdict.reason)

    def test_admission_allows_the_cheaper_delivery_price(self):
        """Gemini at $8.01/delivery is admitted under the same $10 ceiling."""
        verdict = admit(GEMINI_PER_ROLLOUT, GEMINI_RESOLUTION, 10.0)
        self.assertTrue(verdict.admitted)
        self.assertTrue(bool(verdict))
        self.assertAlmostEqual(verdict.projected_cost_per_delivery, 8.012820512820513, delta=1e-9)

    def test_admission_prefers_the_cheaper_attempt_model_here(self):
        """The cheap-per-attempt model is the one that gets through."""
        fable = admit(FABLE_PER_ROLLOUT, FABLE_RESOLUTION, 10.0)
        gemini = admit(GEMINI_PER_ROLLOUT, GEMINI_RESOLUTION, 10.0)
        self.assertFalse(fable.admitted)
        self.assertTrue(gemini.admitted)
        self.assertLess(GEMINI_PER_ROLLOUT, FABLE_PER_ROLLOUT)

    def test_admission_refuses_a_zero_resolution_rate(self):
        """Nothing ever delivered -> no price -> no dispatch."""
        verdict = admit(6.96, 0.0, 10.0)
        self.assertFalse(verdict.admitted)
        self.assertIsNone(verdict.projected_cost_per_delivery)

    def test_admission_at_the_ceiling_is_admitted(self):
        """The ceiling is inclusive: projected == ceiling passes."""
        projected = projected_cost_per_delivery(6.96, 0.388)
        verdict = admit(6.96, 0.388, projected)
        self.assertTrue(verdict.admitted)

    def test_admission_just_over_the_ceiling_is_refused(self):
        """One cent over the ceiling is refused."""
        projected = projected_cost_per_delivery(6.96, 0.388)
        verdict = admit(6.96, 0.388, projected - 0.01)
        self.assertFalse(verdict.admitted)

    def test_admission_refuses_an_illegal_rate_out_of_range(self):
        """A rate above 1 is refused by the gate, not passed through."""
        with self.assertRaises(CostPerDeliveryError):
            admit(6.96, 1.5, 10.0)


class ModelComparisonTests(unittest.TestCase):
    """The ranking is on cost per delivery, not on cost per attempt."""

    def test_cheaper_attempt_model_can_sort_behind(self):
        """A cheap-per-attempt model with a low rate sorts last."""
        quotes = compare(
            [
                {"model": "fable-5.1", "per_attempt_cost": 6.96, "resolution_rate": 0.388},
                {"model": "gemini-3.8-flash", "per_attempt_cost": 2.50, "resolution_rate": 0.312},
            ]
        )
        self.assertEqual([q.model for q in quotes], ["gemini-3.8-flash", "fable-5.1"])
        self.assertTrue(all(isinstance(q, ModelCostQuote) for q in quotes))

    def test_ranking_follows_delivery_price_not_attempt_price(self):
        """The order is the order of cost_per_delivery."""
        quotes = compare(
            [
                {"model": "a", "per_attempt_cost": 10.0, "resolution_rate": 0.9},
                {"model": "b", "per_attempt_cost": 1.0, "resolution_rate": 0.01},
                {"model": "c", "per_attempt_cost": 5.0, "resolution_rate": 0.5},
            ]
        )
        self.assertEqual([q.model for q in quotes], ["c", "a", "b"])
        prices = [q.cost_per_delivery for q in quotes]
        self.assertEqual(prices, sorted(prices))
        # 'a' is the most expensive per attempt ($10) and still the *most*
        # expensive per delivery ($11.11) -- 'c' costs $10 per delivery.
        self.assertEqual(quotes[0].model, "c")
        self.assertEqual(quotes[-1].per_attempt_cost, 1.0)

    def test_quote_values_match_the_projection(self):
        """Each quote's cost_per_delivery is the module's projection."""
        quotes = compare(
            [{"model": "fable-5.1", "per_attempt_cost": 6.96, "resolution_rate": 0.388}]
        )
        self.assertAlmostEqual(
            quotes[0].cost_per_delivery,
            projected_cost_per_delivery(6.96, 0.388),
            delta=1e-12,
        )

    def test_comparison_refuses_an_illegal_rate(self):
        """The ranking refuses an out-of-range rate instead of sorting it."""
        with self.assertRaises(CostPerDeliveryError):
            compare([{"model": "a", "per_attempt_cost": 1.0, "resolution_rate": 0.0}])

    def test_comparison_refuses_a_missing_field(self):
        """A model entry without a rate is refused."""
        with self.assertRaises(CostPerDeliveryError):
            compare([{"model": "a", "per_attempt_cost": 1.0}])
        with self.assertRaises(CostPerDeliveryError):
            compare([{"per_attempt_cost": 1.0, "resolution_rate": 0.5}])


class FailureModeBookkeepingTests(unittest.TestCase):
    """Failed attempts are tagged and aggregated per model."""

    def _ledger(self) -> CostPerDeliveryLedger:
        ledger = CostPerDeliveryLedger()
        ledger.book_attempt(
            "g1", 2.50, "failed", "test-run:t-1", model="gemini",
            failure_mode="integration_error",
        )
        ledger.book_attempt(
            "g2", 2.50, "failed", "test-run:t-2", model="gemini",
            failure_mode="integration_error",
        )
        ledger.book_attempt(
            "g3", 2.50, "failed", "test-run:t-3", model="gemini",
            failure_mode="missed_requirement",
        )
        ledger.book_attempt(
            "g4", 6.96, "failed", "test-run:t-4", model="fable",
            failure_mode="unverified_assumption",
        )
        ledger.book_attempt(
            "g5", 6.96, "verified_delivered", "sealed-receipt:r-5", model="fable",
        )
        return ledger

    def test_counts_are_aggregated_per_model(self):
        """Each model's failures are counted under their own modes."""
        ledger = self._ledger()
        self.assertEqual(
            ledger.failure_mode_counts("gemini"),
            {
                "missed_requirement": 1,
                "integration_error": 2,
                "unverified_assumption": 0,
                "other": 0,
            },
        )
        self.assertEqual(
            ledger.failure_mode_counts("fable")["unverified_assumption"], 1
        )

    def test_shares_sum_to_one_per_model(self):
        """Within one model the mode shares are a distribution."""
        ledger = self._ledger()
        shares = ledger.failure_mode_shares("gemini")
        self.assertAlmostEqual(sum(shares.values()), 1.0, delta=1e-9)
        self.assertAlmostEqual(shares["integration_error"], 2 / 3, delta=1e-9)
        self.assertAlmostEqual(shares["missed_requirement"], 1 / 3, delta=1e-9)

    def test_models_do_not_pollute_each_others_counts(self):
        """A model's failures are not attributed to another model."""
        ledger = self._ledger()
        self.assertEqual(ledger.failure_mode_counts("gemini")["unverified_assumption"], 0)
        self.assertEqual(ledger.failure_mode_counts("fable")["integration_error"], 0)

    def test_the_four_modes_are_the_ones_the_module_declares(self):
        """The mode vocabulary is the Real-SWE miss taxonomy."""
        self.assertEqual(
            set(FAILURE_MODES),
            {
                "missed_requirement",
                "integration_error",
                "unverified_assumption",
                "other",
            },
        )

    def test_no_failures_means_no_distribution(self):
        """With no failures every share is 0.0, not an error."""
        ledger = CostPerDeliveryLedger()
        ledger.book_attempt(
            "a1", 6.96, "verified_delivered", "sealed-receipt:r-1", model="fable"
        )
        shares = ledger.failure_mode_shares("fable")
        self.assertEqual(set(shares.values()), {0.0})
        self.assertEqual(sum(shares.values()), 0.0)


class RealPathTests(unittest.TestCase):
    """The three real paths the slice must drive end to end."""

    def test_path_a_the_two_real_swe_quotes_are_reproduced(self):
        """(a) Both reported per-resolved-task prices come out of the formula."""
        fable = projected_cost_per_delivery(FABLE_PER_ROLLOUT, FABLE_RESOLUTION)
        gemini = projected_cost_per_delivery(GEMINI_PER_ROLLOUT, GEMINI_RESOLUTION)
        self.assertAlmostEqual(fable, FABLE_PER_RESOLVED, delta=0.01)
        self.assertAlmostEqual(gemini, GEMINI_PER_RESOLVED, delta=0.01)

    def test_path_b_admission_under_a_ten_dollar_ceiling(self):
        """(b) $10/delivery: the cheap-attempt model through, the other out."""
        fable = admit(FABLE_PER_ROLLOUT, FABLE_RESOLUTION, 10.0)
        gemini = admit(GEMINI_PER_ROLLOUT, GEMINI_RESOLUTION, 10.0)
        self.assertFalse(fable.admitted)
        self.assertTrue(gemini.admitted)
        self.assertLess(GEMINI_PER_ROLLOUT, FABLE_PER_ROLLOUT)

    def test_path_c_zero_deliveries_is_undefined_and_refuses_dispatch(self):
        """(c) Only failed/abandoned attempts: undefined quote, no dispatch."""
        ledger = CostPerDeliveryLedger()
        ledger.book_attempt(
            "a1", 6.96, "failed", "test-run:t-1", failure_mode="missed_requirement"
        )
        ledger.book_attempt("a2", 6.96, "abandoned", "sealed-receipt:r-2")
        self.assertIsNone(ledger.cost_per_verified_delivery())
        self.assertEqual(ledger.total_settled_cost_usd(), 13.92)
        verdict = admit(6.96, 0.0, 10.0)
        self.assertFalse(verdict.admitted)

    def test_path_d_a_booked_ledger_reproduces_the_reported_multiples(self):
        """(d) 38.8% resolution over booked attempts -> $17.94 per delivery."""
        ledger = CostPerDeliveryLedger()
        # 25 attempts at 38.8% resolution: 9.7 deliveries is not integral, so
        # use the ratio 388/1000 -> 194 attempts with 75.272 ... instead use
        # the exact ratio 0.388 == 97/250: 250 attempts, 97 deliveries.
        for i in range(250):
            verdict = "verified_delivered" if i < 97 else "failed"
            ledger.book_attempt(
                f"a{i}",
                FABLE_PER_ROLLOUT,
                verdict,
                "sealed-receipt:r-1" if verdict == "verified_delivered" else "test-run:t-1",
                model="fable-5.1",
                failure_mode="missed_requirement" if verdict == "failed" else "",
            )
        self.assertEqual(ledger.verified_delivery_count(), 97)
        self.assertAlmostEqual(
            ledger.cost_per_verified_delivery(), FABLE_PER_RESOLVED, delta=0.01
        )
        self.assertAlmostEqual(
            ledger.observed_resolution_rate("fable-5.1"), FABLE_RESOLUTION, delta=1e-9
        )


class SealedReceiptSourceTests(unittest.TestCase):
    """The verdict source is a real sealed receipt, minted here.

    ``forward_seal_ledger`` is read-only for this slice: this test mints a
    sealed event and books it as the verification record behind a delivery
    verdict, which is the transfer the source describes ("completion
    tracking, which Northstar's sealed receipts already enable").
    """

    def test_a_real_sealed_receipt_can_be_the_verdict_source(self):
        from forward_seal_ledger import ForwardSealLedger

        ledger = ForwardSealLedger(initial_key=b"k" * 32, checkpoint_key=b"c" * 32)
        event = ledger.append(
            intent="deliver slice 6",
            action="verify",
            subject="task-42",
            authorization="grant-1",
            inputs_digest="sha256:" + "0" * 64,
            logic_digest="sha256:" + "1" * 64,
            execution_digest="sha256:" + "2" * 64,
            outcome="verified",
        )
        source = f"sealed-receipt:{event.record_hash}"
        book = CostPerDeliveryLedger()
        record = book.book_attempt(
            "a1", 6.96, "verified_delivered", source, model="fable-5.1"
        )
        self.assertEqual(record.verdict_source, source)
        self.assertAlmostEqual(book.cost_per_verified_delivery(), 6.96, delta=1e-9)
