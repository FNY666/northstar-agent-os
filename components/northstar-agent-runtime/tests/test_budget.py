"""Budget accounting: real per-million prices, prompt-cache multipliers, the
conservative fallback for unknown models, and three ceilings that do not overlap.
"""
from __future__ import annotations

import unittest

import support  # noqa: F401
from support import RuntimeTestCase, text_turn, tool_turn

from budget import (
    CACHE_READ_MULTIPLIER,
    CACHE_WRITE_MULTIPLIER,
    CONSERVATIVE_FALLBACK,
    Budget,
    compute_cost,
    price_for,
)
from providers.base import AssistantMessage, Usage, UserMessage


class PricingTests(unittest.TestCase):
    def test_known_model_is_priced_from_the_table(self):
        pricing, estimated = price_for("claude-sonnet-4-5")
        self.assertEqual((pricing.input_per_mtok, pricing.output_per_mtok), (3.00, 15.00))
        self.assertFalse(estimated)

    def test_one_million_tokens_costs_the_list_price(self):
        breakdown = compute_cost(Usage(input_tokens=1_000_000, output_tokens=1_000_000), "claude-sonnet-4-5")
        self.assertAlmostEqual(breakdown.input_usd, 3.0)
        self.assertAlmostEqual(breakdown.output_usd, 15.0)
        self.assertAlmostEqual(breakdown.total_usd, 18.0)
        self.assertFalse(breakdown.pricing_estimated)

    def test_cache_reads_are_discounted_and_cache_writes_cost_a_premium(self):
        pricing, _ = price_for("claude-sonnet-4-5")
        self.assertEqual(CACHE_READ_MULTIPLIER, 0.1)
        self.assertEqual(CACHE_WRITE_MULTIPLIER, 1.25)
        self.assertAlmostEqual(pricing.cache_read_per_mtok, 0.30)
        self.assertAlmostEqual(pricing.cache_write_per_mtok, 3.75)
        breakdown = compute_cost(
            Usage(input_tokens=1_000, cache_read_input_tokens=1_000_000, cache_creation_input_tokens=1_000_000),
            "claude-sonnet-4-5",
        )
        self.assertAlmostEqual(breakdown.cache_read_usd, 0.30)
        self.assertAlmostEqual(breakdown.cache_write_usd, 3.75)
        self.assertLess(breakdown.cache_read_usd, breakdown.input_usd * 1_000, "a cache read must be far cheaper than fresh input")

    def test_cached_tokens_are_not_also_billed_as_fresh_input(self):
        # Providers report input_tokens *excluding* cached tokens; pricing must not
        # double-count them by summing the fields.
        with_cache = compute_cost(Usage(input_tokens=0, cache_read_input_tokens=1_000_000), "claude-sonnet-4-5")
        fresh = compute_cost(Usage(input_tokens=1_000_000), "claude-sonnet-4-5")
        self.assertLess(with_cache.total_usd, fresh.total_usd / 5)

    def test_dated_model_ids_inherit_their_family_price(self):
        pricing, estimated = price_for("claude-sonnet-4-5-20250929")
        self.assertEqual(pricing.input_per_mtok, 3.00)
        self.assertFalse(estimated, "a dated id for a known family is not an estimate")

    def test_unknown_models_fall_back_conservatively_and_are_flagged(self):
        pricing, estimated = price_for("some-new-model-9000")
        self.assertTrue(estimated)
        self.assertIs(pricing, CONSERVATIVE_FALLBACK)
        self.assertEqual(pricing.input_per_mtok, max(item.input_per_mtok for item in _all_pricing()))
        self.assertGreaterEqual(pricing.input_per_mtok, 3.0, "the fallback must not be cheaper than a known tier")

    def test_opus_and_haiku_tiers_differ(self):
        self.assertGreater(price_for("claude-opus-4-1")[0].output_per_mtok, price_for("claude-sonnet-4-5")[0].output_per_mtok)
        self.assertLess(price_for("claude-haiku-4-5")[0].output_per_mtok, price_for("claude-sonnet-4-5")[0].output_per_mtok)


def _all_pricing():
    from budget import PRICE_TABLE

    return list(PRICE_TABLE.values())


class BudgetAccumulationTests(unittest.TestCase):
    def test_totals_accumulate_across_turns(self):
        budget = Budget()
        budget.observe(Usage(input_tokens=1_000, output_tokens=500), "claude-sonnet-4-5")
        budget.observe(Usage(input_tokens=2_000, output_tokens=250), "claude-sonnet-4-5")
        self.assertAlmostEqual(budget.total_cost_usd, (3_000 / 1e6 * 3.0) + (750 / 1e6 * 15.0))
        self.assertEqual(budget.total_usage.input_tokens, 3_000)
        self.assertEqual(len(budget.breakdowns), 2)

    def test_no_ceiling_means_never_exhausted(self):
        budget = Budget()
        budget.observe(Usage(input_tokens=10_000_000), "claude-opus-4-1")
        self.assertFalse(budget.exhausted)
        self.assertIsNone(budget.remaining())

    def test_ceiling_is_exhausted_at_the_boundary_not_before_it(self):
        budget = Budget(max_budget_usd=0.001)
        budget.observe(Usage(input_tokens=100), "claude-sonnet-4-5")  # $0.0003
        self.assertFalse(budget.exhausted)
        self.assertAlmostEqual(budget.remaining(), 0.0007)
        budget.observe(Usage(input_tokens=300), "claude-sonnet-4-5")  # +$0.0009
        self.assertTrue(budget.exhausted)
        self.assertEqual(budget.remaining(), 0.0)

    def test_child_budgets_roll_up_and_carry_the_estimated_flag(self):
        parent = Budget(max_budget_usd=1.0)
        parent.observe(Usage(input_tokens=1_000), "claude-sonnet-4-5")
        child = Budget()
        child.observe(Usage(input_tokens=2_000, output_tokens=10), "mystery-model")
        parent.observe_child(child)
        self.assertTrue(parent.pricing_estimated)
        self.assertEqual(parent.total_usage.input_tokens, 3_000)
        self.assertIn("mystery-model", parent.models)
        self.assertGreater(parent.total_cost_usd, child.total_cost_usd)


class RuntimeCeilingTests(RuntimeTestCase):
    def test_cost_is_taken_from_reported_usage_not_from_text_length(self):
        provider = self.provider([text_turn("x" * 40_000)])
        report = self.drive(self.runtime(provider=provider))
        self.assertEqual(report.result.total_cost_usd, 0.0, "a turn with zero reported usage costs nothing")

    def test_budget_ceiling_stops_before_the_next_generation(self):
        provider = self.provider(
            [
                tool_turn("Read", {"path": "missing"}, usage={"input_tokens": 1_000_000, "output_tokens": 10}),
                tool_turn("Read", {"path": "missing"}, usage={"input_tokens": 1_000_000, "output_tokens": 10}),
                text_turn("never reached", usage={"input_tokens": 1, "output_tokens": 1}),
            ]
        )
        runtime = self.runtime(provider=provider, max_budget_usd=6.0, max_turns=10)
        report = self.drive(runtime, "read")
        result = self.assertExactlyOneResult(report)
        self.assertEqual(result.subtype, "error_max_budget_usd")
        self.assertEqual(report.result.num_turns, 2, "one turn over the ceiling is enough; no third turn")
        self.assertEqual(provider.cursor, 2, "the loop must not spend a generation it cannot pay for")
        self.assertEqual(report.result.num_turns, len(report.events_of(AssistantMessage)))
        self.assertGreaterEqual(result.total_cost_usd, 6.0 - 1e-9)

    def test_each_ceiling_owns_its_own_subtype(self):
        # max_turns
        endless = [tool_turn("Read", {"path": "missing"}, usage={"input_tokens": 1}) for _ in range(5)]
        turns_report = self.drive(self.runtime(turns=endless, max_turns=2, max_tool_calls=None))
        self.assertEqual(self.assertExactlyOneResult(turns_report).subtype, "error_max_turns")

        # max_tool_calls
        calls_report = self.drive(
            self.runtime(turns=[tool_turn("Read", {"path": "missing"})], max_tool_calls=0, max_turns=5)
        )
        self.assertEqual(self.assertExactlyOneResult(calls_report).subtype, "error_max_tool_calls")

        # max_budget_usd
        budget_report = self.drive(
            self.runtime(
                turns=[tool_turn("Read", {"path": "missing"}, usage={"input_tokens": 5_000_000})],
                max_budget_usd=0.001,
                max_turns=5,
                max_tool_calls=None,
            )
        )
        self.assertEqual(self.assertExactlyOneResult(budget_report).subtype, "error_max_budget_usd")

    def test_tool_call_ceiling_refuses_every_pending_call_in_the_turn(self):
        provider = self.provider(
            [
                {
                    "tools": [
                        {"name": "DescribeTools", "input": {}},
                        {"name": "Read", "input": {"path": "b"}},
                        {"name": "Read", "input": {"path": "c"}},
                    ],
                    "usage": {"input_tokens": 10},
                },
                text_turn("unused"),
            ]
        )
        report = self.drive(self.runtime(provider=provider, max_tool_calls=1, max_turns=5))
        self.assertEqual(self.assertExactlyOneResult(report).subtype, "error_max_tool_calls")
        results = [result for message in report.transcript if isinstance(message, UserMessage) for result in message.tool_results]
        self.assertEqual(len(results), 3, "no tool_use may be left without a tool_result")
        self.assertFalse(results[0].is_error, "the call that fit under the ceiling really ran")
        self.assertTrue(all(result.is_error for result in results[1:]))
        self.assertTrue(all("not executed" in result.text() for result in results[1:]))

    def test_pricing_estimated_is_surfaced_on_the_result(self):
        # An unnamed provider leaves the configured model in charge of pricing.
        provider = self.provider([text_turn("hi", usage={"input_tokens": 1000, "output_tokens": 10})], model="")
        report = self.drive(self.runtime(provider=provider, model="unknown-frontier-model"))
        result = self.assertExactlyOneResult(report)
        self.assertTrue(result.pricing_estimated)
        # Conservative fallback is the priciest known tier: 1000*15 + 10*75 per M.
        self.assertAlmostEqual(result.total_cost_usd, 1000 / 1e6 * 15.0 + 10 / 1e6 * 75.0, places=10)

    def test_a_provider_reported_model_wins_for_pricing(self):
        provider = self.provider([text_turn("hi", usage={"input_tokens": 1_000_000})], model="claude-haiku-4-5")
        report = self.drive(self.runtime(provider=provider, model="unknown-frontier-model"))
        self.assertFalse(self.assertExactlyOneResult(report).pricing_estimated)
        self.assertAlmostEqual(report.result.total_cost_usd, 0.8)

    def test_invalid_ceiling_configuration_fails_at_construction(self):
        from loop import RuntimeConfig, RuntimeConfigurationError

        for kwargs in ({"max_turns": 0}, {"max_budget_usd": 0}, {"max_tool_calls": -1}, {"model": " "}):
            with self.subTest(**kwargs):
                with self.assertRaises(RuntimeConfigurationError):
                    RuntimeConfig(**kwargs)


if __name__ == "__main__":
    unittest.main()
