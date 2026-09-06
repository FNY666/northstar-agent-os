import unittest

from budget import (
    CACHE_READ_DISCOUNT,
    CACHE_WRITE_PREMIUM,
    BudgetTracker,
    estimate_cost,
    pricing_for,
)
from providers.base import Usage


class PricingResolutionTests(unittest.TestCase):
    def test_known_model_is_exact_not_estimated(self):
        input_price, output_price, estimated = pricing_for("claude-sonnet-4-5")
        self.assertEqual(input_price, 3.0)
        self.assertEqual(output_price, 15.0)
        self.assertFalse(estimated)

    def test_dated_model_id_matches_family_prefix(self):
        input_price, output_price, estimated = pricing_for("claude-sonnet-4-5-20250929")
        self.assertEqual((input_price, output_price), (3.0, 15.0))
        self.assertFalse(estimated)

    def test_unknown_model_falls_back_to_conservative_pricing(self):
        input_price, output_price, estimated = pricing_for("totally-unknown-model")
        self.assertEqual(input_price, 15.0)  # most expensive known input price
        self.assertEqual(output_price, 75.0)  # most expensive known output price
        self.assertTrue(estimated)


class CostMathTests(unittest.TestCase):
    def test_plain_input_output(self):
        cost = estimate_cost("claude-sonnet-4-5", Usage(input_tokens=1_000_000, output_tokens=1_000_000))
        self.assertEqual(cost.usd, 18.0)
        self.assertFalse(cost.pricing_estimated)

    def test_cache_read_is_discounted_at_0_1x(self):
        cost = estimate_cost("claude-sonnet-4-5", Usage(cache_read_input_tokens=1_000_000))
        self.assertAlmostEqual(cost.usd, 3.0 * CACHE_READ_DISCOUNT, places=9)
        self.assertAlmostEqual(cost.usd, 0.3, places=9)

    def test_cache_write_is_premium_at_1_25x(self):
        cost = estimate_cost("claude-sonnet-4-5", Usage(cache_creation_input_tokens=1_000_000))
        self.assertEqual(cost.usd, 3.0 * CACHE_WRITE_PREMIUM)
        self.assertEqual(cost.usd, 3.75)

    def test_combined_usage(self):
        usage = Usage(input_tokens=100_000, output_tokens=50_000,
                      cache_read_input_tokens=1_000_000, cache_creation_input_tokens=1_000_000)
        cost = estimate_cost("claude-sonnet-4-5", usage)
        expected = 100_000 * 3.0 / 1e6 + 1_000_000 * 3.0 * 0.1 / 1e6 + 1_000_000 * 3.0 * 1.25 / 1e6 + 50_000 * 15.0 / 1e6
        self.assertAlmostEqual(cost.usd, expected, places=9)

    def test_unknown_model_is_flagged_estimated(self):
        cost = estimate_cost("mystery-1", Usage(input_tokens=1_000_000))
        self.assertEqual(cost.usd, 15.0)
        self.assertTrue(cost.pricing_estimated)


class BudgetTrackerTests(unittest.TestCase):
    def test_accumulates_cost_and_usage(self):
        tracker = BudgetTracker()
        tracker.record("claude-sonnet-4-5", Usage(input_tokens=100, output_tokens=10))
        tracker.record("claude-sonnet-4-5", Usage(input_tokens=50, output_tokens=5, cache_read_input_tokens=7))
        self.assertEqual(tracker.generations, 2)
        self.assertEqual(tracker.usage.input_tokens, 150)
        self.assertEqual(tracker.usage.output_tokens, 15)
        self.assertEqual(tracker.usage.cache_read_input_tokens, 7)
        self.assertGreater(tracker.total_usd, 0.0)

    def test_estimated_flag_is_sticky(self):
        tracker = BudgetTracker()
        tracker.record("claude-sonnet-4-5", Usage(input_tokens=1))
        self.assertFalse(tracker.pricing_estimated)
        tracker.record("mystery-1", Usage(input_tokens=1))
        self.assertTrue(tracker.pricing_estimated)

    def test_record_returns_the_generation_cost(self):
        tracker = BudgetTracker()
        cost = tracker.record("claude-sonnet-4-5", Usage(input_tokens=1_000_000))
        self.assertEqual(cost.usd, 3.0)
        self.assertEqual(tracker.total_usd, 3.0)


if __name__ == "__main__":
    unittest.main()
