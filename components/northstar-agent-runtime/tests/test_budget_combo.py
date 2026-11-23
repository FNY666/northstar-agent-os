"""Tests for budget_combo: per-call ceiling + token bucket composed."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from budget_combo import (
    BUDGET_COMBO_VERSION,
    GUARD_BUCKET,
    GUARD_CEILING,
    GUARD_PER_CALL,
    GUARD_RUN,
    ComboBudget,
    ComboCharge,
    ComboDenied,
)


class TestVersion(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(BUDGET_COMBO_VERSION, "budget-combo.v1")
        self.assertEqual(GUARD_CEILING, "ceiling")
        self.assertEqual(GUARD_BUCKET, "bucket")


class TestHappyPath(unittest.TestCase):
    def test_charge_within_both_guards(self):
        combo = ComboBudget(max_budget_usd=1.0)
        charge = combo.check_and_charge("tool", 0.005, 0)
        self.assertIsInstance(charge, ComboCharge)
        self.assertEqual(charge.call_type, "tool")
        self.assertEqual(charge.estimated_cost_usd, 0.005)
        self.assertEqual(charge.seq, 0)
        self.assertAlmostEqual(charge.remaining_run_usd, 0.995)
        self.assertLess(charge.tokens_left, 0.10)  # bucket was drained

    def test_frozen_charge(self):
        combo = ComboBudget()
        charge = combo.check_and_charge("memory_read", 0.0005, 0)
        with self.assertRaises(Exception):
            charge.estimated_cost_usd = 9.0  # type: ignore[misc]

    def test_charges_log(self):
        combo = ComboBudget()
        combo.check_and_charge("tool", 0.001, 0)
        combo.check_and_charge("tool", 0.001, 1)
        self.assertEqual(len(combo.charges), 2)
        self.assertEqual(combo.total_spent_usd, 0.002)


class TestCostGuard(unittest.TestCase):
    def test_per_call_ceiling_refusal_names_guard(self):
        combo = ComboBudget(max_budget_usd=10.0)
        with self.assertRaises(ComboDenied) as ctx:
            combo.check_and_charge("tool", 0.50, 0)  # ceiling is 0.01
        denied = ctx.exception
        self.assertEqual(denied.guard, GUARD_PER_CALL)
        self.assertEqual(denied.call_type, "tool")
        self.assertEqual(denied.needed, 0.50)
        self.assertIsNone(denied.retry_in_seqs)

    def test_run_ceiling_refusal_names_guard(self):
        combo = ComboBudget(max_budget_usd=0.01)
        combo.check_and_charge("tool", 0.009, 0)
        with self.assertRaises(ComboDenied) as ctx:
            combo.check_and_charge("tool", 0.009, 1)
        denied = ctx.exception
        self.assertEqual(denied.guard, GUARD_RUN)
        self.assertIsNotNone(denied.available)

    def test_exactly_at_per_call_ceiling_allowed(self):
        combo = ComboBudget()
        charge = combo.check_and_charge("tool", 0.01, 0)  # ceiling exactly
        self.assertEqual(charge.estimated_cost_usd, 0.01)

    def test_uncapped_run_still_enforces_per_call_ceiling(self):
        combo = ComboBudget(max_budget_usd=None)
        with self.assertRaises(ComboDenied) as ctx:
            combo.check_and_charge("model", 0.50, 0)
        self.assertEqual(ctx.exception.guard, GUARD_PER_CALL)
        self.assertIsNone(ctx.exception.available)


class TestRateGuard(unittest.TestCase):
    def test_bucket_refusal_names_guard_and_retry_hint(self):
        combo = ComboBudget()  # tool bucket: capacity 0.10
        # Drain: 0.009 fits per-call ceiling (0.01) but 12 of them drain 0.108 > 0.10
        seq = 0
        for _ in range(11):
            combo.check_and_charge("tool", 0.009, seq)
        with self.assertRaises(ComboDenied) as ctx:
            combo.check_and_charge("tool", 0.009, seq)
        denied = ctx.exception
        self.assertEqual(denied.guard, GUARD_BUCKET)
        self.assertIsNotNone(denied.retry_in_seqs)
        self.assertGreaterEqual(denied.retry_in_seqs, 0)

    def test_retry_hint_accurate(self):
        combo = ComboBudget()
        seq = 0
        for _ in range(11):
            combo.check_and_charge("tool", 0.009, seq)
        try:
            combo.check_and_charge("tool", 0.009, seq)
            self.fail("expected ComboDenied")
        except ComboDenied as denied:
            wait = denied.retry_in_seqs
            self.assertIsNotNone(wait)
            charge = combo.check_and_charge("tool", 0.009, seq + wait)
            self.assertEqual(charge.seq, seq + wait)

    def test_bucket_refill_over_time(self):
        combo = ComboBudget()
        for _ in range(11):
            combo.check_and_charge("tool", 0.009, 0)
        # After many seqs the bucket refills (0.01/seq) and the call fits again.
        charge = combo.check_and_charge("tool", 0.009, 100)
        self.assertEqual(charge.seq, 100)

    def test_independent_buckets(self):
        combo = ComboBudget()
        # Drain the model bucket; memory_read must still flow.
        for _ in range(11):
            try:
                combo.check_and_charge("model", 0.09, 0)
            except ComboDenied:
                break
        charge = combo.check_and_charge("memory_read", 0.0005, 0)
        self.assertEqual(charge.call_type, "memory_read")


class TestAtomicity(unittest.TestCase):
    def test_ceiling_denial_does_not_drain_bucket(self):
        combo = ComboBudget(max_budget_usd=10.0)
        before = combo.tokens_for("tool")
        with self.assertRaises(ComboDenied):
            combo.check_and_charge("tool", 0.50, 0)  # over per-call ceiling
        self.assertEqual(combo.tokens_for("tool"), before)

    def test_bucket_denial_does_not_charge_ceiling(self):
        combo = ComboBudget(max_budget_usd=10.0)
        for _ in range(11):
            combo.check_and_charge("tool", 0.009, 0)
        spent_before = combo.total_spent_usd
        with self.assertRaises(ComboDenied):
            combo.check_and_charge("tool", 0.009, 0)
        self.assertEqual(combo.total_spent_usd, spent_before)
        self.assertEqual(len(combo.charges), 11)

    def test_guard_order_ceiling_before_bucket(self):
        # A call that violates BOTH guards must report the ceiling first.
        combo = ComboBudget(max_budget_usd=10.0)
        for _ in range(11):
            combo.check_and_charge("tool", 0.009, 0)  # drain bucket
        with self.assertRaises(ComboDenied) as ctx:
            combo.check_and_charge("tool", 0.50, 0)  # over ceiling AND bucket empty
        self.assertEqual(ctx.exception.guard, GUARD_PER_CALL)


class TestValidation(unittest.TestCase):
    def test_unknown_call_type_raises_value_error(self):
        combo = ComboBudget()
        with self.assertRaises(ValueError):
            combo.check_and_charge("teleport", 0.001, 0)

    def test_negative_cost_raises(self):
        combo = ComboBudget()
        with self.assertRaises(ValueError):
            combo.check_and_charge("tool", -0.001, 0)

    def test_bool_cost_raises(self):
        combo = ComboBudget()
        with self.assertRaises(ValueError):
            combo.check_and_charge("tool", True, 0)  # type: ignore[arg-type]

    def test_negative_seq_raises(self):
        combo = ComboBudget()
        with self.assertRaises(ValueError):
            combo.check_and_charge("tool", 0.001, -1)

    def test_bool_seq_raises(self):
        combo = ComboBudget()
        with self.assertRaises(ValueError):
            combo.check_and_charge("tool", 0.001, True)  # type: ignore[arg-type]

    def test_invalid_max_budget_raises(self):
        with self.assertRaises(ValueError):
            ComboBudget(max_budget_usd=-1.0)


class TestTryCharge(unittest.TestCase):
    def test_try_charge_allowed(self):
        combo = ComboBudget()
        ok, result = combo.try_charge("tool", 0.001, 0)
        self.assertTrue(ok)
        self.assertIsInstance(result, ComboCharge)

    def test_try_charge_denied_returns_denial(self):
        combo = ComboBudget()
        ok, result = combo.try_charge("tool", 0.50, 0)
        self.assertFalse(ok)
        self.assertIsInstance(result, ComboDenied)
        self.assertEqual(result.guard, GUARD_PER_CALL)

    def test_try_charge_validation_still_raises(self):
        combo = ComboBudget()
        with self.assertRaises(ValueError):
            combo.try_charge("nope", 0.001, 0)


class TestStatus(unittest.TestCase):
    def test_as_dict_shape(self):
        combo = ComboBudget(max_budget_usd=1.0)
        combo.check_and_charge("tool", 0.001, 0)
        d = combo.as_dict()
        self.assertEqual(d["version"], BUDGET_COMBO_VERSION)
        self.assertIn("cost_guard", d)
        self.assertIn("rate_guard", d)
        self.assertEqual(d["combo_charges"], 1)

    def test_remaining_and_exhausted(self):
        combo = ComboBudget(max_budget_usd=0.01)
        self.assertFalse(combo.exhausted)
        combo.check_and_charge("tool", 0.01, 0)
        self.assertTrue(combo.exhausted)
        self.assertEqual(combo.remaining, 0.0)

    def test_observe_model_passthrough(self):
        combo = ComboBudget()
        combo.check_and_charge("model", 0.05, 0)
        # observe_model delegates to the run budget; must not raise.
        combo.observe_model({"total_tokens": 10}, "test-model")

    def test_bucket_rejections_visible(self):
        combo = ComboBudget()
        for _ in range(11):
            combo.check_and_charge("tool", 0.009, 0)
        with self.assertRaises(ComboDenied):
            combo.check_and_charge("tool", 0.009, 0)
        self.assertEqual(len(combo.bucket_rejections), 1)

    def test_custom_buckets(self):
        from budget_token_bucket import TokenBucket

        combo = ComboBudget(
            buckets={"tool": TokenBucket(0.02, 0.001, start_seq=0),
                     "model": TokenBucket(1.0, 0.05, start_seq=0),
                     "memory_read": TokenBucket(0.05, 0.01, start_seq=0),
                     "memory_write": TokenBucket(0.05, 0.005, start_seq=0)}
        )
        combo.check_and_charge("tool", 0.009, 0)
        combo.check_and_charge("tool", 0.009, 0)
        with self.assertRaises(ComboDenied) as ctx:
            combo.check_and_charge("tool", 0.009, 0)
        self.assertEqual(ctx.exception.guard, GUARD_BUCKET)

    def test_main_smoke(self):
        import budget_combo

        budget_combo.main()


if __name__ == "__main__":
    unittest.main()
