"""Tests for budget_token_bucket: token-bucket rate limiting."""

import unittest

from budget_token_bucket import (
    BUCKET_PARAMS,
    TOKEN_BUCKET_VERSION,
    BucketRejection,
    TokenBucket,
    TokenBucketBudget,
    TokenBucketError,
)


class TokenBucketBasicsTest(unittest.TestCase):
    def test_starts_full(self):
        b = TokenBucket(1.0, 0.1)
        self.assertAlmostEqual(b.tokens, 1.0)

    def test_consume_success(self):
        b = TokenBucket(1.0, 0.1)
        self.assertTrue(b.consume(0.4, 0))
        self.assertAlmostEqual(b.tokens, 0.6)

    def test_consume_failure_does_not_deduct(self):
        b = TokenBucket(1.0, 0.1)
        self.assertFalse(b.consume(1.5, 0))
        self.assertAlmostEqual(b.tokens, 1.0)

    def test_consume_exactly_capacity(self):
        b = TokenBucket(1.0, 0.1)
        self.assertTrue(b.consume(1.0, 0))
        self.assertAlmostEqual(b.tokens, 0.0)

    def test_refill_linear(self):
        b = TokenBucket(1.0, 0.1)
        b.consume(1.0, 0)
        b.refill(5)
        self.assertAlmostEqual(b.tokens, 0.5)

    def test_refill_capped_at_capacity(self):
        b = TokenBucket(1.0, 0.5)
        b.consume(0.2, 0)
        b.refill(100)
        self.assertAlmostEqual(b.tokens, 1.0)

    def test_refill_idempotent_same_seq(self):
        b = TokenBucket(1.0, 0.1)
        b.consume(0.5, 3)
        b.refill(3)
        self.assertAlmostEqual(b.tokens, 0.5)

    def test_backwards_seq_raises(self):
        b = TokenBucket(1.0, 0.1)
        b.refill(5)
        with self.assertRaises(TokenBucketError):
            b.refill(3)

    def test_negative_capacity_raises(self):
        with self.assertRaises(TokenBucketError):
            TokenBucket(-1.0, 0.1)

    def test_zero_capacity_raises(self):
        with self.assertRaises(TokenBucketError):
            TokenBucket(0.0, 0.1)

    def test_bool_seq_rejected(self):
        with self.assertRaises(TokenBucketError):
            TokenBucket(1.0, 0.1, start_seq=True)

    def test_negative_cost_rejected(self):
        b = TokenBucket(1.0, 0.1)
        with self.assertRaises(TokenBucketError):
            b.consume(-0.1, 0)


class TimeUntilAvailableTest(unittest.TestCase):
    def test_zero_when_available(self):
        b = TokenBucket(1.0, 0.1)
        self.assertEqual(b.time_until_available(0.5, 0), 0)

    def test_rounds_up(self):
        b = TokenBucket(1.0, 0.1)
        b.consume(1.0, 0)
        # deficit 0.5, rate 0.1 -> 5 seqs
        self.assertEqual(b.time_until_available(0.5, 0), 5)
        # deficit 0.55 -> ceil(5.5) = 6
        self.assertEqual(b.time_until_available(0.55, 0), 6)

    def test_zero_rate_never(self):
        b = TokenBucket(1.0, 0.0)
        b.consume(1.0, 0)
        self.assertEqual(b.time_until_available(0.5, 0), -1)

    def test_wait_then_consume_succeeds(self):
        b = TokenBucket(1.0, 0.1)
        b.consume(1.0, 0)
        wait = b.time_until_available(0.5, 0)
        self.assertTrue(b.consume(0.5, wait))


class TokenBucketBudgetTest(unittest.TestCase):
    def test_default_buckets_cover_all_types(self):
        budget = TokenBucketBudget()
        for ctype in BUCKET_PARAMS:
            self.assertGreater(budget.tokens_for(ctype), 0)

    def test_unknown_call_type_fail_closed(self):
        budget = TokenBucketBudget()
        with self.assertRaises(TokenBucketError):
            budget.check_and_consume("nonsense", 0.01, 0)

    def test_buckets_are_independent(self):
        budget = TokenBucketBudget()
        # Drain model bucket
        budget.check_and_consume("model", 1.0, 0)
        self.assertFalse(budget.check_and_consume("model", 0.1, 0))
        # Tool bucket untouched
        self.assertTrue(budget.check_and_consume("tool", 0.05, 0))

    def test_rejection_logged(self):
        budget = TokenBucketBudget()
        budget.check_and_consume("model", 1.0, 0)
        ok = budget.check_and_consume("model", 0.5, 0)
        self.assertFalse(ok)
        self.assertEqual(len(budget.rejections), 1)
        rej = budget.rejections[0]
        self.assertIsInstance(rej, BucketRejection)
        self.assertEqual(rej.call_type, "model")
        self.assertGreaterEqual(rej.retry_in_seqs, 0)

    def test_rejection_retry_hint_accurate(self):
        budget = TokenBucketBudget()
        budget.check_and_consume("model", 1.0, 0)
        budget.check_and_consume("model", 0.5, 0)
        rej = budget.rejections[0]
        # After waiting retry_in seqs, the call should succeed
        self.assertTrue(
            budget.check_and_consume("model", 0.5, rej.retry_in_seqs)
        )

    def test_custom_buckets(self):
        custom = {"model": TokenBucket(2.0, 0.2)}
        budget = TokenBucketBudget(custom)
        self.assertAlmostEqual(budget.tokens_for("model"), 2.0)
        with self.assertRaises(TokenBucketError):
            budget.tokens_for("tool")

    def test_unknown_custom_type_rejected(self):
        with self.assertRaises(TokenBucketError):
            TokenBucketBudget({"evil": TokenBucket(1.0, 0.1)})

    def test_as_dict_shape(self):
        budget = TokenBucketBudget()
        d = budget.as_dict()
        self.assertEqual(d["version"], TOKEN_BUCKET_VERSION)
        self.assertIn("model", d["buckets"])
        self.assertEqual(d["rejections"], 0)

    def test_instances_do_not_share_rejections(self):
        a = TokenBucketBudget()
        b = TokenBucketBudget()
        a.check_and_consume("model", 1.0, 0)
        a.check_and_consume("model", 0.5, 0)
        self.assertEqual(len(a.rejections), 1)
        self.assertEqual(len(b.rejections), 0)


class VersionTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(TOKEN_BUCKET_VERSION, "token-bucket.v1")


if __name__ == "__main__":
    unittest.main()
