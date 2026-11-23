"""Targeted tests for rate_limiter.py."""

import unittest

from rate_limiter import (
    RATE_LIMITER_VERSION,
    SCHEMA_PIN,
    LimitDecision,
    RateLimiter,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        rl = RateLimiter(3, 1)
        self.assertEqual(rl.version, "rate-limiter.v1")
        self.assertEqual(RATE_LIMITER_VERSION, "rate-limiter.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.rate-limiter.v1")


class TestConstructor(unittest.TestCase):
    def test_zero_capacity_rejected(self):
        with self.assertRaises(ValueError):
            RateLimiter(0, 1)

    def test_zero_rate_rejected(self):
        with self.assertRaises(ValueError):
            RateLimiter(3, 0)

    def test_bool_rejected(self):
        with self.assertRaises(TypeError):
            RateLimiter(True, 1)
        with self.assertRaises(TypeError):
            RateLimiter(3, True)

    def test_properties(self):
        rl = RateLimiter(5, 2)
        self.assertEqual(rl.capacity, 5)
        self.assertEqual(rl.refill_per_second, 2)


class TestBurst(unittest.TestCase):
    def test_full_burst_allowed(self):
        rl = RateLimiter(3, 1)
        self.assertTrue(all(rl.allow_request(0) for _ in range(3)))

    def test_fourth_request_denied(self):
        rl = RateLimiter(3, 1)
        for _ in range(3):
            rl.allow_request(0)
        self.assertFalse(rl.allow_request(0))

    def test_wait_time_zero_when_tokens(self):
        rl = RateLimiter(3, 1)
        self.assertEqual(rl.get_wait_time(0), 0)


class TestRefill(unittest.TestCase):
    def test_one_token_after_one_second(self):
        rl = RateLimiter(2, 1)
        rl.allow_request(0)
        rl.allow_request(0)
        self.assertFalse(rl.allow_request(0))
        self.assertTrue(rl.allow_request(1000))

    def test_wait_time_exact(self):
        rl = RateLimiter(1, 1)
        rl.allow_request(0)
        self.assertEqual(rl.get_wait_time(0), 1000)
        self.assertEqual(rl.get_wait_time(500), 500)

    def test_refill_caps_at_capacity(self):
        rl = RateLimiter(2, 10)
        rl.allow_request(0)
        # long idle: cannot exceed capacity
        self.assertTrue(rl.allow_request(60000))
        self.assertTrue(rl.allow_request(60000))
        self.assertFalse(rl.allow_request(60000))

    def test_fractional_refill_no_drift(self):
        # 3 tokens/sec: 333ms -> 0 tokens, 334ms -> 1 token
        rl = RateLimiter(1, 3)
        rl.allow_request(0)
        self.assertFalse(rl.allow_request(333))
        self.assertTrue(rl.allow_request(334))


class TestDecide(unittest.TestCase):
    def test_decide_record(self):
        rl = RateLimiter(1, 1)
        d = rl.decide(0)
        self.assertIsInstance(d, LimitDecision)
        self.assertTrue(d.allowed)
        self.assertEqual(d.tokens_after, 0)
        self.assertEqual(d.wait_ms, 1000)
        self.assertEqual(d.schema, "northstar.rate-limiter.v1")
        asd = d.as_dict()
        self.assertEqual(asd["allowed"], True)
        self.assertEqual(asd["wait_ms"], 1000)

    def test_backward_time_fails_closed(self):
        rl = RateLimiter(3, 1)
        rl.allow_request(100)
        with self.assertRaises(TypeError):
            rl.allow_request(50)

    def test_reset_restores_capacity(self):
        rl = RateLimiter(2, 1)
        rl.allow_request(0)
        rl.allow_request(0)
        self.assertFalse(rl.allow_request(0))
        rl.reset()
        self.assertTrue(rl.allow_request(0))


if __name__ == "__main__":
    unittest.main()
