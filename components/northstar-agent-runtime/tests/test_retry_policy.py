"""Tests for retry_policy.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from retry_policy import (  # noqa: E402
    RETRY_POLICY_VERSION,
    SCHEMA_PIN,
    BackoffStrategy,
    RetryExhausted,
    RetryPolicy,
    RetryPolicyError,
    RetryReport,
    retry_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(RETRY_POLICY_VERSION, "retry-policy.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.retry-policy.v1")


class TestConstructorValidation(unittest.TestCase):
    def test_bad_attempts(self):
        for bad in (0, -1, True, "3", 2.5, None):
            with self.assertRaises(RetryPolicyError, msg=f"max_attempts={bad!r}"):
                RetryPolicy(max_attempts=bad)

    def test_bad_base_delay(self):
        for bad in (-1, True, "100", 1.5, None):
            with self.assertRaises(RetryPolicyError, msg=f"base_delay_ms={bad!r}"):
                RetryPolicy(base_delay_ms=bad)

    def test_bad_strategy(self):
        with self.assertRaises(RetryPolicyError):
            RetryPolicy(backoff_strategy="fibonacci")
        with self.assertRaises(RetryPolicyError):
            RetryPolicy(backoff_strategy=42)

    def test_strategy_case_insensitive_string(self):
        p = RetryPolicy(backoff_strategy="Exponential")
        self.assertEqual(p.backoff_strategy, BackoffStrategy.EXPONENTIAL)

    def test_bad_retry_on(self):
        with self.assertRaises(RetryPolicyError):
            RetryPolicy(retry_on=())
        with self.assertRaises(RetryPolicyError):
            RetryPolicy(retry_on="ValueError")
        with self.assertRaises(RetryPolicyError):
            RetryPolicy(retry_on=(ValueError, "nope"))

    def test_max_delay_below_base_rejected(self):
        with self.assertRaises(RetryPolicyError):
            RetryPolicy(base_delay_ms=100, max_delay_ms=50)


class TestDelayComputation(unittest.TestCase):
    def test_constant(self):
        p = RetryPolicy(max_attempts=4, backoff_strategy="constant", base_delay_ms=100)
        self.assertEqual(p.retry_schedule(), (100, 100, 100))

    def test_linear(self):
        p = RetryPolicy(max_attempts=4, backoff_strategy="linear", base_delay_ms=100)
        self.assertEqual(p.retry_schedule(), (100, 200, 300))

    def test_exponential(self):
        p = RetryPolicy(max_attempts=5, backoff_strategy="exponential", base_delay_ms=100)
        self.assertEqual(p.retry_schedule(), (100, 200, 400, 800))

    def test_cap_applied(self):
        p = RetryPolicy(
            max_attempts=5, backoff_strategy="exponential",
            base_delay_ms=100, max_delay_ms=250,
        )
        self.assertEqual(p.retry_schedule(), (100, 200, 250, 250))

    def test_no_retry_single_attempt(self):
        p = RetryPolicy(max_attempts=1)
        self.assertEqual(p.retry_schedule(), ())

    def test_deterministic(self):
        a = RetryPolicy(max_attempts=6, base_delay_ms=37)
        b = RetryPolicy(max_attempts=6, base_delay_ms=37)
        self.assertEqual(a.retry_schedule(), b.retry_schedule())

    def test_bad_attempt_number(self):
        p = RetryPolicy()
        for bad in (1, 0, -2, True, "2"):
            with self.assertRaises(RetryPolicyError):
                p.delay_before_attempt(bad)


class TestExecute(unittest.TestCase):
    def test_success_first_try_no_sleep(self):
        waited = []
        result, report = RetryPolicy().execute(lambda: 42, sleeper=waited.append)
        self.assertEqual(result, 42)
        self.assertTrue(report.succeeded)
        self.assertEqual(report.attempts_made, 1)
        self.assertEqual(waited, [])
        self.assertEqual(report.delays_ms, ())

    def test_success_after_retries_uses_schedule(self):
        waited = []
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise ValueError("boom")
            return "ok"

        p = RetryPolicy(max_attempts=4, backoff_strategy="linear", base_delay_ms=100)
        result, report = p.execute(flaky, sleeper=waited.append)
        self.assertEqual(result, "ok")
        self.assertEqual(report.attempts_made, 3)
        self.assertEqual(waited, [0.1, 0.2])  # seconds, matches linear schedule

    def test_exhaustion_chains_last_error(self):
        def always():
            raise RuntimeError("dead")

        p = RetryPolicy(max_attempts=3, base_delay_ms=10)
        with self.assertRaises(RetryExhausted) as ctx:
            p.execute(always, sleeper=lambda s: None)
        exc = ctx.exception
        self.assertEqual(exc.report.attempts_made, 3)
        self.assertFalse(exc.report.succeeded)
        self.assertEqual(exc.report.last_error_type, "RuntimeError")
        self.assertIsInstance(exc.__cause__, RuntimeError)
        self.assertIs(exc.last_error, exc.__cause__)

    def test_non_retryable_propagates_immediately(self):
        calls = {"n": 0}

        def bad():
            calls["n"] += 1
            raise KeyError("programming error")

        p = RetryPolicy(max_attempts=5, retry_on=(ValueError,), base_delay_ms=1)
        with self.assertRaises(KeyError):
            p.execute(bad, sleeper=lambda s: None)
        self.assertEqual(calls["n"], 1)  # no retry consumed

    def test_retry_on_single_class(self):
        p = RetryPolicy(max_attempts=2, retry_on=ValueError, base_delay_ms=1)
        calls = {"n": 0}

        def raises_value():
            calls["n"] += 1
            raise ValueError("x")

        with self.assertRaises(RetryExhausted):
            p.execute(raises_value, sleeper=lambda s: None)
        self.assertEqual(calls["n"], 2)

    def test_keyboard_interrupt_never_retried(self):
        p = RetryPolicy(max_attempts=5, base_delay_ms=1)
        with self.assertRaises(KeyboardInterrupt):
            p.execute(lambda: (_ for _ in ()).throw(KeyboardInterrupt()), sleeper=lambda s: None)

    def test_args_kwargs_passthrough(self):
        result, report = RetryPolicy().execute(
            lambda a, b=0: a + b, 2, b=3, sleeper=lambda s: None
        )
        self.assertEqual(result, 5)
        self.assertTrue(report.succeeded)

    def test_non_callable_rejected(self):
        with self.assertRaises(RetryPolicyError):
            RetryPolicy().execute("not-a-function", sleeper=lambda s: None)

    def test_report_frozen_and_shaped(self):
        _, report = RetryPolicy(max_attempts=2, base_delay_ms=5).execute(
            lambda: "x", sleeper=lambda s: None
        )
        self.assertIsInstance(report, RetryReport)
        d = report.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["version"], RETRY_POLICY_VERSION)
        with self.assertRaises(AttributeError):
            report.attempts_made = 99  # frozen

    def test_audit_event_shape(self):
        _, report = RetryPolicy().execute(lambda: 1, sleeper=lambda s: None)
        event = retry_audit_event(report, seq=7)
        self.assertEqual(event["audit_seq"], 7)
        self.assertEqual(event["event"], "retry-policy")
        self.assertEqual(event["schema"], SCHEMA_PIN)
        with self.assertRaises(RetryPolicyError):
            retry_audit_event(report, seq=-1)
        with self.assertRaises(RetryPolicyError):
            retry_audit_event(report, seq=True)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import retry_policy

        retry_policy.main()  # raises on failure


if __name__ == "__main__":
    unittest.main()
