"""Tests for timeout_manager: safety deadlines on untrusted work."""

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from timeout_manager import (
    ACTION_DENY,
    ACTION_ESCALATE,
    ACTION_KILL,
    OUTCOME_COMPLETED,
    OUTCOME_FAILED,
    OUTCOME_TIMEOUT,
    TIMEOUT_MANAGER_VERSION,
    TIMEOUT_SCHEMA,
    Timeout,
    TimeoutExceeded,
    TimeoutManager,
    timeout_audit_event,
)


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(TIMEOUT_MANAGER_VERSION, "timeout-manager.v1")

    def test_schema_pin(self):
        self.assertEqual(TIMEOUT_SCHEMA, "northstar.timeout-manager.v1")


class TestTimeoutRecord(unittest.TestCase):
    def test_frozen(self):
        timeout = Timeout(name="t", duration=1.0, action=ACTION_DENY)
        with self.assertRaises(AttributeError):
            timeout.duration = 2.0  # type: ignore[misc]

    def test_as_dict_shape(self):
        timeout = Timeout(name="model-call", duration=2.5, action=ACTION_KILL)
        record = timeout.as_dict()
        self.assertEqual(record["schema"], TIMEOUT_SCHEMA)
        self.assertEqual(record["version"], TIMEOUT_MANAGER_VERSION)
        self.assertEqual(record["name"], "model-call")
        self.assertEqual(record["duration"], 2.5)
        self.assertEqual(record["action"], ACTION_KILL)

    def test_all_actions_valid(self):
        for action in (ACTION_DENY, ACTION_KILL, ACTION_ESCALATE):
            Timeout(name="t", duration=1.0, action=action)

    def test_bad_action_rejected(self):
        with self.assertRaises(ValueError):
            Timeout(name="t", duration=1.0, action="warn")

    def test_empty_name_rejected(self):
        with self.assertRaises(ValueError):
            Timeout(name="", duration=1.0, action=ACTION_DENY)

    def test_zero_duration_rejected(self):
        with self.assertRaises(ValueError):
            Timeout(name="t", duration=0.0, action=ACTION_DENY)

    def test_negative_duration_rejected(self):
        with self.assertRaises(ValueError):
            Timeout(name="t", duration=-1.0, action=ACTION_DENY)

    def test_bool_duration_rejected(self):
        with self.assertRaises(TypeError):
            Timeout(name="t", duration=True, action=ACTION_DENY)

    def test_str_duration_rejected(self):
        with self.assertRaises(TypeError):
            Timeout(name="t", duration="5", action=ACTION_DENY)


class TestTimeoutExceeded(unittest.TestCase):
    def test_carries_timeout(self):
        timeout = Timeout(name="t", duration=1.0, action=ACTION_ESCALATE)
        exc = TimeoutExceeded(timeout)
        self.assertIs(exc.timeout, timeout)
        self.assertIn("t", str(exc))

    def test_non_timeout_rejected(self):
        with self.assertRaises(TypeError):
            TimeoutExceeded("not-a-timeout")  # type: ignore[arg-type]


class TestDeadlineArithmetic(unittest.TestCase):
    def setUp(self):
        self.manager = TimeoutManager()

    def test_deadline_in_future(self):
        timeout = Timeout(name="t", duration=60.0, action=ACTION_DENY)
        before = time.monotonic()
        deadline = self.manager.deadline_for(timeout)
        after = time.monotonic()
        self.assertGreaterEqual(deadline, before + 60.0)
        self.assertLessEqual(deadline, after + 60.0)

    def test_deadline_for_rejects_non_timeout(self):
        with self.assertRaises(TypeError):
            self.manager.deadline_for("nope")  # type: ignore[arg-type]

    def test_expired_future_false(self):
        deadline = time.monotonic() + 60.0
        self.assertFalse(self.manager.expired(deadline))

    def test_expired_past_true(self):
        deadline = time.monotonic() - 1.0
        self.assertTrue(self.manager.expired(deadline))

    def test_expired_rejects_bool(self):
        with self.assertRaises(TypeError):
            self.manager.expired(True)

    def test_remaining_positive_before(self):
        deadline = time.monotonic() + 60.0
        self.assertGreater(self.manager.remaining(deadline), 0.0)

    def test_remaining_zero_after(self):
        deadline = time.monotonic() - 1.0
        self.assertEqual(self.manager.remaining(deadline), 0.0)


class TestRunWithTimeout(unittest.TestCase):
    def setUp(self):
        self.manager = TimeoutManager()

    def test_fast_function_returns_result(self):
        timeout = Timeout(name="t", duration=5.0, action=ACTION_DENY)
        self.assertEqual(self.manager.run_with_timeout(lambda: 42, timeout), 42)

    def test_args_and_kwargs_passed(self):
        timeout = Timeout(name="t", duration=5.0, action=ACTION_DENY)

        def add(a, b=0):
            return a + b

        self.assertEqual(
            self.manager.run_with_timeout(add, timeout, 2, b=3), 5
        )

    def test_slow_function_raises_timeout_exceeded(self):
        timeout = Timeout(name="slow", duration=0.05, action=ACTION_KILL)
        with self.assertRaises(TimeoutExceeded) as ctx:
            self.manager.run_with_timeout(time.sleep, timeout, 10.0)
        self.assertIs(ctx.exception.timeout, timeout)

    def test_function_exception_propagates_unchanged(self):
        timeout = Timeout(name="t", duration=5.0, action=ACTION_DENY)

        def boom():
            raise RuntimeError("own failure")

        with self.assertRaises(RuntimeError) as ctx:
            self.manager.run_with_timeout(boom, timeout)
        self.assertEqual(str(ctx.exception), "own failure")

    def test_non_callable_rejected(self):
        timeout = Timeout(name="t", duration=5.0, action=ACTION_DENY)
        with self.assertRaises(TypeError):
            self.manager.run_with_timeout(42, timeout)  # type: ignore[arg-type]

    def test_non_timeout_rejected(self):
        with self.assertRaises(TypeError):
            self.manager.run_with_timeout(lambda: 1, "nope")  # type: ignore[arg-type]


class TestAuditEvent(unittest.TestCase):
    def test_shape(self):
        timeout = Timeout(name="t", duration=1.0, action=ACTION_DENY)
        event = timeout_audit_event(timeout, OUTCOME_COMPLETED, 7)
        self.assertEqual(event["schema"], "audit.ndjson/1")
        self.assertEqual(event["module"], TIMEOUT_MANAGER_VERSION)
        self.assertEqual(event["timeout"]["name"], "t")
        self.assertEqual(event["outcome"], OUTCOME_COMPLETED)
        self.assertEqual(event["audit_seq"], 7)

    def test_all_outcomes_valid(self):
        timeout = Timeout(name="t", duration=1.0, action=ACTION_DENY)
        for outcome in (OUTCOME_COMPLETED, OUTCOME_TIMEOUT, OUTCOME_FAILED):
            timeout_audit_event(timeout, outcome, 0)

    def test_bad_outcome_rejected(self):
        timeout = Timeout(name="t", duration=1.0, action=ACTION_DENY)
        with self.assertRaises(ValueError):
            timeout_audit_event(timeout, "maybe", 0)

    def test_bad_seq_rejected(self):
        timeout = Timeout(name="t", duration=1.0, action=ACTION_DENY)
        with self.assertRaises(ValueError):
            timeout_audit_event(timeout, OUTCOME_TIMEOUT, -1)

    def test_bool_seq_rejected(self):
        timeout = Timeout(name="t", duration=1.0, action=ACTION_DENY)
        with self.assertRaises(ValueError):
            timeout_audit_event(timeout, OUTCOME_TIMEOUT, True)

    def test_non_timeout_rejected(self):
        with self.assertRaises(TypeError):
            timeout_audit_event("nope", OUTCOME_TIMEOUT, 0)  # type: ignore[arg-type]


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import timeout_manager

        timeout_manager.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
