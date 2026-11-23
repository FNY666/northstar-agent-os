"""Tests for circuit_breaker.py (15 required)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from circuit_breaker import (  # noqa: E402
    CIRCUIT_BREAKER_VERSION,
    SCHEMA_PIN,
    BreakerEvent,
    CircuitBreaker,
    CircuitBreakerError,
    CircuitOpenError,
    CircuitState,
)


def _ok() -> str:
    return "ok"


def _boom() -> str:
    raise RuntimeError("subsystem down")


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CIRCUIT_BREAKER_VERSION, "circuit-breaker.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.circuit-breaker.v1")


class TestConstruction(unittest.TestCase):
    def test_defaults_closed(self):
        b = CircuitBreaker()
        self.assertEqual(b.state, CircuitState.CLOSED)
        self.assertEqual(b.consecutive_failures, 0)

    def test_bad_threshold_rejected(self):
        for bad in (0, -1, True, "3", 2.0):
            with self.assertRaises(CircuitBreakerError):
                CircuitBreaker(failure_threshold=bad)

    def test_bad_cooldown_rejected(self):
        for bad in (-1, True, "5", 1.5):
            with self.assertRaises(CircuitBreakerError):
                CircuitBreaker(cooldown_seqs=bad)


class TestTripAndFailFast(unittest.TestCase):
    def test_trips_at_threshold(self):
        b = CircuitBreaker(failure_threshold=3)
        for s in (1, 2):
            with self.assertRaises(RuntimeError):
                b.call(_boom, seq=s)
            self.assertEqual(b.state, CircuitState.CLOSED)
        with self.assertRaises(RuntimeError):
            b.call(_boom, seq=3)
        self.assertEqual(b.state, CircuitState.OPEN)

    def test_open_fails_fast_without_invoking(self):
        b = CircuitBreaker(failure_threshold=1)
        with self.assertRaises(RuntimeError):
            b.call(_boom, seq=1)
        invoked = []
        with self.assertRaises(CircuitOpenError) as ctx:
            b.call(lambda: invoked.append(1), seq=2)
        self.assertEqual(invoked, [])
        self.assertEqual(ctx.exception.state, CircuitState.OPEN)

    def test_original_exception_propagates_unwrapped(self):
        b = CircuitBreaker(failure_threshold=5)
        with self.assertRaises(RuntimeError) as ctx:
            b.call(_boom, seq=1)
        self.assertEqual(str(ctx.exception), "subsystem down")

    def test_success_resets_consecutive_count(self):
        b = CircuitBreaker(failure_threshold=3)
        for s in (1, 2):
            with self.assertRaises(RuntimeError):
                b.call(_boom, seq=s)
        self.assertEqual(b.call(_ok, seq=3), "ok")
        self.assertEqual(b.consecutive_failures, 0)
        self.assertEqual(b.state, CircuitState.CLOSED)

    def test_non_callable_rejected(self):
        b = CircuitBreaker()
        with self.assertRaises(CircuitBreakerError):
            b.call("not-callable", seq=1)


class TestRecovery(unittest.TestCase):
    def test_half_open_trial_success_closes(self):
        b = CircuitBreaker(failure_threshold=1, cooldown_seqs=5)
        with self.assertRaises(RuntimeError):
            b.call(_boom, seq=10)
        self.assertEqual(b.state, CircuitState.OPEN)
        # seq 11..14: still in cooldown, fail fast.
        for s in (11, 14):
            with self.assertRaises(CircuitOpenError):
                b.call(_ok, seq=s)
        # seq 15: cooldown elapsed -> half-open trial succeeds.
        self.assertEqual(b.call(_ok, seq=15), "ok")
        self.assertEqual(b.state, CircuitState.CLOSED)

    def test_half_open_trial_failure_reopens(self):
        b = CircuitBreaker(failure_threshold=1, cooldown_seqs=2)
        with self.assertRaises(RuntimeError):
            b.call(_boom, seq=1)
        with self.assertRaises(RuntimeError):
            b.call(_boom, seq=3)  # half-open trial fails
        self.assertEqual(b.state, CircuitState.OPEN)

    def test_manual_reset(self):
        b = CircuitBreaker(failure_threshold=1)
        with self.assertRaises(RuntimeError):
            b.call(_boom, seq=1)
        self.assertEqual(b.state, CircuitState.OPEN)
        b.reset(seq=2)
        self.assertEqual(b.state, CircuitState.CLOSED)
        self.assertEqual(b.consecutive_failures, 0)
        self.assertEqual(b.call(_ok, seq=3), "ok")

    def test_allow_call_does_not_invoke(self):
        b = CircuitBreaker(failure_threshold=1, cooldown_seqs=0)
        with self.assertRaises(RuntimeError):
            b.call(_boom, seq=1)
        self.assertTrue(b.allow_call(seq=2))  # cooldown 0 -> half-open


class TestValidationAndEvents(unittest.TestCase):
    def test_bad_seq_rejected(self):
        b = CircuitBreaker()
        for bad in (-1, True, "1", 1.0, None):
            with self.assertRaises(CircuitBreakerError):
                b.call(_ok, seq=bad)
            with self.assertRaises(CircuitBreakerError):
                b.report_success(bad)
            with self.assertRaises(CircuitBreakerError):
                b.report_failure(bad)
            with self.assertRaises(CircuitBreakerError):
                b.reset(bad)

    def test_events_recorded_in_order(self):
        b = CircuitBreaker(failure_threshold=1)
        with self.assertRaises(RuntimeError):
            b.call(_boom, seq=1)
        b.reset(seq=2)
        kinds = [e.kind for e in b.events()]
        self.assertEqual(kinds, ["opened", "reset"])
        self.assertTrue(all(isinstance(e, BreakerEvent) for e in b.events()))
        self.assertEqual(b.events()[0].as_dict()["schema"], SCHEMA_PIN)

    def test_event_frozen_and_validated(self):
        e = BreakerEvent(kind="opened", seq=5, consecutive_failures=3)
        with self.assertRaises(Exception):
            e.kind = "closed"  # frozen
        with self.assertRaises(CircuitBreakerError):
            BreakerEvent(kind="bogus", seq=1, consecutive_failures=0)

    def test_report_api_without_call(self):
        b = CircuitBreaker(failure_threshold=2)
        b.report_failure(seq=1)
        self.assertEqual(b.state, CircuitState.CLOSED)
        b.report_failure(seq=2)
        self.assertEqual(b.state, CircuitState.OPEN)
        b.report_success(seq=3)
        self.assertEqual(b.state, CircuitState.CLOSED)

    def test_main_self_check(self):
        import circuit_breaker

        circuit_breaker.main()


if __name__ == "__main__":
    unittest.main()
