"""Tests for CircuitBreaker.open() (manual trip). 15 required."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from circuit_breaker import (  # noqa: E402
    CIRCUIT_BREAKER_VERSION,
    SCHEMA_PIN,
    CircuitBreaker,
    CircuitBreakerError,
    CircuitOpenError,
    CircuitState,
)


def _ok() -> str:
    return "ok"


def _boom() -> str:
    raise RuntimeError("subsystem down")


class TestManualOpen(unittest.TestCase):
    def test_open_from_closed(self):
        b = CircuitBreaker()
        self.assertEqual(b.open(1), CircuitState.OPEN)
        self.assertEqual(b.state, CircuitState.OPEN)

    def test_open_records_opened_event(self):
        b = CircuitBreaker()
        b.open(7)
        kinds = [e.kind for e in b.events()]
        self.assertIn("opened", kinds)
        ev = b.events()[-1]
        self.assertEqual(ev.kind, "opened")
        self.assertEqual(ev.seq, 7)
        self.assertEqual(ev.consecutive_failures, 0)

    def test_open_below_threshold_still_trips(self):
        # Manual trip does not wait for the failure threshold.
        b = CircuitBreaker(failure_threshold=10)
        with self.assertRaises(RuntimeError):
            b.call(_boom, seq=1)
        self.assertEqual(b.state, CircuitState.CLOSED)
        b.open(2)
        self.assertEqual(b.state, CircuitState.OPEN)

    def test_open_refuses_calls_fail_fast(self):
        b = CircuitBreaker()
        b.open(1)
        invoked = []
        with self.assertRaises(CircuitOpenError):
            b.call(lambda: invoked.append(1), seq=2)
        self.assertEqual(invoked, [])

    def test_open_idempotent_when_already_open(self):
        b = CircuitBreaker()
        b.open(1)
        n_events = len(b.events())
        self.assertEqual(b.open(2), CircuitState.OPEN)
        # No duplicate "opened" event on the no-op.
        self.assertEqual(len(b.events()), n_events)

    def test_open_from_half_open_restarts_cooldown(self):
        b = CircuitBreaker(failure_threshold=1, cooldown_seqs=5)
        with self.assertRaises(RuntimeError):
            b.call(_boom, seq=1)
        self.assertEqual(b.state, CircuitState.OPEN)
        # Cooldown elapsed -> half-open trial.
        self.assertTrue(b.allow_call(6))
        self.assertEqual(b.state, CircuitState.HALF_OPEN)
        # Manual open from half-open forces it back to open.
        b.open(7)
        self.assertEqual(b.state, CircuitState.OPEN)
        # Cooldown restarted at seq 7: no trial yet at seq 8.
        self.assertFalse(b.allow_call(8))
        self.assertTrue(b.allow_call(12))

    def test_open_bad_seq_rejected(self):
        b = CircuitBreaker()
        for bad in (-1, True, "3", 2.5, None):
            with self.assertRaises(CircuitBreakerError):
                b.open(bad)
        self.assertEqual(b.state, CircuitState.CLOSED)

    def test_open_then_reset_recovers(self):
        b = CircuitBreaker()
        b.open(1)
        b.reset(2)
        self.assertEqual(b.state, CircuitState.CLOSED)
        self.assertEqual(b.consecutive_failures, 0)
        self.assertEqual(b.call(_ok, seq=3), "ok")

    def test_open_then_report_success_closes(self):
        # Existing semantics: success while open/half-open closes.
        b = CircuitBreaker()
        b.open(1)
        self.assertEqual(b.report_success(2), CircuitState.CLOSED)

    def test_open_preserves_failure_count(self):
        b = CircuitBreaker(failure_threshold=5)
        with self.assertRaises(RuntimeError):
            b.call(_boom, seq=1)
        with self.assertRaises(RuntimeError):
            b.call(_boom, seq=2)
        b.open(3)
        self.assertEqual(b.consecutive_failures, 2)
        self.assertEqual(b.events()[-1].consecutive_failures, 2)

    def test_open_event_carries_schema_pins(self):
        b = CircuitBreaker()
        b.open(4)
        d = b.events()[-1].as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["version"], CIRCUIT_BREAKER_VERSION)
        self.assertEqual(d["kind"], "opened")

    def test_open_does_not_change_thresholds(self):
        b = CircuitBreaker(failure_threshold=4, cooldown_seqs=9)
        b.open(1)
        self.assertEqual(b.failure_threshold, 4)
        self.assertEqual(b.cooldown_seqs, 9)

    def test_half_open_trial_after_manual_open(self):
        b = CircuitBreaker(failure_threshold=3, cooldown_seqs=5)
        b.open(4)
        # Trial allowed once cooldown (seq 4 + 5) elapses.
        self.assertFalse(b.allow_call(5))
        self.assertEqual(b.call(_ok, seq=9), "ok")
        self.assertEqual(b.state, CircuitState.CLOSED)

    def test_breakers_are_independent(self):
        a = CircuitBreaker()
        c = CircuitBreaker()
        a.open(1)
        self.assertEqual(a.state, CircuitState.OPEN)
        self.assertEqual(c.state, CircuitState.CLOSED)
        self.assertEqual(c.call(_ok, seq=1), "ok")

    def test_module_main_still_passes(self):
        import subprocess

        mod = Path(__file__).resolve().parents[1] / "circuit_breaker.py"
        out = subprocess.run(
            [sys.executable, str(mod)], capture_output=True, text=True, timeout=30
        )
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("circuit-breaker OK", out.stdout)


if __name__ == "__main__":
    unittest.main()
