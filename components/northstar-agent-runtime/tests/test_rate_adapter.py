"""Tests for rate_adapter (AIMD adaptation)."""

import unittest

from rate_adapter import RateAdapter


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        self.t += 1.0
        return self.t


class TestRateAdapterInit(unittest.TestCase):
    def test_initial_rate_used_as_is(self):
        a = RateAdapter(initial_rate=25.0, clock=FakeClock())
        self.assertEqual(a.current_rate(), 25.0)

    def test_initial_rate_clamped_above_max(self):
        a = RateAdapter(initial_rate=999.0, max_rate=50.0, clock=FakeClock())
        self.assertEqual(a.current_rate(), 50.0)

    def test_initial_rate_clamped_below_min(self):
        a = RateAdapter(initial_rate=0.01, min_rate=2.0, clock=FakeClock())
        self.assertEqual(a.current_rate(), 2.0)

    def test_invalid_min_rate_raises(self):
        with self.assertRaises(ValueError):
            RateAdapter(min_rate=0.0, clock=FakeClock())

    def test_invalid_max_below_min_raises(self):
        with self.assertRaises(ValueError):
            RateAdapter(min_rate=10.0, max_rate=5.0, clock=FakeClock())

    def test_invalid_beta_raises(self):
        for bad in (0.0, 1.0, -0.2, 1.5):
            with self.assertRaises(ValueError, msg=f"beta={bad}"):
                RateAdapter(beta=bad, clock=FakeClock())

    def test_invalid_alpha_raises(self):
        with self.assertRaises(ValueError):
            RateAdapter(alpha=0.0, clock=FakeClock())


class TestAIMD(unittest.TestCase):
    def test_success_adds_alpha(self):
        a = RateAdapter(initial_rate=10.0, alpha=2.0, clock=FakeClock())
        self.assertAlmostEqual(a.on_success(), 12.0)
        self.assertAlmostEqual(a.on_success(), 14.0)

    def test_success_caps_at_max(self):
        a = RateAdapter(initial_rate=99.0, max_rate=100.0, alpha=5.0,
                        clock=FakeClock())
        self.assertEqual(a.on_success(), 100.0)
        self.assertEqual(a.on_success(), 100.0)

    def test_loss_multiplies_by_beta(self):
        a = RateAdapter(initial_rate=100.0, beta=0.5, clock=FakeClock())
        self.assertAlmostEqual(a.on_loss(), 50.0)
        self.assertAlmostEqual(a.on_loss(), 25.0)

    def test_loss_floors_at_min(self):
        a = RateAdapter(initial_rate=5.0, min_rate=2.0, beta=0.5,
                        clock=FakeClock())
        a.on_loss()  # 2.5
        self.assertAlmostEqual(a.on_loss(), 2.0)
        self.assertAlmostEqual(a.on_loss(), 2.0)

    def test_current_rate_tracks_last_adaptation(self):
        a = RateAdapter(initial_rate=10.0, alpha=1.0, beta=0.5,
                        clock=FakeClock())
        a.on_success()
        self.assertAlmostEqual(a.current_rate(), 11.0)
        a.on_loss()
        self.assertAlmostEqual(a.current_rate(), 5.5)

    def test_successes_and_losses_counted(self):
        a = RateAdapter(clock=FakeClock())
        a.on_success()
        a.on_success()
        a.on_loss()
        self.assertEqual(a.successes, 2)
        self.assertEqual(a.losses, 1)

    def test_consecutive_losses(self):
        a = RateAdapter(clock=FakeClock())
        a.on_loss()
        a.on_loss()
        self.assertEqual(a.consecutive_losses, 2)
        a.on_success()
        self.assertEqual(a.consecutive_losses, 0)

    def test_loss_rate(self):
        a = RateAdapter(clock=FakeClock())
        self.assertEqual(a.loss_rate, 0.0)
        a.on_success()
        a.on_success()
        a.on_success()
        a.on_loss()
        self.assertAlmostEqual(a.loss_rate, 0.25)


class TestHistoryAndReset(unittest.TestCase):
    def test_history_records_events(self):
        clock = FakeClock()
        a = RateAdapter(initial_rate=10.0, clock=clock)
        a.on_success()
        a.on_loss()
        hist = a.history
        self.assertEqual(len(hist), 3)  # initial + 2 events
        self.assertAlmostEqual(hist[-1][1], a.current_rate())
        self.assertTrue(all(hist[i][0] < hist[i + 1][0]
                            for i in range(len(hist) - 1)))

    def test_reset_restores_state(self):
        a = RateAdapter(initial_rate=10.0, alpha=1.0, beta=0.5,
                        clock=FakeClock())
        a.on_success()
        a.on_loss()
        self.assertEqual(a.successes + a.losses, 2)
        a.reset()
        self.assertEqual(a.successes, 0)
        self.assertEqual(a.losses, 0)
        self.assertEqual(a.consecutive_losses, 0)
        # reset() with no rate preserves the current rate (5.5), per docstring
        self.assertAlmostEqual(a.current_rate(), 5.5)
        a.reset(rate=10.0)
        self.assertAlmostEqual(a.current_rate(), 10.0)

    def test_reset_with_rate(self):
        a = RateAdapter(initial_rate=10.0, max_rate=100.0, clock=FakeClock())
        a.reset(rate=42.0)
        self.assertAlmostEqual(a.current_rate(), 42.0)

    def test_long_success_run_converges_to_max(self):
        a = RateAdapter(initial_rate=1.0, min_rate=1.0, max_rate=20.0,
                        alpha=1.0, clock=FakeClock())
        for _ in range(100):
            a.on_success()
        self.assertEqual(a.current_rate(), 20.0)

    def test_long_loss_run_converges_to_min(self):
        a = RateAdapter(initial_rate=20.0, min_rate=1.0, beta=0.5,
                        clock=FakeClock())
        for _ in range(100):
            a.on_loss()
        self.assertEqual(a.current_rate(), 1.0)


if __name__ == "__main__":
    unittest.main()
