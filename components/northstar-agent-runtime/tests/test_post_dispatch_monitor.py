"""Tests for post-dispatch invariant monitoring."""

import unittest

from post_dispatch_monitor import PostDispatchMonitor


class PostDispatchMonitorTests(unittest.TestCase):
    def test_ok_on_successes(self):
        m = PostDispatchMonitor(window_size=10)
        for i in range(10):
            v = m.observe({"tool": "Read", "success": True, "args_digest": f"a{i}"})
        self.assertEqual(v, "OK")

    def test_halt_on_error_spike(self):
        m = PostDispatchMonitor(window_size=10, max_error_rate=0.20)
        for i in range(7):
            m.observe({"tool": "Read", "success": True, "args_digest": f"a{i}"})
        for i in range(3):
            v = m.observe({"tool": "Write", "success": False, "args_digest": f"b{i}"})
        self.assertEqual(v, "HALT")
        self.assertIn("error rate", m.halt_reason)

    def test_warn_before_halt(self):
        m = PostDispatchMonitor(window_size=10, max_error_rate=0.20, warn_error_rate=0.10)
        for i in range(8):
            m.observe({"tool": "Read", "success": True, "args_digest": f"a{i}"})
        v = m.observe({"tool": "Write", "success": False, "args_digest": "b0"})
        # 1/9 = 11% > 10% warn threshold, < 20% halt threshold.
        self.assertEqual(v, "WARN")

    def test_halt_on_oscillation(self):
        # Use a high error threshold so oscillation (not error rate) triggers.
        m = PostDispatchMonitor(window_size=20, max_retries=5, max_error_rate=0.90)
        for i in range(6):
            # Alternate success/failure on the same call: 50% error rate.
            v = m.observe({
                "tool": "Bash",
                "success": (i % 2 == 0),
                "args_digest": "same",
            })
        self.assertEqual(v, "HALT")
        self.assertIn("oscillation", m.halt_reason)

    def test_no_halt_on_consistent_failure(self):
        # Same call failing consistently is not oscillation (it's just broken,
        # not oscillating). The error-rate invariant catches it instead.
        m = PostDispatchMonitor(window_size=20, max_retries=5, max_error_rate=0.90)
        for i in range(6):
            v = m.observe({"tool": "Bash", "success": False, "args_digest": "same"})
        # 6/6 = 100% error rate > 90% threshold -> HALT via error rate, not oscillation.
        self.assertEqual(v, "HALT")
        self.assertIn("error rate", m.halt_reason)

    def test_halt_is_sticky(self):
        m = PostDispatchMonitor(window_size=10, max_error_rate=0.20)
        for i in range(10):
            m.observe({"tool": "X", "success": False, "args_digest": f"a{i}"})
        self.assertEqual(m.observe({"tool": "Read", "success": True, "args_digest": "z"}), "HALT")

    def test_reset_clears_halt(self):
        m = PostDispatchMonitor(window_size=10, max_error_rate=0.20)
        for i in range(10):
            m.observe({"tool": "X", "success": False, "args_digest": f"a{i}"})
        self.assertEqual(m.observe({"tool": "Y", "success": True, "args_digest": "z"}), "HALT")
        m.reset()
        v = m.observe({"tool": "Read", "success": True, "args_digest": "z"})
        self.assertEqual(v, "OK")
        self.assertEqual(m.halt_reason, "")


if __name__ == "__main__":
    unittest.main()
