"""Tests for phi_detector: phi accrual failure detection."""

import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import phi_detector
from phi_detector import (
    MAX_PHI,
    PHI_DETECTOR_VERSION,
    PHI_UNKNOWN_NODE,
    SCHEMA_PIN,
    PhiDetector,
    PhiReport,
    phi_audit_event,
)


def steady(det: PhiDetector, node: str, count: int = 20, step: int = 100) -> None:
    for i in range(count):
        det.heartbeat(node, i * step)


def jittered(det: PhiDetector, node: str, count: int = 40) -> None:
    """Alternating 90/110ms steps: mean 100, nonzero variance."""
    t = 0
    for i in range(count):
        det.heartbeat(node, t)
        t += 90 if i % 2 == 0 else 110


class TestPhiDetector(unittest.TestCase):
    def test_version_and_schema_pins(self) -> None:
        self.assertEqual(PHI_DETECTOR_VERSION, "phi-accrual-detector.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.phi-accrual-detector.v1")

    def test_steady_heartbeat_low_phi(self) -> None:
        det = PhiDetector()
        steady(det, "n1")
        self.assertLess(det.phi("n1", 1950), 1.0)

    def test_silence_accrues_phi(self) -> None:
        det = PhiDetector()
        jittered(det, "n1")
        # last heartbeat lands at t=3890 (39 intervals, mean ~99.7).
        p1 = det.phi("n1", 4_000)  # silence 110: just past the mean
        p2 = det.phi("n1", 4_030)  # silence 140: well past the mean
        self.assertLess(p1, p2)
        self.assertGreater(p2, 1.0)

    def test_unknown_node_maximal_phi(self) -> None:
        det = PhiDetector()
        self.assertEqual(det.phi("ghost", 1_000), PHI_UNKNOWN_NODE)
        self.assertTrue(det.is_suspected("ghost", 1_000))

    def test_first_heartbeat_no_suspicion(self) -> None:
        det = PhiDetector()
        det.heartbeat("n1", 500)
        self.assertEqual(det.phi("n1", 500), 0.0)
        self.assertEqual(det.phi("n1", 1_000_000), 0.0)

    def test_is_suspected_threshold_boundary(self) -> None:
        det = PhiDetector()
        steady(det, "n1")
        # phi grows smoothly; a threshold of 0 suspects anything at/after
        # the last heartbeat, a huge one suspects nothing real.
        self.assertTrue(det.is_suspected("n1", 10_000, threshold=1.0))
        self.assertFalse(det.is_suspected("n1", 1_950, threshold=MAX_PHI))

    def test_backward_time_fail_closed(self) -> None:
        det = PhiDetector()
        steady(det, "n1")
        with self.assertRaises(TypeError):
            det.heartbeat("n1", 500)
        with self.assertRaises(TypeError):
            det.phi("n1", 500)

    def test_bad_input_fail_closed(self) -> None:
        det = PhiDetector()
        for bad in ("", 123, None):
            with self.assertRaises(TypeError):
                det.heartbeat(bad, 100)
        for bad in (True, -1, 1.5, "100"):
            with self.assertRaises((TypeError, ValueError)):
                det.heartbeat("n1", bad)
        with self.assertRaises(ValueError):
            PhiDetector(max_samples=2, min_samples=5)
        with self.assertRaises((TypeError, ValueError)):
            det.is_suspected("n1", 100, threshold=float("nan"))

    def test_nodes_first_seen_order_and_last_heartbeat(self) -> None:
        det = PhiDetector()
        det.heartbeat("b", 100)
        det.heartbeat("a", 200)
        self.assertEqual(det.nodes(), ("b", "a"))
        self.assertEqual(det.last_heartbeat("a"), 200)
        self.assertIsNone(det.last_heartbeat("ghost"))

    def test_reset_and_clear(self) -> None:
        det = PhiDetector()
        steady(det, "n1")
        det.reset("n1")
        self.assertEqual(det.nodes(), ())
        self.assertEqual(det.phi("n1", 5_000), PHI_UNKNOWN_NODE)
        steady(det, "n2")
        det.clear()
        self.assertEqual(det.nodes(), ())
        self.assertIsNone(det.last_heartbeat("n2"))

    def test_window_bounded(self) -> None:
        det = PhiDetector(max_samples=5)
        steady(det, "n1", count=20, step=100)
        rep = det.report("n1", 1_950)
        self.assertEqual(rep.samples, 5)
        self.assertAlmostEqual(rep.mean_interval_ms, 100.0)

    def test_zero_variance_exact_rhythm(self) -> None:
        det = PhiDetector()
        steady(det, "n1", step=100)
        rep = det.report("n1", 1_950)
        self.assertAlmostEqual(rep.stddev_interval_ms, 0.0)
        self.assertEqual(rep.phi, 0.0)  # silence not yet past the mean
        self.assertEqual(det.phi("n1", 2_050), MAX_PHI)  # overshoot: maximal

    def test_report_shape_and_frozen(self) -> None:
        det = PhiDetector()
        steady(det, "n1")
        rep = det.report("n1", 2_500)
        self.assertIsInstance(rep, PhiReport)
        d = rep.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["node_id"], "n1")
        self.assertEqual(d["silence_ms"], 2_500 - 1_900)
        with self.assertRaises(AttributeError):
            rep.phi = 0.0  # frozen

    def test_audit_event_shape(self) -> None:
        det = PhiDetector()
        steady(det, "n1")
        rep = det.report("n1", 2_500)
        ev = phi_audit_event(rep, 7, True)
        self.assertEqual(ev["audit_seq"], 7)
        self.assertTrue(ev["suspected"])
        self.assertIn("phi", ev)
        with self.assertRaises(TypeError):
            phi_audit_event(rep, 7, "yes")
        with self.assertRaises(TypeError):
            phi_audit_event("nope", 7, True)

    def test_phi_monotonic_in_silence(self) -> None:
        det = PhiDetector()
        steady(det, "n1", count=30, step=100)
        phis = [det.phi("n1", 3_000 + k * 500) for k in range(6)]
        for a, b in zip(phis, phis[1:]):
            self.assertLessEqual(a, b)
        self.assertTrue(all(p >= 0.0 for p in phis))

    def test_main_self_check(self) -> None:
        # main() asserts internally; it must not raise.
        phi_detector.main()


if __name__ == "__main__":
    unittest.main()
