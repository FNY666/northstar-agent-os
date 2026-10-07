"""Targeted tests for congestion_control.py."""

import unittest

from congestion_control import (
    CONGESTION_CONTROL_VERSION,
    SCHEMA_PIN,
    AckSample,
    CongestionControl,
    LossEvent,
    Phase,
)


def _ack(t, delivered=100_000, rtt=50):
    return AckSample(now_ms=t, delivered_bytes=delivered, rtt_ms=rtt)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        cc = CongestionControl()
        self.assertEqual(cc.version, "congestion-control.v1")
        self.assertEqual(CONGESTION_CONTROL_VERSION, "congestion-control.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.congestion-control.v1")


class TestConstructor(unittest.TestCase):
    def test_rejects_bad_window(self):
        with self.assertRaises(ValueError):
            CongestionControl(bandwidth_window_ms=0)
        with self.assertRaises(TypeError):
            CongestionControl(bandwidth_window_ms=True)

    def test_rejects_bad_packet_size(self):
        with self.assertRaises(ValueError):
            CongestionControl(packet_bytes=0)

    def test_defaults(self):
        cc = CongestionControl()
        self.assertEqual(cc.bandwidth_window_ms, 10_000)
        self.assertEqual(cc.packet_bytes, 1500)
        self.assertEqual(cc.phase, Phase.STARTUP)
        self.assertIsNone(cc.min_rtt_ms)


class TestStartup(unittest.TestCase):
    def test_initial_cwnd_is_minimum_window(self):
        cc = CongestionControl()
        self.assertEqual(cc.cwnd(), 4 * 1500)

    def test_min_rtt_tracks_lowest(self):
        cc = CongestionControl()
        cc.on_ack(_ack(0, rtt=80))
        cc.on_ack(_ack(50, rtt=60))
        self.assertEqual(cc.min_rtt_ms, 60)

    def test_startup_grows_cwnd_with_delivery(self):
        cc = CongestionControl()
        cc.on_ack(_ack(0))
        w0 = cc.cwnd()
        for i in range(1, 6):
            cc.on_ack(_ack(i * 50, delivered=100_000 * (i + 1)))
        self.assertGreater(cc.cwnd(), w0)

    def test_startup_exits_on_plateau(self):
        cc = CongestionControl()
        for i in range(200):
            cc.on_ack(_ack(i * 50))
        self.assertEqual(cc.phase, Phase.PROBE_BW)

    def test_backwards_time_rejected(self):
        cc = CongestionControl()
        cc.on_ack(_ack(100))
        with self.assertRaises(TypeError):
            cc.on_ack(_ack(50))

    def test_wrong_sample_type_rejected(self):
        cc = CongestionControl()
        with self.assertRaises(TypeError):
            cc.on_ack("not-a-sample")
        with self.assertRaises(TypeError):
            cc.on_loss("not-an-event")


class TestProbeBW(unittest.TestCase):
    def test_probe_bw_gains_cycle(self):
        cc = CongestionControl()
        for i in range(200):
            cc.on_ack(_ack(i * 50))
        self.assertEqual(cc.phase, Phase.PROBE_BW)
        seen = {cc.cwnd()}
        for i in range(200, 240):
            cc.on_ack(_ack(i * 50))
            seen.add(cc.cwnd())
        self.assertGreater(len(seen), 1)

    def test_btlbw_reported_in_bytes_per_second(self):
        cc = CongestionControl()
        cc.on_ack(_ack(0, delivered=100_000, rtt=50))
        # 100000 bytes / 50 ms = 2000 B/ms = 2,000,000 B/s
        self.assertAlmostEqual(cc.btlbw_bytes_per_s, 2_000_000.0)


class TestProbeRTT(unittest.TestCase):
    def test_probe_rtt_after_ten_seconds(self):
        cc = CongestionControl()
        cc.on_ack(_ack(0))
        cc.on_ack(_ack(10_001))
        self.assertEqual(cc.phase, Phase.PROBE_RTT)
        self.assertEqual(cc.cwnd(), 4 * 1500)

    def test_probe_rtt_exits_after_deadline(self):
        cc = CongestionControl()
        cc.on_ack(_ack(0))
        cc.on_ack(_ack(10_001))
        cc.on_ack(_ack(10_201))  # deadline = 10001 + 200
        self.assertEqual(cc.phase, Phase.PROBE_BW)


class TestLoss(unittest.TestCase):
    def test_loss_caps_cwnd_at_half(self):
        cc = CongestionControl()
        for i in range(200):
            cc.on_ack(_ack(i * 50))
        before = cc.cwnd()
        cc.on_loss(LossEvent(now_ms=10_001, packets_lost=3))
        self.assertLessEqual(cc.cwnd(), max(4 * 1500, before // 2))

    def test_cwnd_never_below_floor_after_loss(self):
        cc = CongestionControl()
        cc.on_ack(_ack(0))
        cc.on_loss(LossEvent(now_ms=1, packets_lost=10))
        self.assertGreaterEqual(cc.cwnd(), 4 * 1500)

    def test_frozen_records(self):
        s = AckSample(now_ms=1, delivered_bytes=10, rtt_ms=5)
        self.assertEqual(s.schema, SCHEMA_PIN)
        self.assertEqual(s.as_dict()["rtt_ms"], 5)
        e = LossEvent(now_ms=2, packets_lost=1)
        self.assertEqual(e.as_dict()["packets_lost"], 1)


if __name__ == "__main__":
    unittest.main()
