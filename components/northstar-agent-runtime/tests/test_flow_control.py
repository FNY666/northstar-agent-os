"""Tests for flow_control.py (15 tests, unittest, stdlib-only)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from flow_control import (  # noqa: E402
    FLOW_CONTROL_VERSION,
    SCHEMA_PIN,
    AckDecision,
    FlowControl,
    SendDecision,
    WindowSnapshot,
)


def make(window_bytes: int = 100) -> FlowControl:
    return FlowControl(window_bytes=window_bytes)


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self) -> None:
        self.assertEqual(FLOW_CONTROL_VERSION, "flow-control.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.flow-control.v1")


class TestConstructor(unittest.TestCase):
    def test_initial_window_size(self) -> None:
        fc = make(100)
        self.assertEqual(fc.window_size(), 100)
        self.assertEqual(fc.window_bytes, 100)

    def test_window_rejected_when_bad(self) -> None:
        with self.assertRaises(ValueError):
            FlowControl(window_bytes=0)
        with self.assertRaises(TypeError):
            FlowControl(window_bytes=1.5)  # type: ignore[arg-type]


class TestSend(unittest.TestCase):
    def test_send_accepted_when_fits(self) -> None:
        fc = make(100)
        d = fc.send(40)
        self.assertIsInstance(d, SendDecision)
        self.assertTrue(d.accepted)
        self.assertEqual(d.seq_no, 0)
        self.assertEqual(d.window_after, 60)
        self.assertEqual(d.schema, SCHEMA_PIN)
        self.assertEqual(fc.window_size(), 60)

    def test_send_rejected_when_over_window(self) -> None:
        fc = make(100)
        fc.send(80)
        d = fc.send(21)
        self.assertFalse(d.accepted)
        self.assertEqual(d.seq_no, 0)
        self.assertEqual(fc.window_size(), 20)  # state untouched

    def test_send_exactly_filling_window(self) -> None:
        fc = make(100)
        self.assertTrue(fc.send(100).accepted)
        self.assertEqual(fc.window_size(), 0)
        self.assertFalse(fc.send(1).accepted)

    def test_send_type_validation(self) -> None:
        fc = make(100)
        with self.assertRaises(TypeError):
            fc.send("10")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            fc.send(True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            fc.send(0)
        with self.assertRaises(ValueError):
            fc.send(-5)


class TestAck(unittest.TestCase):
    def test_ack_frees_window_cumulatively(self) -> None:
        fc = make(100)
        fc.send(30)  # seq 0..29
        fc.send(30)  # seq 30..59
        a = fc.ack(59)
        self.assertIsInstance(a, AckDecision)
        self.assertTrue(a.accepted)
        self.assertEqual(a.bytes_acked, 60)
        self.assertEqual(a.schema, SCHEMA_PIN)
        self.assertEqual(fc.window_size(), 100)

    def test_ack_prefix_only(self) -> None:
        fc = make(100)
        fc.send(30)  # seq 0..29
        fc.send(30)  # seq 30..59
        a = fc.ack(29)
        self.assertTrue(a.accepted)
        self.assertEqual(a.bytes_acked, 30)
        self.assertEqual(fc.window_size(), 70)

    def test_duplicate_ack_rejected_and_counted(self) -> None:
        fc = make(100)
        fc.send(30)
        self.assertTrue(fc.ack(29).accepted)
        dup = fc.ack(29)
        self.assertFalse(dup.accepted)
        self.assertEqual(dup.bytes_acked, 0)
        self.assertEqual(fc.duplicate_acks, 1)

    def test_ack_beyond_next_seq_rejected(self) -> None:
        fc = make(100)
        fc.send(30)
        bad = fc.ack(10_000)
        self.assertFalse(bad.accepted)
        self.assertEqual(bad.bytes_acked, 0)
        self.assertEqual(fc.window_size(), 70)

    def test_ack_input_validation(self) -> None:
        fc = make(100)
        a = fc.ack(-1)  # nothing sent: frees nothing, counts as duplicate
        self.assertFalse(a.accepted)
        self.assertEqual(fc.duplicate_acks, 1)
        with self.assertRaises(TypeError):
            fc.ack("x")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            fc.ack(-2)


class TestWindow(unittest.TestCase):
    def test_send_after_ack_unblocks_window(self) -> None:
        fc = make(100)
        fc.send(90)
        self.assertFalse(fc.send(11).accepted)
        fc.ack(89)
        self.assertEqual(fc.window_size(), 100)
        d = fc.send(11)
        self.assertTrue(d.accepted)
        self.assertEqual(d.seq_no, 90)  # sequence numbers keep advancing

    def test_snapshot_is_frozen_and_consistent(self) -> None:
        fc = make(100)
        fc.send(30)
        fc.send(20)
        fc.ack(29)
        snap = fc.snapshot()
        self.assertIsInstance(snap, WindowSnapshot)
        self.assertEqual(snap.window_bytes, 100)
        self.assertEqual(snap.in_flight_bytes, 20)
        self.assertEqual(snap.available, 80)
        self.assertEqual(snap.next_seq, 50)
        self.assertEqual(snap.segments_in_flight, 1)
        self.assertEqual(snap.duplicate_acks, 0)
        self.assertEqual(snap.schema, SCHEMA_PIN)
        with self.assertRaises(Exception):
            snap.available = 0  # type: ignore[misc]


class TestResize(unittest.TestCase):
    def test_resize_window(self) -> None:
        fc = make(100)
        fc.send(90)
        self.assertEqual(fc.resize(200), 110)
        self.assertEqual(fc.window_size(), 110)
        self.assertEqual(fc.window_bytes, 200)
        with self.assertRaises(ValueError):
            fc.resize(0)


if __name__ == "__main__":
    unittest.main()
