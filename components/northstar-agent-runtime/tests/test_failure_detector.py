"""Tests for the phi-accrual failure_detector module."""

import ast
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from failure_detector import (
    DEFAULT_MIN_SAMPLES,
    DEFAULT_THRESHOLD,
    DEFAULT_WINDOW_SIZE,
    EVENT_HEARTBEAT,
    EVENT_REJECTED,
    EVENT_SUSPECT,
    FAILURE_DETECTOR_SCHEMA,
    FAILURE_DETECTOR_VERSION,
    MAX_PHI,
    AuditKindError,
    BadNodeError,
    BadThresholdError,
    BadWindowError,
    FailureDetector,
    FailureDetectorError,
    HeartbeatRecord,
    SeqOrderError,
    SuspicionRecord,
    UnknownNodeError,
    failure_detector_audit_event,
    main,
)

_STDLIB_ALLOW = {
    "hashlib",
    "json",
    "math",
    "threading",
    "dataclasses",
    "typing",
    "collections",
    "__future__",
}


def _steady(det, node="n1", start=1, count=10, step=10):
    for i in range(count):
        det.heartbeat(node, start + i * step)


class TestPins(unittest.TestCase):
    def test_version_schema_and_kind_pins(self):
        self.assertEqual(FAILURE_DETECTOR_VERSION, "failure-detector.v1")
        self.assertEqual(FAILURE_DETECTOR_SCHEMA, "northstar.failure-detector.v1")
        self.assertEqual(
            (EVENT_HEARTBEAT, EVENT_SUSPECT, EVENT_REJECTED),
            ("heartbeat", "suspect", "rejected"),
        )
        self.assertEqual(DEFAULT_THRESHOLD, 8.0)
        self.assertEqual((DEFAULT_WINDOW_SIZE, DEFAULT_MIN_SAMPLES), (1000, 2))
        self.assertEqual(MAX_PHI, 30.0)

    def test_stdlib_only(self):
        src = Path(__file__).resolve().parent.parent / "failure_detector.py"
        tree = ast.parse(src.read_text())
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                mods.add((node.module or "").split(".")[0])
        self.assertLessEqual(mods - _STDLIB_ALLOW, set(), f"non-stdlib: {mods}")


class TestHeartbeat(unittest.TestCase):
    def test_heartbeat_roundtrip_and_inter_arrival(self):
        fd = FailureDetector()
        first = fd.heartbeat("n1", 1)
        self.assertIsInstance(first, HeartbeatRecord)
        self.assertIsNone(first.inter_arrival)
        second = fd.heartbeat("n1", 11)
        self.assertEqual(second.inter_arrival, 10)
        self.assertTrue(first.verify())
        self.assertTrue(second.verify())

    def test_heartbeat_auto_registers_unknown_node(self):
        fd = FailureDetector()
        fd.heartbeat("late-joiner", 5)
        self.assertEqual(fd.nodes(), ("late-joiner",))
        self.assertEqual(fd.last_arrival("late-joiner"), 5)

    def test_heartbeat_bad_node_id_fails_closed_and_consumes_seq(self):
        fd = FailureDetector()
        for i, bad in enumerate(("", 123, None, True), start=1):
            with self.assertRaises((BadNodeError, TypeError)):
                fd.heartbeat(bad, i)
        # first failed mutation consumed seq 1: replaying seq 1 is refused
        with self.assertRaises(SeqOrderError):
            fd.heartbeat("n1", 1)
        fd.heartbeat("n1", 5)
        self.assertEqual(fd.stats(5)["ledger_seq"], 5)


class TestPhi(unittest.TestCase):
    def test_phi_zero_without_enough_samples(self):
        fd = FailureDetector()
        fd.heartbeat("n1", 1)  # no inter-arrival samples yet
        self.assertEqual(fd.phi("n1", 10), 0.0)
        self.assertEqual(fd.phi("n1", 1_000_000), 0.0)

    def test_phi_grows_with_staleness(self):
        fd = FailureDetector()
        _steady(fd)
        fresh = fd.phi("n1", 91)  # one step after last arrival at seq 91
        stale = fd.phi("n1", 10_000)
        self.assertEqual(fresh, 0.0)  # exactly at the mean cadence
        self.assertGreater(stale, fresh)
        self.assertGreaterEqual(stale, DEFAULT_THRESHOLD)

    def test_phi_unknown_node_fails_closed(self):
        fd = FailureDetector()
        with self.assertRaises(UnknownNodeError):
            fd.phi("ghost", 5)
        with self.assertRaises(UnknownNodeError):
            fd.suspect("ghost", 5)
        self.assertRaises(UnknownNodeError, fd.last_arrival, "ghost")


class TestSuspect(unittest.TestCase):
    def test_suspect_verdict_is_data_not_raised(self):
        fd = FailureDetector()
        _steady(fd)
        fresh = fd.suspect("n1", 92)
        self.assertIsInstance(fresh, SuspicionRecord)
        self.assertFalse(fresh.suspected)
        self.assertTrue(fresh.verify())
        stale = fd.suspect("n1", 100_000)
        self.assertTrue(stale.suspected)
        self.assertGreaterEqual(stale.phi, DEFAULT_THRESHOLD)
        self.assertTrue(stale.verify())

    def test_suspect_threshold_boundary(self):
        fd = FailureDetector(threshold=0.5)
        _steady(fd)
        verdict = fd.suspect("n1", 10_000)
        self.assertTrue(verdict.suspected)
        self.assertGreaterEqual(verdict.phi, 0.5)


class TestSeqDiscipline(unittest.TestCase):
    def test_seq_must_strictly_increase(self):
        fd = FailureDetector()
        fd.heartbeat("n1", 1)
        for bad in (1, 0, -1, True, 1.5, "2"):
            with self.assertRaises((SeqOrderError, TypeError, ValueError)):
                fd.heartbeat("n1", bad)
        fd.heartbeat("n1", 2)  # rewind did not consume

    def test_pure_read_views_do_not_consume_seq(self):
        fd = FailureDetector()
        _steady(fd)
        before = fd.stats(100)["ledger_seq"]
        fd.phi("n1", 100)
        fd.stats(100)
        self.assertEqual(fd.sample_count("n1"), 9)
        self.assertEqual(fd.stats(100)["ledger_seq"], before)


class TestWindowAndEdges(unittest.TestCase):
    def test_window_slides_and_counts(self):
        fd = FailureDetector(window_size=3)
        _steady(fd, count=10)
        self.assertEqual(fd.sample_count("n1"), 3)

    def test_constant_cadence_break_is_definitive(self):
        fd = FailureDetector()
        _steady(fd, step=10)
        # zero variance: exactly on cadence -> 0.0, any break -> MAX_PHI
        self.assertEqual(fd.phi("n1", 101), 0.0)
        self.assertEqual(fd.phi("n1", 200), MAX_PHI)

    def test_constructor_rejects_bad_config(self):
        with self.assertRaises(BadThresholdError):
            FailureDetector(threshold=0)
        with self.assertRaises(BadThresholdError):
            FailureDetector(threshold=float("inf"))
        with self.assertRaises(BadWindowError):
            FailureDetector(window_size=0)
        with self.assertRaises(BadWindowError):
            FailureDetector(min_samples=True)

    def test_audit_shapes_and_bad_kind(self):
        fd = FailureDetector()
        fd.heartbeat("n1", 1)
        fd.suspect("n1", 2)
        kinds = [row["kind"] for row in fd.audit_log()]
        self.assertEqual(kinds, [EVENT_HEARTBEAT, EVENT_SUSPECT])
        for row in fd.audit_log():
            self.assertEqual(row["audit"], "audit.ndjson/1")
            self.assertEqual(row["schema"], FAILURE_DETECTOR_SCHEMA)
            self.assertEqual(row["version"], FAILURE_DETECTOR_VERSION)
            self.assertEqual(row["node_id"], "n1")
        with self.assertRaises(AuditKindError):
            failure_detector_audit_event("nope", node_id="n1", seq=3)

    def test_main_self_check(self):
        proc = subprocess.run(
            [sys.executable, "-c", "from failure_detector import main; main()"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("failure-detector OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
