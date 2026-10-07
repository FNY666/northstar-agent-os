"""Targeted tests for the RUM monitor interface."""

import ast
import json
import unittest
from pathlib import Path

from rum_monitor import (
    AUDIT_SCHEMA,
    KIND_ALERT_DEFINED,
    KIND_ALERT_EVALUATED,
    KIND_REJECTED,
    KIND_SESSION_ENDED,
    KIND_SESSION_STARTED,
    KIND_SUMMARY_REPORTED,
    KIND_VITAL_RECORDED,
    RUM_MONITOR_SCHEMA,
    RUM_MONITOR_VERSION,
    METRICS,
    RATINGS,
    RUMError,
    SeqOrderError,
    DuplicateSessionError,
    DuplicateAlertError,
    UnknownMetricError,
    UnknownSessionError,
    SessionStateError,
    BadValueError,
    BadAlertError,
    RUMMonitor,
    rum_monitor_audit_event,
    main,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "rum_monitor.py"


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(RUM_MONITOR_VERSION, "rum-monitor.v1")
        self.assertEqual(RUM_MONITOR_SCHEMA, "northstar.rum-monitor.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_metric_vocabulary(self):
        self.assertEqual(tuple(sorted(METRICS)),
                         ("cls", "fcp", "inp", "lcp", "ttfb"))
        self.assertEqual(tuple(sorted(RATINGS)),
                         ("good", "needs-improvement", "poor"))

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        stdlib = {
            "hashlib", "json", "math", "dataclasses", "threading", "typing",
            "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], stdlib, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], stdlib,
                              node.module)

    def test_main(self):
        main()


class TestSession(unittest.TestCase):
    def setUp(self):
        self.m = RUMMonitor()

    def test_session_roundtrip(self):
        rec = self.m.session("s-1", 1, page="/home",
                             attributes={"ua": "test"})
        self.assertEqual(rec.record_id, "ses-1")
        self.assertTrue(rec.verify())
        self.assertEqual(rec.page, "/home")
        self.assertEqual(rec.attributes, {"ua": "test"})
        self.assertEqual(self.m.session_state("s-1"), "active")
        self.assertEqual(self.m.session_ids(), ("s-1",))

    def test_session_duplicate_refused(self):
        self.m.session("s-1", 1)
        with self.assertRaises(DuplicateSessionError):
            self.m.session("s-1", 2)
        # failed mutation consumed seq 2: next must be > 2
        with self.assertRaises(SeqOrderError):
            self.m.session("s-2", 2)
        rec = self.m.session("s-2", 3)
        self.assertEqual(rec.record_id, "ses-2")

    def test_session_bad_inputs(self):
        with self.assertRaises(RUMError):
            self.m.session("", 1)
        with self.assertRaises(RUMError):
            self.m.session("s-1", True)
        with self.assertRaises(RUMError):
            self.m.session("s-1", -1)
        with self.assertRaises(RUMError):
            self.m.session("s-1", 1, attributes={"k": 2.5})
        with self.assertRaises(RUMError):
            self.m.session("s-1", 1, page="x" * 513)

    def test_end_session(self):
        self.m.session("s-1", 1)
        ended = self.m.end_session("s-1", 2)
        self.assertTrue(ended.verify())
        self.assertEqual(ended.record_id, "end-2")
        self.assertEqual(self.m.session_state("s-1"), "ended")
        # double end refused, terminal
        with self.assertRaises(SessionStateError):
            self.m.end_session("s-1", 3)
        # unknown session refused
        with self.assertRaises(UnknownSessionError):
            self.m.end_session("nope", 4)

    def test_seq_rewind_refused(self):
        self.m.session("s-1", 5)
        with self.assertRaises(SeqOrderError):
            self.m.session("s-2", 5)
        with self.assertRaises(SeqOrderError):
            self.m.session("s-2", 3)


class TestVital(unittest.TestCase):
    def setUp(self):
        self.m = RUMMonitor()
        self.m.session("s-1", 1)

    def test_vital_roundtrip_and_rating(self):
        s = self.m.vital("s-1", "lcp", 2400.0, 2, url="https://x/")
        self.assertEqual(s.record_id, "vtl-2")
        self.assertEqual(s.rating, "good")
        self.assertTrue(s.verify())

    def test_rating_boundaries(self):
        cases = [
            ("lcp", 2500.0, "good"), ("lcp", 2500.5, "needs-improvement"),
            ("lcp", 4000.0, "needs-improvement"), ("lcp", 4000.5, "poor"),
            ("inp", 200.0, "good"), ("inp", 500.0, "needs-improvement"),
            ("inp", 501.0, "poor"),
            ("cls", 0.1, "good"), ("cls", 0.25, "needs-improvement"),
            ("cls", 0.26, "poor"),
            ("fcp", 1800.0, "good"), ("fcp", 3001.0, "poor"),
            ("ttfb", 800.0, "good"), ("ttfb", 1801.0, "poor"),
        ]
        seq = 2
        for metric, value, rating in cases:
            s = self.m.vital("s-1", metric, value, seq)
            self.assertEqual(s.rating, rating, (metric, value))
            seq += 1

    def test_vital_unknown_metric(self):
        with self.assertRaises(UnknownMetricError):
            self.m.vital("s-1", "fid", 100.0, 2)

    def test_vital_bad_values(self):
        seq = 2
        for bad in (float("nan"), float("inf"), -1.0, True, "100", None):
            with self.assertRaises(BadValueError):
                self.m.vital("s-1", "lcp", bad, seq)
            seq += 1
        # caps
        with self.assertRaises(BadValueError):
            self.m.vital("s-1", "lcp", 3_600_001.0, seq)
            seq += 1
        with self.assertRaises(BadValueError):
            self.m.vital("s-1", "cls", 10.5, seq + 1)

    def test_vital_unknown_or_ended_session(self):
        with self.assertRaises(UnknownSessionError):
            self.m.vital("nope", "lcp", 100.0, 2)
        self.m.end_session("s-1", 3)
        with self.assertRaises(SessionStateError):
            self.m.vital("s-1", "lcp", 100.0, 4)

    def test_value_canonicalization(self):
        s = self.m.vital("s-1", "lcp", 2400.123456789, 2)
        self.assertEqual(s.value, 2400.123457)
        self.assertTrue(s.verify())


class TestAlert(unittest.TestCase):
    def setUp(self):
        self.m = RUMMonitor()
        self.m.session("s-1", 1)

    def test_alert_roundtrip(self):
        rule = self.m.alert("a-1", "lcp", 2, 0.5, window=10,
                            severity="critical")
        self.assertEqual(rule.record_id, "alr-2")
        self.assertTrue(rule.verify())
        self.assertEqual(self.m.get_alert("a-1").alert_id, "a-1")

    def test_alert_bad_inputs(self):
        seq = 2
        with self.assertRaises(BadAlertError):
            self.m.alert("a-1", "lcp", seq, 0.0)
        seq += 1
        with self.assertRaises(BadAlertError):
            self.m.alert("a-1", "lcp", seq, 1.5)
        seq += 1
        with self.assertRaises(BadAlertError):
            self.m.alert("a-1", "lcp", seq, 0.5, window=0)
        seq += 1
        with self.assertRaises(BadAlertError):
            self.m.alert("a-1", "lcp", seq, 0.5, severity="panic")
        seq += 1
        with self.assertRaises(UnknownMetricError):
            self.m.alert("a-1", "nope", seq, 0.5)
        seq += 1
        with self.assertRaises(RUMError):
            self.m.alert("", "lcp", seq, 0.5)

    def test_alert_duplicate(self):
        self.m.alert("a-1", "lcp", 2, 0.5)
        with self.assertRaises(DuplicateAlertError):
            self.m.alert("a-1", "inp", 3, 0.5)

    def test_evaluate_no_samples(self):
        self.m.alert("a-1", "lcp", 2, 0.5)
        ev = self.m.evaluate(3)
        v = ev.verdicts[0]
        self.assertFalse(v.triggered)
        self.assertEqual(v.poor_fraction, 0.0)
        self.assertEqual(v.window_samples, 0)
        self.assertTrue(ev.verify())

    def test_evaluate_trigger(self):
        self.m.alert("a-1", "lcp", 2, 0.5, window=4)
        seq = 3
        for value in (2400.0, 5000.0, 5000.0, 2400.0):  # 2/4 poor
            self.m.vital("s-1", "lcp", value, seq)
            seq += 1
        ev = self.m.evaluate(seq)
        v = ev.verdicts[0]
        self.assertTrue(v.triggered)
        self.assertEqual(v.poor_fraction, 0.5)
        self.assertEqual(v.window_samples, 4)
        # below threshold: not triggered
        self.m.alert("a-2", "lcp", seq + 1, 0.75, window=4)
        ev2 = self.m.evaluate(seq + 2)
        by_id = {v.alert_id: v for v in ev2.verdicts}
        self.assertFalse(by_id["a-2"].triggered)
        self.assertTrue(by_id["a-1"].triggered)

    def test_evaluate_window_respected(self):
        self.m.alert("a-1", "lcp", 2, 1.0, window=2)
        seq = 3
        for value in (5000.0, 5000.0, 2400.0, 2400.0):  # last 2 good
            self.m.vital("s-1", "lcp", value, seq)
            seq += 1
        ev = self.m.evaluate(seq)
        v = ev.verdicts[0]
        self.assertFalse(v.triggered)
        self.assertEqual(v.window_samples, 2)
        self.assertEqual(v.poor_fraction, 0.0)

    def test_evaluate_no_rules(self):
        ev = self.m.evaluate(2)
        self.assertEqual(ev.verdicts, ())
        self.assertTrue(ev.verify())


class TestSummary(unittest.TestCase):
    def test_summary_rollup(self):
        m = RUMMonitor()
        m.session("s-1", 1)
        seq = 2
        for value in (2400.0, 3000.0, 5000.0, 2400.0):  # good,ni,poor,good
            m.vital("s-1", "lcp", value, seq)
            seq += 1
        report = m.summary("lcp", seq)
        self.assertTrue(report.verify())
        self.assertEqual(report.record_id, "sum-6")
        self.assertEqual(report.counts,
                         {"good": 2, "needs-improvement": 1, "poor": 1})
        self.assertEqual(report.total, 4)
        self.assertEqual(report.poor_fraction, 0.25)
        self.assertEqual(report.median, 2700.0)

    def test_summary_empty(self):
        m = RUMMonitor()
        report = m.summary("cls", 1)
        self.assertTrue(report.verify())
        self.assertEqual(report.total, 0)
        self.assertEqual(report.poor_fraction, 0.0)
        self.assertIsNone(report.median)
        self.assertEqual(report.counts,
                         {"good": 0, "needs-improvement": 0, "poor": 0})


class TestAudit(unittest.TestCase):
    def test_audit_shapes_and_leak_ban(self):
        m = RUMMonitor()
        m.session("s-1", 1, page="/secret-page")
        m.vital("s-1", "lcp", 2400.0, 2, url="https://x/?token=abc")
        m.alert("a-1", "lcp", 3, 0.5)
        kinds = [e["kind"] for e in m.audit_log()]
        self.assertEqual(
            kinds,
            [KIND_SESSION_STARTED, KIND_VITAL_RECORDED, KIND_ALERT_DEFINED],
        )
        blob = json.dumps(m.audit_log())
        self.assertNotIn("token=abc", blob)
        self.assertNotIn("/secret-page", blob)
        for e in m.audit_log():
            self.assertEqual(e["schema"], AUDIT_SCHEMA)
            self.assertEqual(e["module"], "rum_monitor")

    def test_audit_bad_kind(self):
        with self.assertRaises(RUMError):
            rum_monitor_audit_event("nope", 1)

    def test_rejected_audited(self):
        m = RUMMonitor()
        m.session("s-1", 1)
        with self.assertRaises(DuplicateSessionError):
            m.session("s-1", 2)
        last = m.audit_log()[-1]
        self.assertEqual(last["kind"], KIND_REJECTED)
        self.assertIn("duplicate", last["detail"]["reason"])


if __name__ == "__main__":
    unittest.main()
