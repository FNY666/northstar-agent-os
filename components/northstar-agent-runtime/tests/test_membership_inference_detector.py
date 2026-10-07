"""Tests for membership_inference_detector."""
import hashlib
import unittest

from membership_inference_detector import (
    MIA_DETECTOR_VERSION,
    SCHEMA_PIN,
    MIASignal,
    MIAFinding,
    MIAReport,
    QueryRecord,
    ResponseRecord,
    analyze_probes,
    detect_mia,
    mia_audit_event,
    scan_mia,
)


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def make_queries(n, distinct=1, start=0):
    return [
        QueryRecord(f"q{start + i}", start + i, digest(f"input-{(start + i) % distinct}"))
        for i in range(n)
    ]


def make_responses(n, start=0, confidence=None, loss=None):
    return [
        ResponseRecord(f"q{start + i}", start + i, confidence=confidence, loss=loss)
        for i in range(n)
    ]


class VersionPinTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(MIA_DETECTOR_VERSION, "membership-inference-detector.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.membership-inference-detector.v1")


class QueryRecordTest(unittest.TestCase):
    def test_valid(self):
        q = QueryRecord("q1", 0, digest("x"))
        self.assertEqual(q.query_id, "q1")

    def test_frozen(self):
        q = QueryRecord("q1", 0, digest("x"))
        with self.assertRaises(Exception):
            q.query_id = "q2"  # noqa: B018

    def test_bad_query_id(self):
        with self.assertRaises(TypeError):
            QueryRecord("", 0, digest("x"))
        with self.assertRaises(TypeError):
            QueryRecord(123, 0, digest("x"))

    def test_bad_seq(self):
        with self.assertRaises(TypeError):
            QueryRecord("q1", -1, digest("x"))
        with self.assertRaises(TypeError):
            QueryRecord("q1", True, digest("x"))

    def test_bad_digest(self):
        with self.assertRaises(TypeError):
            QueryRecord("q1", 0, "not-a-digest")
        with self.assertRaises(TypeError):
            QueryRecord("q1", 0, "A" * 64)  # uppercase rejected


class ResponseRecordTest(unittest.TestCase):
    def test_valid_optional(self):
        r = ResponseRecord("q1", 0)
        self.assertIsNone(r.confidence)
        self.assertIsNone(r.loss)

    def test_confidence_bounds(self):
        with self.assertRaises(TypeError):
            ResponseRecord("q1", 0, confidence=1.5)
        with self.assertRaises(TypeError):
            ResponseRecord("q1", 0, confidence=True)
        with self.assertRaises(TypeError):
            ResponseRecord("q1", 0, loss=-0.1)

    def test_frozen(self):
        r = ResponseRecord("q1", 0, confidence=0.5)
        with self.assertRaises(Exception):
            r.confidence = 0.9  # noqa: B018


class RepeatSignalTest(unittest.TestCase):
    def test_ten_repeats_trips(self):
        qs = make_queries(10, distinct=1)
        findings = scan_mia(qs)
        self.assertTrue(any(f.signal == MIASignal.REPEATED_QUERIES for f in findings))

    def test_nine_repeats_quiet(self):
        qs = make_queries(9, distinct=1)
        findings = scan_mia(qs)
        self.assertFalse(any(f.signal == MIASignal.REPEATED_QUERIES for f in findings))

    def test_ratio_branch(self):
        # 12 queries, 4 distinct -> ratio 1-4/12 = 0.67 >= 0.6
        qs = make_queries(12, distinct=4)
        findings = scan_mia(qs)
        self.assertTrue(any(f.signal == MIASignal.REPEATED_QUERIES for f in findings))

    def test_low_ratio_quiet(self):
        qs = make_queries(12, distinct=12)
        findings = scan_mia(qs)
        self.assertFalse(any(f.signal == MIASignal.REPEATED_QUERIES for f in findings))


class InstrumentedSignalTest(unittest.TestCase):
    def test_confidence_harvest_trips(self):
        qs = make_queries(10, distinct=10)
        rs = make_responses(10, confidence=0.99)
        findings = scan_mia(qs, rs)
        self.assertTrue(any(f.signal == MIASignal.CONFIDENCE_PROBING for f in findings))

    def test_loss_only_counts(self):
        qs = make_queries(10, distinct=10)
        rs = make_responses(10, loss=0.01)
        findings = scan_mia(qs, rs)
        self.assertTrue(any(f.signal == MIASignal.CONFIDENCE_PROBING for f in findings))

    def test_partial_instrumentation_quiet(self):
        qs = make_queries(10, distinct=10)
        rs = make_responses(5, confidence=0.9)  # 5/10 = 0.5 < 0.8
        findings = scan_mia(qs, rs)
        self.assertFalse(any(f.signal == MIASignal.CONFIDENCE_PROBING for f in findings))

    def test_small_batch_quiet(self):
        qs = make_queries(5, distinct=5)
        rs = make_responses(5, confidence=0.99)
        findings = scan_mia(qs, rs)
        self.assertFalse(any(f.signal == MIASignal.CONFIDENCE_PROBING for f in findings))


class ShadowSignalTest(unittest.TestCase):
    def test_shadow_batch_trips(self):
        qs = make_queries(60, distinct=40)
        findings = scan_mia(qs)
        self.assertTrue(any(f.signal == MIASignal.SHADOW_BATCH for f in findings))

    def test_below_threshold_quiet(self):
        qs = make_queries(60, distinct=20)  # distinct < 30
        findings = scan_mia(qs)
        self.assertFalse(any(f.signal == MIASignal.SHADOW_BATCH for f in findings))


class DetectTest(unittest.TestCase):
    def test_empty_clean(self):
        self.assertFalse(detect_mia([], []))
        self.assertEqual(scan_mia([]), ())

    def test_single_signal_below_default_threshold(self):
        # Only the repeat signal (10 repeats, no instrumentation) -> 0.4 < 0.7
        qs = make_queries(10, distinct=1)
        self.assertFalse(detect_mia(qs, ()))

    def test_two_signals_trip_default(self):
        qs = make_queries(12, distinct=1)
        rs = make_responses(12, confidence=0.99)
        self.assertTrue(detect_mia(qs, rs))

    def test_custom_threshold(self):
        qs = make_queries(10, distinct=1)
        self.assertTrue(detect_mia(qs, (), threshold=0.3))

    def test_bad_threshold(self):
        with self.assertRaises(TypeError):
            detect_mia([], [], threshold=1.5)
        with self.assertRaises(TypeError):
            detect_mia([], [], threshold=True)

    def test_mapping_input(self):
        d = digest("m")
        qs = [{"query_id": "q0", "seq": 0, "input_digest": d}] * 10
        rs = [{"query_id": "q0", "seq": 0, "confidence": 0.9}] * 10
        self.assertTrue(any(
            f.signal == MIASignal.REPEATED_QUERIES for f in scan_mia(qs, rs)
        ))

    def test_malformed_raises(self):
        with self.assertRaises(TypeError):
            scan_mia([{"query_id": "q0"}])  # missing keys
        with self.assertRaises(TypeError):
            scan_mia(["not-a-record"])


class ReportShapeTest(unittest.TestCase):
    def test_report_fields(self):
        qs = make_queries(12, distinct=3)
        report = analyze_probes(qs)
        self.assertIsInstance(report, MIAReport)
        self.assertEqual(report.query_count, 12)
        self.assertEqual(report.distinct_inputs, 3)
        self.assertEqual(report.max_repeat, 4)
        d = report.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["version"], MIA_DETECTOR_VERSION)

    def test_finding_shape(self):
        qs = make_queries(10, distinct=1)
        (finding,) = [f for f in scan_mia(qs) if f.signal == MIASignal.REPEATED_QUERIES]
        self.assertIsInstance(finding, MIAFinding)
        d = finding.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["signal"], "repeated-queries")

    def test_signal_order(self):
        # All three signals trip; order must be REPEATED, CONFIDENCE, SHADOW.
        # 12 repeats of one digest + 48 distinct singles = 60 queries, 49 distinct.
        qs = (
            [QueryRecord(f"r{i}", i, digest("hot-target")) for i in range(12)]
            + [
                QueryRecord(f"s{i}", 12 + i, digest(f"calib-{i}"))
                for i in range(48)
            ]
        )
        rs = [
            ResponseRecord(q.query_id, q.seq, confidence=0.9) for q in qs
        ]
        signals = [f.signal for f in scan_mia(qs, rs)]
        self.assertEqual(
            signals,
            [MIASignal.REPEATED_QUERIES, MIASignal.CONFIDENCE_PROBING, MIASignal.SHADOW_BATCH],
        )

    def test_audit_event(self):
        report = analyze_probes(make_queries(3, distinct=3))
        event = mia_audit_event(report, 7)
        self.assertEqual(event["schema"], "audit.ndjson/1")
        self.assertEqual(event["event"], "mia-scan")
        self.assertEqual(event["seq"], 7)
        with self.assertRaises(TypeError):
            mia_audit_event(report, -1)


class MainTest(unittest.TestCase):
    def test_main(self):
        import membership_inference_detector as m

        m.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
