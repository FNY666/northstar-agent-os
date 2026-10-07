"""Tests for no_token_monitor: latent-reasoning monitoring without CoT."""
import unittest

from no_token_monitor import (
    ISSUE_KNOWN_BAD_OUTPUT,
    ISSUE_LATENCY_ANOMALY,
    ISSUE_OVERCONFIDENCE,
    MAX_CONFIDENCE,
    NO_TOKEN_MONITOR_VERSION,
    SCHEMA_PIN,
    LatencyBaseline,
    LatentTrace,
    MalformedTrace,
    MonitorFinding,
    MonitorReport,
    NoTokenMonitorError,
    TaskComplexity,
    detect_known_bad_output,
    detect_latency_anomaly,
    detect_overconfidence,
    monitor_findings,
    monitor_latent,
)


def _trace(**kw):
    base = {
        "input_hash": "a" * 64,
        "output_hash": "b" * 64,
        "latency_ms": 120.0,
        "confidence": 0.8,
    }
    base.update(kw)
    return LatentTrace(**base)


def _baseline(**kw):
    base = {"complexity": TaskComplexity.MEDIUM, "min_ms": 50.0, "max_ms": 500.0}
    base.update(kw)
    return LatencyBaseline(**base)


class VersionPinTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(NO_TOKEN_MONITOR_VERSION, "no-token-monitor.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.no-token-monitor.v1")


class LatentTraceTest(unittest.TestCase):
    def test_frozen(self):
        t = _trace()
        with self.assertRaises(Exception):
            t.confidence = 0.5  # type: ignore

    def test_bad_hash_rejected(self):
        with self.assertRaises(MalformedTrace):
            _trace(input_hash="xyz")
        with self.assertRaises(MalformedTrace):
            _trace(output_hash="A" * 64)  # uppercase not allowed

    def test_bad_latency_rejected(self):
        with self.assertRaises(MalformedTrace):
            _trace(latency_ms=-1.0)
        with self.assertRaises(MalformedTrace):
            _trace(latency_ms=True)

    def test_bad_confidence_rejected(self):
        with self.assertRaises(MalformedTrace):
            _trace(confidence=1.5)
        with self.assertRaises(MalformedTrace):
            _trace(confidence=-0.1)

    def test_digest_stable(self):
        self.assertEqual(_trace().digest(), _trace().digest())
        self.assertTrue(_trace().digest().startswith("sha256:"))

    def test_baseline_validation(self):
        with self.assertRaises(NoTokenMonitorError):
            _baseline(min_ms=600.0, max_ms=100.0)
        with self.assertRaises(NoTokenMonitorError):
            LatencyBaseline(complexity="high", min_ms=1.0, max_ms=2.0)  # type: ignore


class LatencyAnomalyTest(unittest.TestCase):
    def test_inside_envelope_clean(self):
        self.assertFalse(detect_latency_anomaly(_trace(latency_ms=120.0), _baseline()))

    def test_too_fast_flagged(self):
        self.assertTrue(detect_latency_anomaly(_trace(latency_ms=5.0), _baseline()))

    def test_too_slow_flagged(self):
        self.assertTrue(detect_latency_anomaly(_trace(latency_ms=5000.0), _baseline()))

    def test_boundary_is_clean(self):
        self.assertFalse(detect_latency_anomaly(_trace(latency_ms=50.0), _baseline()))
        self.assertFalse(detect_latency_anomaly(_trace(latency_ms=500.0), _baseline()))


class OverconfidenceTest(unittest.TestCase):
    def test_low_complexity_allows_full_confidence(self):
        self.assertFalse(detect_overconfidence(_trace(confidence=1.0), TaskComplexity.LOW))

    def test_high_complexity_flags_099(self):
        self.assertTrue(detect_overconfidence(_trace(confidence=0.99), TaskComplexity.HIGH))

    def test_at_ceiling_is_clean(self):
        self.assertFalse(
            detect_overconfidence(
                _trace(confidence=MAX_CONFIDENCE[TaskComplexity.HIGH]),
                TaskComplexity.HIGH,
            )
        )


class KnownBadOutputTest(unittest.TestCase):
    def test_blocklisted_output_flagged(self):
        t = _trace(output_hash="d" * 64)
        self.assertTrue(detect_known_bad_output(t, frozenset({"d" * 64})))

    def test_clean_output_not_flagged(self):
        t = _trace(output_hash="b" * 64)
        self.assertFalse(detect_known_bad_output(t, frozenset({"d" * 64})))


class MonitorLatentTest(unittest.TestCase):
    def test_clean_trace(self):
        r = monitor_latent(_trace(), baseline=_baseline())
        self.assertEqual(r.verdict, "clean")
        self.assertEqual(r.issues, ())
        self.assertEqual(r.schema, SCHEMA_PIN)

    def test_no_baseline_skips_latency(self):
        # Absurd latency but no baseline: latency check skipped, still clean.
        r = monitor_latent(_trace(latency_ms=999999.0, confidence=0.5))
        self.assertEqual(r.verdict, "clean")

    def test_fixed_issue_order(self):
        t = _trace(latency_ms=5.0, confidence=0.99, output_hash="d" * 64)
        r = monitor_latent(
            t,
            baseline=_baseline(),
            complexity=TaskComplexity.HIGH,
            known_bad_outputs=frozenset({"d" * 64}),
        )
        self.assertEqual(
            r.issues,
            (ISSUE_LATENCY_ANOMALY, ISSUE_OVERCONFIDENCE, ISSUE_KNOWN_BAD_OUTPUT),
        )

    def test_mapping_input_accepted(self):
        r = monitor_latent(
            {
                "input_hash": "a" * 64,
                "output_hash": "b" * 64,
                "latency_ms": 120.0,
                "confidence": 0.8,
            },
            baseline=_baseline(),
        )
        self.assertEqual(r.verdict, "clean")

    def test_unparseable_trace_flagged_all(self):
        r = monitor_latent({"garbage": True}, baseline=_baseline())
        self.assertEqual(r.verdict, "flagged")
        self.assertEqual(len(r.issues), 3)

    def test_non_mapping_non_trace_flagged(self):
        r = monitor_latent("not a trace")  # type: ignore
        self.assertEqual(r.verdict, "flagged")

    def test_report_invariants(self):
        with self.assertRaises(NoTokenMonitorError):
            MonitorReport(verdict="clean", issues=("x",), trace_digest="d")
        with self.assertRaises(NoTokenMonitorError):
            MonitorReport(verdict="flagged", issues=(), trace_digest="d")
        with self.assertRaises(NoTokenMonitorError):
            MonitorReport(verdict="maybe", issues=(), trace_digest="d")


class MonitorFindingsTest(unittest.TestCase):
    def test_findings_carry_detail(self):
        t = _trace(latency_ms=5.0, confidence=0.99)
        findings = monitor_findings(
            t, baseline=_baseline(), complexity=TaskComplexity.HIGH
        )
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(isinstance(f, MonitorFinding) for f in findings))
        self.assertTrue(all(f.detail for f in findings))

    def test_clean_trace_no_findings(self):
        self.assertEqual(monitor_findings(_trace(), baseline=_baseline()), ())


class MainTest(unittest.TestCase):
    def test_main_runs(self):
        import no_token_monitor

        no_token_monitor.main()


if __name__ == "__main__":
    unittest.main()
