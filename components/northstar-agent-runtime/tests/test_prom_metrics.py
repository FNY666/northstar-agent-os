"""Tests for prom_metrics.py — Prometheus counter/gauge/histogram bookkeeping."""

import unittest

import prom_metrics
from prom_metrics import (
    PROM_METRICS_VERSION,
    SCHEMA_PIN,
    AuditError,
    BucketOrderError,
    CounterDecreaseError,
    InvalidNameError,
    LabelMismatchError,
    MetricTypeConflictError,
    PromMetrics,
    PromMetricsError,
    UnknownMetricError,
    prom_metrics_audit_event,
)


class VersionPinTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(PROM_METRICS_VERSION, "prom-metrics.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.prom-metrics.v1")


class RegisterTests(unittest.TestCase):
    def setUp(self):
        self.pm = PromMetrics()

    def test_register_counter(self):
        ident = self.pm.register("requests_total", "counter", 0)
        self.assertEqual(ident.metric, "requests_total")
        self.assertTrue(ident.digest.startswith("sha256:"))

    def test_register_gauge(self):
        ident = self.pm.register("queue_depth", "gauge", 0, help_text="depth")
        self.assertEqual(ident.metric, "queue_depth")

    def test_register_histogram(self):
        ident = self.pm.register("latency", "histogram", 0, buckets=(0.1, 1.0))
        self.assertEqual(ident.metric, "latency")

    def test_histogram_requires_buckets(self):
        with self.assertRaises(PromMetricsError):
            self.pm.register("latency", "histogram", 0)

    def test_buckets_must_increase(self):
        with self.assertRaises(BucketOrderError):
            self.pm.register("latency", "histogram", 0, buckets=(1.0, 0.5))

    def test_duplicate_bucket_bounds(self):
        with self.assertRaises(BucketOrderError):
            self.pm.register("latency", "histogram", 0, buckets=(0.5, 0.5))

    def test_duplicate_registration_same_type_refused(self):
        self.pm.register("requests_total", "counter", 0)
        with self.assertRaises(PromMetricsError):
            self.pm.register("requests_total", "counter", 1)

    def test_type_conflict_refused(self):
        self.pm.register("requests_total", "counter", 0)
        with self.assertRaises(MetricTypeConflictError):
            self.pm.register("requests_total", "gauge", 1)

    def test_bad_metric_name(self):
        with self.assertRaises(InvalidNameError):
            self.pm.register("9bad-name", "counter", 0)

    def test_reserved_label_name(self):
        with self.assertRaises(InvalidNameError):
            self.pm.register("m", "counter", 0, label_names=("__name__",))

    def test_histogram_le_label_refused(self):
        with self.assertRaises(InvalidNameError):
            self.pm.register("m", "histogram", 0, label_names=("le",), buckets=(1.0,))

    def test_buckets_on_non_histogram_refused(self):
        with self.assertRaises(PromMetricsError):
            self.pm.register("m", "counter", 0, buckets=(1.0,))

    def test_metrics_view(self):
        self.pm.register("b", "gauge", 0)
        self.pm.register("a", "counter", 1)
        self.assertEqual(self.pm.metrics(), ("a", "b"))


class CounterTests(unittest.TestCase):
    def setUp(self):
        self.pm = PromMetrics()
        self.pm.register("requests_total", "counter", 0, label_names=("method",))

    def test_counter_inc(self):
        sample = self.pm.counter_inc("requests_total", {"method": "get"}, 3, 1)
        self.assertEqual(sample.new_value, 3)
        self.assertTrue(sample.digest.startswith("sha256:"))

    def test_counter_accumulates(self):
        self.pm.counter_inc("requests_total", {"method": "get"}, 3, 1)
        sample = self.pm.counter_inc("requests_total", {"method": "get"}, 2, 2)
        self.assertEqual(sample.new_value, 5)

    def test_counter_decrease_refused(self):
        self.pm.counter_inc("requests_total", {"method": "get"}, 3, 1)
        with self.assertRaises(CounterDecreaseError):
            self.pm.counter_inc("requests_total", {"method": "get"}, -1, 2)
        # pinned value unchanged
        self.assertEqual(self.pm.sample("requests_total", {"method": "get"}), 3)

    def test_counter_zero_inc_ok(self):
        sample = self.pm.counter_inc("requests_total", {"method": "get"}, 0, 1)
        self.assertEqual(sample.new_value, 0)

    def test_counter_nan_refused(self):
        with self.assertRaises(PromMetricsError):
            self.pm.counter_inc("requests_total", {"method": "get"}, float("nan"), 1)

    def test_counter_unknown_metric(self):
        with self.assertRaises(UnknownMetricError):
            self.pm.counter_inc("nope", {}, 1, 1)

    def test_counter_wrong_type(self):
        self.pm.register("g", "gauge", 0)
        with self.assertRaises(MetricTypeConflictError):
            self.pm.counter_inc("g", {}, 1, 1)

    def test_label_mismatch(self):
        with self.assertRaises(LabelMismatchError):
            self.pm.counter_inc("requests_total", {"other": "x"}, 1, 1)

    def test_series_are_independent(self):
        self.pm.counter_inc("requests_total", {"method": "get"}, 3, 1)
        self.pm.counter_inc("requests_total", {"method": "post"}, 10, 2)
        self.assertEqual(self.pm.sample("requests_total", {"method": "get"}), 3)
        self.assertEqual(self.pm.sample("requests_total", {"method": "post"}), 10)

    def test_sample_absent_series(self):
        self.assertIsNone(self.pm.sample("requests_total", {"method": "get"}))

    def test_bool_amount_refused(self):
        with self.assertRaises(PromMetricsError):
            self.pm.counter_inc("requests_total", {"method": "get"}, True, 1)


class GaugeTests(unittest.TestCase):
    def setUp(self):
        self.pm = PromMetrics()
        self.pm.register("queue_depth", "gauge", 0)

    def test_gauge_set(self):
        sample = self.pm.gauge_set("queue_depth", {}, 7, 1)
        self.assertEqual(sample.value, 7)
        self.assertEqual(sample.op, "set")

    def test_gauge_inc_dec(self):
        self.pm.gauge_set("queue_depth", {}, 7, 1)
        inc = self.pm.gauge_inc("queue_depth", {}, 3, 2)
        self.assertEqual(inc.value, 10)
        dec = self.pm.gauge_dec("queue_depth", {}, 4, 3)
        self.assertEqual(dec.value, 6)

    def test_gauge_can_go_negative(self):
        sample = self.pm.gauge_dec("queue_depth", {}, 5, 1)
        self.assertEqual(sample.value, -5)

    def test_gauge_inc_negative_amount(self):
        sample = self.pm.gauge_inc("queue_depth", {}, -2, 1)
        self.assertEqual(sample.value, -2)

    def test_gauge_inf_refused(self):
        with self.assertRaises(PromMetricsError):
            self.pm.gauge_set("queue_depth", {}, float("inf"), 1)

    def test_gauge_frozen_record(self):
        sample = self.pm.gauge_set("queue_depth", {}, 7, 1)
        with self.assertRaises(Exception):
            sample.value = 9  # type: ignore[misc]

    def test_gauge_as_dict(self):
        sample = self.pm.gauge_set("queue_depth", {}, 7, 1)
        d = sample.as_dict()
        self.assertEqual(d["version"], PROM_METRICS_VERSION)
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["op"], "set")


class HistogramTests(unittest.TestCase):
    def setUp(self):
        self.pm = PromMetrics()
        self.pm.register("latency", "histogram", 0, buckets=(0.1, 0.5, 1.0))

    def test_observe(self):
        obs = self.pm.histogram_observe("latency", {}, 0.2, 1)
        self.assertEqual(obs.count, 1)
        self.assertAlmostEqual(obs.total, 0.2)
        self.assertEqual(obs.bucket_counts, (0, 1, 1))  # cumulative

    def test_cumulative_buckets(self):
        self.pm.histogram_observe("latency", {}, 0.05, 1)
        self.pm.histogram_observe("latency", {}, 2.0, 2)
        state = self.pm.sample("latency", {})
        self.assertEqual(state["buckets"], [1, 1, 1])
        self.assertEqual(state["count"], 2)
        self.assertAlmostEqual(state["total"], 2.05)

    def test_value_above_all_buckets(self):
        obs = self.pm.histogram_observe("latency", {}, 99.0, 1)
        self.assertEqual(obs.bucket_counts, (0, 0, 0))
        self.assertEqual(obs.count, 1)

    def test_exact_bound_included(self):
        obs = self.pm.histogram_observe("latency", {}, 0.5, 1)
        self.assertEqual(obs.bucket_counts, (0, 1, 1))

    def test_unknown_histogram(self):
        with self.assertRaises(UnknownMetricError):
            self.pm.histogram_observe("nope", {}, 1.0, 1)


class ScrapeTests(unittest.TestCase):
    def setUp(self):
        self.pm = PromMetrics()
        self.pm.register("requests_total", "counter", 0, label_names=("method",),
                         help_text="total requests")
        self.pm.register("queue_depth", "gauge", 1, help_text="depth")
        self.pm.register("latency", "histogram", 2, buckets=(0.1, 1.0), help_text="lat")
        self.pm.counter_inc("requests_total", {"method": "get"}, 3, 3)
        self.pm.gauge_set("queue_depth", {}, 7, 4)
        self.pm.histogram_observe("latency", {}, 0.5, 5)

    def test_scrape_exposition(self):
        report = self.pm.scrape(6)
        self.assertIn("# HELP requests_total total requests", report.text)
        self.assertIn("# TYPE requests_total counter", report.text)
        self.assertIn('requests_total{method="get"} 3', report.text)
        self.assertIn("queue_depth 7", report.text)

    def test_scrape_histogram_lines(self):
        report = self.pm.scrape(6)
        self.assertIn('latency_bucket{le="0.1"} 0', report.text)
        self.assertIn('latency_bucket{le="1"} 1', report.text)
        self.assertIn('latency_bucket{le="+Inf"} 1', report.text)
        self.assertIn("latency_sum 0.5", report.text)
        self.assertIn("latency_count 1", report.text)

    def test_scrape_series_count(self):
        report = self.pm.scrape(6)
        self.assertEqual(report.series_count, 7)  # 1 + 1 + (2+1+1+1)

    def test_scrape_digest(self):
        report = self.pm.scrape(6)
        self.assertTrue(report.digest.startswith("sha256:"))
        self.assertTrue(report.text_digest.startswith("sha256:"))

    def test_scrape_deterministic(self):
        r1 = self.pm.scrape(6)
        # fresh identical registry must produce identical text
        pm2 = PromMetrics()
        pm2.register("requests_total", "counter", 0, label_names=("method",),
                    help_text="total requests")
        pm2.register("queue_depth", "gauge", 1, help_text="depth")
        pm2.register("latency", "histogram", 2, buckets=(0.1, 1.0), help_text="lat")
        pm2.counter_inc("requests_total", {"method": "get"}, 3, 3)
        pm2.gauge_set("queue_depth", {}, 7, 4)
        pm2.histogram_observe("latency", {}, 0.5, 5)
        r2 = pm2.scrape(6)
        self.assertEqual(r1.text, r2.text)
        self.assertEqual(r1.text_digest, r2.text_digest)

    def test_scrape_seq_monotonic(self):
        self.pm.scrape(6)
        with self.assertRaises(PromMetricsError):
            self.pm.scrape(6)

    def test_label_escaping(self):
        self.pm.register("esc", "counter", 0, label_names=("path",))
        self.pm.counter_inc("esc", {"path": 'a"b\\c\nd'}, 1, 1)
        report = self.pm.scrape(7)
        self.assertIn(r'esc{path="a\"b\\c\nd"} 1', report.text)

    def test_scrape_bad_seq(self):
        with self.assertRaises(PromMetricsError):
            self.pm.scrape(-1)
        with self.assertRaises(PromMetricsError):
            self.pm.scrape(True)


class AuditTests(unittest.TestCase):
    def test_audit_shape(self):
        event = prom_metrics_audit_event("scraped", 3, {"series": 6})
        self.assertEqual(event["schema"], SCHEMA_PIN)
        self.assertEqual(event["version"], PROM_METRICS_VERSION)
        self.assertEqual(event["audit_seq"], 3)
        self.assertEqual(event["event"], "prom-metrics")
        self.assertEqual(event["kind"], "scraped")

    def test_audit_bad_kind(self):
        with self.assertRaises(AuditError):
            prom_metrics_audit_event("bogus", 1, {})

    def test_audit_bad_detail(self):
        with self.assertRaises(AuditError):
            prom_metrics_audit_event("scraped", 1, "not-a-dict")

    def test_all_kinds(self):
        for kind in ("registered", "counter-inc", "gauge-op", "observed", "scraped", "rejected"):
            event = prom_metrics_audit_event(kind, 1, {})
            self.assertEqual(event["kind"], kind)


class SeqValidationTests(unittest.TestCase):
    def setUp(self):
        self.pm = PromMetrics()

    def test_bool_seq_refused(self):
        with self.assertRaises(PromMetricsError):
            self.pm.register("m", "counter", True)

    def test_negative_seq_refused(self):
        with self.assertRaises(PromMetricsError):
            self.pm.register("m", "counter", -1)


class StdlibOnlyTests(unittest.TestCase):
    def test_stdlib_only(self):
        import ast
        from pathlib import Path

        src = Path(prom_metrics.__file__).read_text()
        tree = ast.parse(src)
        allowed = {"__future__", "hashlib", "math", "re", "threading", "dataclasses",
                   "typing", "json", "canonical_json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.assertIn(node.module.split(".")[0], allowed)


class MainTests(unittest.TestCase):
    def test_main(self):
        prom_metrics.main()


if __name__ == "__main__":
    unittest.main()
