"""Tests for timeseries_db.py."""

import unittest

from timeseries_db import (
    SCHEMA_PIN,
    TIMESERIES_DB_VERSION,
    TimeseriesDB,
    TimeseriesError,
    timeseries_db_audit_event,
)


class TimeseriesDBVersionTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(TIMESERIES_DB_VERSION, "timeseries-db.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.timeseries-db.v1")


class TimeseriesDBWriteTest(unittest.TestCase):
    def setUp(self):
        self.db = TimeseriesDB()

    def test_write_roundtrip(self):
        point = self.db.write("cpu", {"host": "a"}, 1000, 0.5, 0)
        self.assertEqual(point.metric, "cpu")
        self.assertEqual(dict(point.labels), {"host": "a"})
        self.assertEqual(point.timestamp_ms, 1000)
        self.assertEqual(point.value, 0.5)
        self.assertEqual(point.seq, 0)
        self.assertEqual(self.db.point_count(), 1)

    def test_write_label_order_invariant(self):
        self.db.write("cpu", {"b": "2", "a": "1"}, 1000, 1.0, 0)
        self.db.write("cpu", {"a": "1", "b": "2"}, 2000, 2.0, 1)
        # Same series: one key, two points.
        self.assertEqual(len(self.db.series()), 1)
        self.assertEqual(self.db.point_count(), 2)

    def test_write_validation(self):
        bad = [
            ("", {"h": "a"}, 1000, 1.0, 0),          # empty metric
            ("cpu", {"h": "a"}, -1, 1.0, 0),        # negative ts
            ("cpu", {"h": "a"}, True, 1.0, 0),      # bool ts
            ("cpu", {"h": "a"}, 1000, float("nan"), 0),  # NaN
            ("cpu", {"h": "a"}, 1000, float("inf"), 0),  # inf
            ("cpu", {"h": "a"}, 1000, True, 0),     # bool value
            ("cpu", {"h": "a"}, 1000, 1.0, -1),     # negative seq
            ("cpu", "not-a-mapping", 1000, 1.0, 0),  # bad labels
            ("cpu", {"": "a"}, 1000, 1.0, 0),       # empty label key
        ]
        for metric, labels, ts, value, seq in bad:
            with self.assertRaises(TimeseriesError, msg=str((metric, ts, value, seq))):
                self.db.write(metric, labels, ts, value, seq)
        self.assertEqual(self.db.point_count(), 0)


class TimeseriesDBQueryTest(unittest.TestCase):
    def setUp(self):
        self.db = TimeseriesDB()
        self.db.write("cpu", {"host": "a"}, 1000, 0.5, 0)
        self.db.write("cpu", {"host": "a"}, 2000, 0.7, 1)
        self.db.write("cpu", {"host": "b"}, 1500, 0.3, 2)

    def test_query_order(self):
        got = self.db.query("cpu")
        self.assertEqual([p.timestamp_ms for p in got], [1000, 1500, 2000])

    def test_query_label_subset(self):
        got = self.db.query("cpu", {"host": "a"})
        self.assertEqual(len(got), 2)
        self.assertTrue(all(dict(p.labels)["host"] == "a" for p in got))

    def test_query_time_range(self):
        got = self.db.query("cpu", None, 1000, 2000)
        self.assertEqual([p.timestamp_ms for p in got], [1000, 1500])
        # End is exclusive.
        got = self.db.query("cpu", None, 0, 1000)
        self.assertEqual(got, ())

    def test_query_bad_range(self):
        with self.assertRaises(TimeseriesError):
            self.db.query("cpu", None, 2000, 1000)

    def test_query_unknown_metric_empty(self):
        self.assertEqual(self.db.query("mem"), ())


class TimeseriesDBDownsampleTest(unittest.TestCase):
    def setUp(self):
        self.db = TimeseriesDB()
        self.db.write("cpu", {"host": "a"}, 1000, 0.5, 0)
        self.db.write("cpu", {"host": "a"}, 1500, 0.7, 1)
        self.db.write("cpu", {"host": "a"}, 2500, 0.9, 2)

    def test_downsample_avg(self):
        buckets = self.db.downsample("cpu", None, 1000, "avg", 0, 3000, 0)
        self.assertEqual(len(buckets), 2)
        self.assertEqual(buckets[0].bucket_start_ms, 1000)
        self.assertEqual(buckets[0].count, 2)
        self.assertAlmostEqual(buckets[0].value, 0.6)
        self.assertTrue(buckets[0].digest.startswith("sha256:"))
        self.assertEqual(buckets[1].bucket_start_ms, 2000)
        self.assertAlmostEqual(buckets[1].value, 0.9)

    def test_downsample_aggs(self):
        for agg, expected in [("count", 2.0), ("sum", 1.2), ("min", 0.5), ("max", 0.7)]:
            buckets = self.db.downsample("cpu", None, 1000, agg, 0, 2000, 0)
            self.assertEqual(len(buckets), 1)
            self.assertAlmostEqual(buckets[0].value, expected, msg=agg)

    def test_downsample_empty_range(self):
        self.assertEqual(self.db.downsample("cpu", None, 1000, "avg", 9000, 9999, 0), ())

    def test_downsample_validation(self):
        with self.assertRaises(TimeseriesError):
            self.db.downsample("cpu", None, 0, "avg", 0, 3000, 0)
        with self.assertRaises(TimeseriesError):
            self.db.downsample("cpu", None, 1000, "median", 0, 3000, 0)
        with self.assertRaises(TimeseriesError):
            self.db.downsample("cpu", None, 1000, "avg", 3000, 0, 0)


class TimeseriesDBRetentionTest(unittest.TestCase):
    def test_retention_drops_strictly_older(self):
        db = TimeseriesDB()
        db.write("cpu", None, 1000, 1.0, 0)
        db.write("cpu", None, 2000, 2.0, 1)
        report = db.retention(2000, 2)
        self.assertEqual(report.points_dropped, 1)
        self.assertEqual(report.points_kept, 1)
        self.assertEqual(report.cutoff_ms, 2000)
        self.assertEqual(db.point_count(), 1)
        # Empty series are removed from the key index.
        db.retention(3000, 3)
        self.assertEqual(db.series(), ())
        self.assertEqual(db.point_count(), 0)

    def test_retention_validation(self):
        db = TimeseriesDB()
        with self.assertRaises(TimeseriesError):
            db.retention(-1, 0)


class TimeseriesDBAuditTest(unittest.TestCase):
    def test_audit_event_shape(self):
        event = timeseries_db_audit_event("point-written", 3, metric="cpu", points=1)
        self.assertEqual(event["schema"], SCHEMA_PIN)
        self.assertEqual(event["kind"], "point-written")
        self.assertEqual(event["audit_seq"], 3)
        self.assertEqual(event["module_version"], "timeseries-db.v1")
        self.assertEqual(event["metric"], "cpu")

    def test_audit_unknown_kind(self):
        with self.assertRaises(TimeseriesError):
            timeseries_db_audit_event("bogus", 0)

    def test_main(self):
        from timeseries_db import main

        main()


if __name__ == "__main__":
    unittest.main()
