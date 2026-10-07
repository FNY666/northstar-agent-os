"""Tests for streaming_sql."""

import unittest

from streaming_sql import (
    AGG_FUNCS,
    STREAMING_SQL_VERSION,
    SCHEMA_PIN,
    LateEventError,
    SlidingWindow,
    StreamingSQL,
    StreamingSQLError,
    TumblingWindow,
    WatermarkReport,
    WindowError,
    WindowResult,
    streaming_sql_audit_event,
)


def rows(times):
    return [{"event_time": t, "value": t * 10} for t in times]


class VersionPinTests(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(STREAMING_SQL_VERSION, "streaming-sql.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.streaming-sql.v1")


class WindowTests(unittest.TestCase):
    def test_tumbling_assign(self):
        w = TumblingWindow(5)
        self.assertEqual(w.assign(0), (0, 5))
        self.assertEqual(w.assign(4), (0, 5))
        self.assertEqual(w.assign(5), (5, 10))
        self.assertEqual(w.assign(13), (10, 15))

    def test_tumbling_bad_size(self):
        for bad in (0, -1, True, "5"):
            with self.assertRaises((ValueError, TypeError)):
                TumblingWindow(bad)

    def test_sliding_assign(self):
        w = SlidingWindow(6, 3)
        self.assertEqual(w.assign(0), ((0, 6),))
        self.assertEqual(w.assign(5), ((0, 6), (3, 9)))
        self.assertEqual(w.assign(6), ((3, 9), (6, 12)))

    def test_sliding_slide_larger_than_size(self):
        with self.assertRaises(WindowError):
            SlidingWindow(4, 6)

    def test_windows_frozen(self):
        w = TumblingWindow(5)
        with self.assertRaises(AttributeError):
            w.size = 7


class AggregateTests(unittest.TestCase):
    def test_all_aggs(self):
        sql = StreamingSQL()
        tum = sql.tumbling_window(10)
        r = [{"event_time": t, "value": v} for t, v in [(1, 4), (2, 8)]]
        by = {x.agg: x.value for x in
              [sql2.aggregate(r, tum, a, i + 1)[0]
               for i, a, sql2 in [(0, "count", StreamingSQL()),
                                  (1, "sum", StreamingSQL()),
                                  (2, "min", StreamingSQL()),
                                  (3, "max", StreamingSQL()),
                                  (4, "avg", StreamingSQL())]]}
        self.assertEqual(by["count"], 2)
        self.assertEqual(by["sum"], 12)
        self.assertEqual(by["min"], 4)
        self.assertEqual(by["max"], 8)
        self.assertEqual(by["avg"], 6.0)

    def test_agg_ordering(self):
        sql = StreamingSQL(allowed_lateness=100)
        tum = sql.tumbling_window(5)
        out = sql.aggregate(rows([9, 1, 4]), tum, "count", 1)
        self.assertEqual([r.window_start for r in out], [0, 5])

    def test_result_digest(self):
        sql = StreamingSQL()
        r1 = sql.aggregate(rows([1, 2]), sql.tumbling_window(5), "sum", 1)[0]
        r2 = StreamingSQL().aggregate(rows([1, 2]),
                                      TumblingWindow(5), "sum", 1)[0]
        self.assertEqual(r1.digest, r2.digest)
        self.assertTrue(r1.digest.startswith("sha256:"))

    def test_unknown_agg(self):
        sql = StreamingSQL()
        with self.assertRaises(ValueError):
            sql.aggregate(rows([1]), sql.tumbling_window(5), "median", 1)
        with self.assertRaises(TypeError):
            sql.aggregate(rows([1]), sql.tumbling_window(5), 42, 1)

    def test_bad_rows(self):
        sql = StreamingSQL()
        with self.assertRaises(ValueError):
            sql.aggregate([{"value": 1}], sql.tumbling_window(5), "count", 1)
        with self.assertRaises(TypeError):
            sql.aggregate(["nope"], sql.tumbling_window(5), "count", 1)

    def test_missing_value_rejected(self):
        sql = StreamingSQL()
        with self.assertRaises(TypeError):
            sql.aggregate([{"event_time": 1}], sql.tumbling_window(5),
                          "sum", 1)

    def test_bad_window_type(self):
        sql = StreamingSQL()
        with self.assertRaises(TypeError):
            sql.aggregate(rows([1]), "tumbling", "count", 1)

    def test_negative_event_time(self):
        sql = StreamingSQL()
        with self.assertRaises(ValueError):
            sql.aggregate([{"event_time": -1, "value": 1}],
                          sql.tumbling_window(5), "count", 1)


class WatermarkTests(unittest.TestCase):
    def test_no_events(self):
        self.assertIsNone(StreamingSQL().watermark())

    def test_watermark_basic(self):
        sql = StreamingSQL(allowed_lateness=2)
        sql.aggregate(rows([5, 10]), sql.tumbling_window(5), "count", 1)
        wm = sql.watermark()
        self.assertIsInstance(wm, WatermarkReport)
        self.assertEqual(wm.watermark, 8)

    def test_late_event_refused(self):
        sql = StreamingSQL()
        sql.aggregate(rows([1, 2, 10]), sql.tumbling_window(5), "count", 1)
        with self.assertRaises(LateEventError):
            sql.aggregate([{"event_time": 3, "value": 1}],
                          sql.tumbling_window(5), "count", 2)

    def test_lateness_tolerance(self):
        sql = StreamingSQL(allowed_lateness=10)
        sql.aggregate(rows([1, 2, 30]), sql.tumbling_window(5), "count", 1)
        # window (0,5) end=5 <= 30-10=20 -> still complete, late.
        with self.assertRaises(LateEventError):
            sql.aggregate([{"event_time": 3, "value": 1}],
                          sql.tumbling_window(5), "count", 2)


class AuditTests(unittest.TestCase):
    def test_audit_shape(self):
        ev = streaming_sql_audit_event("aggregated", 3)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["module"], SCHEMA_PIN)
        self.assertEqual(ev["kind"], "aggregated")
        self.assertEqual(ev["audit_seq"], 3)

    def test_audit_bad_kind(self):
        with self.assertRaises(ValueError):
            streaming_sql_audit_event("bogus", 1)


class ErrorTests(unittest.TestCase):
    def test_errors_are_streaming(self):
        self.assertTrue(issubclass(LateEventError, StreamingSQLError))
        self.assertTrue(issubclass(WindowError, StreamingSQLError))

    def test_agg_funcs_pinned(self):
        self.assertEqual(AGG_FUNCS, {"count", "sum", "min", "max", "avg"})


class MainTests(unittest.TestCase):
    def test_main(self):
        import streaming_sql
        streaming_sql.main()


if __name__ == "__main__":
    unittest.main()
