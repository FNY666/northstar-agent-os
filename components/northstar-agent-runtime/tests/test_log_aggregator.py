"""Targeted tests for log_aggregator.py (Loki-style log aggregation)."""

import unittest

from log_aggregator import (
    LOG_AGGREGATOR_VERSION,
    SCHEMA_PIN,
    MAX_LINE_BYTES,
    LogAggregator,
    LogAggregatorError,
    LogEntry,
    log_aggregator_audit_event,
    main,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(LOG_AGGREGATOR_VERSION, "log-aggregator.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.log-aggregator.v1")


class TestIngest(unittest.TestCase):
    def setUp(self):
        self.agg = LogAggregator()

    def test_ingest_returns_frozen_entry(self):
        entry = self.agg.ingest("app", {"host": "a"}, 1000, "hello", 0)
        self.assertIsInstance(entry, LogEntry)
        self.assertEqual(entry.stream, "app")
        self.assertEqual(entry.labels, (("host", "a"),))
        self.assertEqual(entry.timestamp_ms, 1000)
        self.assertEqual(entry.line, "hello")
        self.assertEqual(entry.seq, 0)
        self.assertTrue(entry.digest.startswith("sha256:"))
        with self.assertRaises(Exception):
            entry.line = "mutated"  # frozen

    def test_label_order_invariance(self):
        e1 = self.agg.ingest("app", {"a": "1", "b": "2"}, 1000, "x", 0)
        e2 = self.agg.ingest("app", {"b": "2", "a": "1"}, 1000, "x", 0)
        self.assertEqual(e1.labels, e2.labels)
        self.assertEqual(self.agg.stream_count(), 1)

    def test_entry_count(self):
        self.assertEqual(self.agg.entry_count(), 0)
        self.agg.ingest("app", None, 1000, "x", 0)
        self.agg.ingest("db", None, 1000, "y", 1)
        self.assertEqual(self.agg.entry_count(), 2)

    def test_empty_stream_rejected(self):
        with self.assertRaises(LogAggregatorError):
            self.agg.ingest("", None, 1000, "x", 0)

    def test_bad_stream_type_rejected(self):
        with self.assertRaises(LogAggregatorError):
            self.agg.ingest(123, None, 1000, "x", 0)

    def test_bad_labels_rejected(self):
        with self.assertRaises(LogAggregatorError):
            self.agg.ingest("app", "not-a-mapping", 1000, "x", 0)
        with self.assertRaises(LogAggregatorError):
            self.agg.ingest("app", {1: "v"}, 1000, "x", 0)
        with self.assertRaises(LogAggregatorError):
            self.agg.ingest("app", {"k": 2}, 1000, "x", 0)

    def test_bad_timestamp_rejected(self):
        with self.assertRaises(LogAggregatorError):
            self.agg.ingest("app", None, -1, "x", 0)
        with self.assertRaises(LogAggregatorError):
            self.agg.ingest("app", None, True, "x", 0)

    def test_bad_line_rejected(self):
        with self.assertRaises(LogAggregatorError):
            self.agg.ingest("app", None, 1000, "", 0)
        with self.assertRaises(LogAggregatorError):
            self.agg.ingest("app", None, 1000, 42, 0)
        with self.assertRaises(LogAggregatorError):
            self.agg.ingest("app", None, 1000, "x" * (MAX_LINE_BYTES + 1), 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(LogAggregatorError):
            self.agg.ingest("app", None, 1000, "x", -1)
        with self.assertRaises(LogAggregatorError):
            self.agg.ingest("app", None, 1000, "x", True)


class TestQuery(unittest.TestCase):
    def setUp(self):
        self.agg = LogAggregator()
        self.agg.ingest("app", {"host": "a"}, 1000, "starting up", 0)
        self.agg.ingest("app", {"host": "a"}, 2000, "error: disk full", 1)
        self.agg.ingest("app", {"host": "b"}, 1000, "starting up", 2)
        self.agg.ingest("db", {"host": "a"}, 3000, "checkpoint", 3)

    def test_query_all(self):
        got = self.agg.query()
        self.assertEqual(len(got), 4)

    def test_query_stream(self):
        got = self.agg.query(stream="app")
        self.assertEqual(len(got), 3)
        self.assertTrue(all(e.stream == "app" for e in got))

    def test_query_label_subset(self):
        got = self.agg.query(labels={"host": "a"})
        self.assertEqual(len(got), 3)  # two app + one db

    def test_query_stream_and_labels(self):
        got = self.agg.query(stream="app", labels={"host": "b"})
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].line, "starting up")

    def test_query_range_half_open(self):
        got = self.agg.query(start=1000, end=2000)
        self.assertEqual(len(got), 2)  # end exclusive
        self.assertTrue(all(1000 <= e.timestamp_ms < 2000 for e in got))

    def test_query_bad_range_rejected(self):
        with self.assertRaises(LogAggregatorError):
            self.agg.query(start=2000, end=1000)

    def test_query_ascending_order(self):
        # Out-of-order ingest still returns sorted results.
        agg = LogAggregator()
        agg.ingest("s", None, 3000, "c", 0)
        agg.ingest("s", None, 1000, "a", 1)
        agg.ingest("s", None, 2000, "b", 2)
        got = agg.query()
        self.assertEqual([e.line for e in got], ["a", "b", "c"])

    def test_query_contains(self):
        got = self.agg.query(contains="error")
        self.assertEqual(len(got), 1)
        self.assertIn("disk full", got[0].line)

    def test_query_contains_rejected(self):
        with self.assertRaises(LogAggregatorError):
            self.agg.query(contains="")

    def test_query_regex(self):
        got = self.agg.query(regex=r"^start")
        self.assertEqual(len(got), 2)

    def test_query_bad_regex_rejected(self):
        with self.assertRaises(LogAggregatorError):
            self.agg.query(regex="([unclosed")

    def test_query_limit(self):
        got = self.agg.query(limit=2)
        self.assertEqual(len(got), 2)
        # Limit applies after deterministic sort: earliest two.
        self.assertEqual(got[0].timestamp_ms, 1000)

    def test_query_bad_limit_rejected(self):
        with self.assertRaises(LogAggregatorError):
            self.agg.query(limit=0)
        with self.assertRaises(LogAggregatorError):
            self.agg.query(limit=True)

    def test_query_unknown_stream_empty(self):
        got = self.agg.query(stream="nope")
        self.assertEqual(got, ())

    def test_query_deterministic(self):
        a = self.agg.query()
        b = self.agg.query()
        self.assertEqual([e.digest for e in a], [e.digest for e in b])


class TestTail(unittest.TestCase):
    def setUp(self):
        self.agg = LogAggregator()
        for i in range(5):
            self.agg.ingest("app", None, 1000 * (i + 1), f"line-{i}", i)

    def test_tail_all(self):
        report = self.agg.tail(10, seq=5)
        self.assertEqual(len(report.entries), 5)
        self.assertEqual(report.requested, 10)

    def test_tail_n(self):
        report = self.agg.tail(2, seq=5)
        self.assertEqual(len(report.entries), 2)
        self.assertEqual([e.line for e in report.entries], ["line-3", "line-4"])

    def test_tail_ascending_order(self):
        report = self.agg.tail(3, seq=5)
        ts = [e.timestamp_ms for e in report.entries]
        self.assertEqual(ts, sorted(ts))

    def test_tail_with_filter(self):
        self.agg.ingest("db", None, 9999, "other", 5)
        report = self.agg.tail(2, stream="app", seq=6)
        self.assertEqual(len(report.entries), 2)
        self.assertTrue(all(e.stream == "app" for e in report.entries))

    def test_tail_empty(self):
        report = LogAggregator().tail(5, seq=0)
        self.assertEqual(report.entries, ())

    def test_tail_bad_n_rejected(self):
        for bad in (0, -1, True, "2", 1.5):
            with self.assertRaises(LogAggregatorError):
                self.agg.tail(bad, seq=5)


class TestRetention(unittest.TestCase):
    def setUp(self):
        self.agg = LogAggregator()
        self.agg.ingest("app", {"h": "a"}, 1000, "old", 0)
        self.agg.ingest("app", {"h": "a"}, 2000, "new", 1)
        self.agg.ingest("db", {"h": "a"}, 1000, "old", 2)

    def test_retention_drops_strictly_older(self):
        report = self.agg.retention(2000, 3)
        self.assertEqual(report.entries_dropped, 2)
        self.assertEqual(report.entries_kept, 1)
        self.assertEqual(report.streams_visited, 2)
        self.assertEqual(self.agg.entry_count(), 1)

    def test_retention_purges_emptied_streams(self):
        self.agg.retention(2000, 3)
        self.assertEqual(self.agg.stream_count(), 1)
        self.assertEqual(self.agg.streams()[0][0], "app")

    def test_retention_boundary_kept(self):
        # Exactly at the cutoff is kept (drops strictly older).
        report = self.agg.retention(1000, 3)
        self.assertEqual(report.entries_dropped, 0)
        self.assertEqual(report.entries_kept, 3)

    def test_retention_bad_cutoff_rejected(self):
        with self.assertRaises(LogAggregatorError):
            self.agg.retention(-1, 3)


class TestViewsAndVerify(unittest.TestCase):
    def test_streams_sorted(self):
        agg = LogAggregator()
        agg.ingest("zebra", None, 1000, "x", 0)
        agg.ingest("app", None, 1000, "x", 1)
        keys = agg.streams()
        self.assertEqual([k[0] for k in keys], ["app", "zebra"])

    def test_verify_clean(self):
        agg = LogAggregator()
        agg.ingest("app", None, 1000, "x", 0)
        self.assertTrue(agg.verify())


class TestAudit(unittest.TestCase):
    def test_audit_shape(self):
        event = log_aggregator_audit_event("line-ingested", 7, digest="sha256:abc")
        self.assertEqual(event["schema"], SCHEMA_PIN)
        self.assertEqual(event["audit_seq"], 7)
        self.assertEqual(event["kind"], "line-ingested")
        self.assertEqual(event["module_version"], LOG_AGGREGATOR_VERSION)
        self.assertEqual(event["digest"], "sha256:abc")

    def test_audit_all_kinds(self):
        for kind in (
            "created",
            "line-ingested",
            "queried",
            "tailed",
            "retention-applied",
            "rejected",
        ):
            event = log_aggregator_audit_event(kind, 0)
            self.assertEqual(event["kind"], kind)

    def test_audit_unknown_kind_rejected(self):
        with self.assertRaises(LogAggregatorError):
            log_aggregator_audit_event("bogus", 0)

    def test_audit_bad_seq_rejected(self):
        with self.assertRaises(LogAggregatorError):
            log_aggregator_audit_event("queried", -1)


class TestMain(unittest.TestCase):
    def test_main(self):
        main()  # self-check runs without assertion


if __name__ == "__main__":
    unittest.main()
