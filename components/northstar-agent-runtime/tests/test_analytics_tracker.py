"""Targeted tests for the analytics tracker interface."""

import ast
import json
import unittest
from pathlib import Path

from analytics_tracker import (
    ANALYTICS_TRACKER_SCHEMA,
    ANALYTICS_TRACKER_VERSION,
    AUDIT_SCHEMA,
    KIND_COHORT,
    KIND_EVENT_TRACKED,
    KIND_FUNNEL,
    KIND_REJECTED,
    AnalyticsError,
    AnalyticsTracker,
    SeqOrderError,
    UnknownEventError,
    analytics_tracker_audit_event,
    compute_cohort_digest,
    compute_event_digest,
    compute_funnel_digest,
    main,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "analytics_tracker.py"


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(ANALYTICS_TRACKER_VERSION, "analytics-tracker.v1")
        self.assertEqual(ANALYTICS_TRACKER_SCHEMA, "northstar.analytics-tracker.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {
            "__future__", "hashlib", "json", "dataclasses", "threading", "typing",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestTrack(unittest.TestCase):
    def test_track_happy_path(self):
        tracker = AnalyticsTracker()
        event = tracker.track("u1", "signup", 1, {"plan": "pro", "seats": 3})
        self.assertEqual(event.event_id, "evt-1")
        self.assertEqual(event.user_id, "u1")
        self.assertEqual(event.event_name, "signup")
        self.assertEqual(event.seq, 1)
        self.assertEqual(event.properties, (("plan", "pro"), ("seats", 3)))
        self.assertEqual(event.prev_digest, "genesis")
        self.assertTrue(event.record_digest.startswith("sha256:"))
        self.assertEqual(compute_event_digest(event), event.record_digest)

    def test_track_chain(self):
        tracker = AnalyticsTracker()
        first = tracker.track("u1", "signup", 1)
        second = tracker.track("u1", "login", 2)
        self.assertEqual(second.prev_digest, first.record_digest)
        self.assertEqual(second.event_id, "evt-2")

    def test_track_bad_inputs(self):
        tracker = AnalyticsTracker()
        with self.assertRaises(AnalyticsError):
            tracker.track("", "signup", 1)
        with self.assertRaises(AnalyticsError):
            tracker.track("u1", "", 2)
        with self.assertRaises(AnalyticsError):
            tracker.track("u1", "bad\x00name", 3)
        with self.assertRaises(AnalyticsError):
            tracker.track("u1", "ok", 4, {"f": 1.5})
        with self.assertRaises(AnalyticsError):
            tracker.track("u1", "ok", 5, {"big": 2 ** 60})
        with self.assertRaises(AnalyticsError):
            tracker.track("u1", "ok", 6, {"k" * 65: "v"})
        with self.assertRaises(AnalyticsError):
            tracker.track("u1", "ok", True)
        with self.assertRaises(AnalyticsError):
            tracker.track("u1", "ok", -1)

    def test_seq_rewind_refused(self):
        tracker = AnalyticsTracker()
        tracker.track("u1", "signup", 5)
        with self.assertRaises(SeqOrderError):
            tracker.track("u1", "login", 5)
        with self.assertRaises(SeqOrderError):
            tracker.track("u1", "login", 3)

    def test_failed_mutation_consumes_seq(self):
        tracker = AnalyticsTracker()
        with self.assertRaises(AnalyticsError):
            tracker.track("u1", "", 5)  # bad name consumes seq 5
        with self.assertRaises(SeqOrderError):
            tracker.track("u1", "ok", 5)  # 5 is spent
        event = tracker.track("u1", "ok", 6)
        self.assertEqual(event.event_id, "evt-1")  # ledger position kept


class TestFunnel(unittest.TestCase):
    def _three_users(self):
        tracker = AnalyticsTracker()
        tracker.track("a", "signup", 1)
        tracker.track("a", "purchase", 2)
        tracker.track("a", "refund", 3)
        tracker.track("b", "signup", 4)
        tracker.track("b", "refund", 5)  # skips purchase
        tracker.track("c", "purchase", 6)  # never entered
        return tracker

    def test_funnel_happy_path(self):
        tracker = self._three_users()
        report = tracker.funnel("buy", ("signup", "purchase", "refund"), 7, 100)
        self.assertEqual(report.step_counts, (2, 1, 1))
        self.assertEqual(report.conversion_rates, (1.0, 0.5, 0.5))
        self.assertEqual(report.analyzed_events, 6)
        self.assertEqual(compute_funnel_digest(report), report.record_digest)

    def test_funnel_order_enforced(self):
        tracker = AnalyticsTracker()
        tracker.track("u1", "purchase", 1)
        tracker.track("u1", "signup", 2)  # purchase came before entry
        report = tracker.funnel("buy", ("signup", "purchase"), 3, 100)
        self.assertEqual(report.step_counts, (1, 0))

    def test_funnel_window_expiry(self):
        tracker = AnalyticsTracker()
        tracker.track("u1", "signup", 1)
        tracker.track("u1", "purchase", 200)
        narrow = tracker.funnel("buy", ("signup", "purchase"), 201, 100)
        self.assertEqual(narrow.step_counts, (1, 0))
        wide = tracker.funnel("buy", ("signup", "purchase"), 202, 1000)
        self.assertEqual(wide.step_counts, (1, 1))

    def test_funnel_empty_ledger(self):
        tracker = AnalyticsTracker()
        report = tracker.funnel("buy", ("signup", "purchase"), 1, 100)
        self.assertEqual(report.step_counts, (0, 0))
        self.assertEqual(report.conversion_rates, (0.0, 0.0))

    def test_funnel_bad_inputs(self):
        tracker = AnalyticsTracker()
        with self.assertRaises(AnalyticsError):
            tracker.funnel("buy", ["signup"], 1, 100)  # < 2 steps
        with self.assertRaises(AnalyticsError):
            tracker.funnel("", ("signup", "purchase"), 2, 100)
        with self.assertRaises(AnalyticsError):
            tracker.funnel("buy", ("signup", "purchase"), 3, 0)


class TestCohort(unittest.TestCase):
    def test_cohort_retention(self):
        tracker = AnalyticsTracker()
        tracker.track("u1", "signup", 1)
        tracker.track("u1", "login", 2)
        tracker.track("u2", "signup", 3)
        tracker.track("u3", "signup", 11)
        tracker.track("u3", "login", 12)
        tracker.track("u1", "login", 13)
        tracker.track("u2", "login", 14)
        report = tracker.cohort("ret", "signup", "login", 15,
                                bucket_size=10, periods=3)
        self.assertEqual(len(report.buckets), 2)
        b0, b1 = report.buckets
        self.assertEqual((b0.bucket, b0.size), (0, 2))
        self.assertEqual(b0.retention, (0.5, 1.0, 0.0))
        self.assertEqual((b1.bucket, b1.size), (1, 1))
        self.assertEqual(b1.retention, (1.0, 0.0, 0.0))
        self.assertEqual(compute_cohort_digest(report), report.record_digest)

    def test_cohort_no_anchor_events(self):
        tracker = AnalyticsTracker()
        tracker.track("u1", "login", 1)
        report = tracker.cohort("ret", "signup", "login", 2,
                                bucket_size=10, periods=2)
        self.assertEqual(report.buckets, ())

    def test_cohort_bad_inputs(self):
        tracker = AnalyticsTracker()
        with self.assertRaises(AnalyticsError):
            tracker.cohort("ret", "signup", "login", 1, bucket_size=0, periods=2)
        with self.assertRaises(AnalyticsError):
            tracker.cohort("ret", "signup", "login", 2, bucket_size=10, periods=0)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        tracker = AnalyticsTracker()
        tracker.track("u1", "signup", 1, {"secret": "s3cr3t"})
        tracker.funnel("buy", ("signup", "purchase"), 2, 100)
        kinds = [e["kind"] for e in tracker.audit_log()]
        self.assertEqual(kinds, [KIND_EVENT_TRACKED, KIND_FUNNEL])
        for event in tracker.audit_log():
            self.assertEqual(event["schema"], AUDIT_SCHEMA)
            self.assertEqual(event["module"], "analytics_tracker")

    def test_audit_boundary_bans_user_data(self):
        tracker = AnalyticsTracker()
        tracker.track("user-xyz", "signup", 1, {"token": "tok-abc-123"})
        tracker.cohort("c", "signup", "login", 2, bucket_size=10, periods=1)
        blob = json.dumps([dict(e) for e in tracker.audit_log()])
        self.assertNotIn("user-xyz", blob)
        self.assertNotIn("tok-abc-123", blob)

    def test_rejected_audit_and_unknown_kind(self):
        tracker = AnalyticsTracker()
        with self.assertRaises(AnalyticsError):
            tracker.track("u1", "", 1)
        kinds = [e["kind"] for e in tracker.audit_log()]
        self.assertEqual(kinds, [KIND_REJECTED])
        with self.assertRaises(AnalyticsError):
            analytics_tracker_audit_event("nope", 2)


class TestViews(unittest.TestCase):
    def test_views(self):
        tracker = AnalyticsTracker()
        tracker.track("u1", "signup", 1)
        tracker.track("u1", "login", 2)
        self.assertEqual(tracker.event_ids(), ("evt-1", "evt-2"))
        self.assertEqual(len(tracker.events_for("u1")), 2)
        self.assertEqual(tracker.events_for("nobody"), ())
        self.assertEqual(tracker.event("evt-1").event_name, "signup")
        with self.assertRaises(UnknownEventError):
            tracker.event("evt-999")
        stats = tracker.stats()
        self.assertEqual(stats["events"], 2)
        self.assertEqual(stats["users"], 1)
        self.assertEqual(stats["last_seq"], 2)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        main()


if __name__ == "__main__":
    unittest.main()
