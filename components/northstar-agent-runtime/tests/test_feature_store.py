"""Tests for feature_store: registry, point-in-time serving, backfill."""

import unittest

from feature_store import (
    AUDIT_FORMAT,
    SCHEMA_PIN,
    FEATURE_STORE_VERSION,
    BackfillReport,
    DuplicateFeatureError,
    FeatureDefinition,
    FeatureStore,
    FeatureStoreError,
    FeatureVector,
    UnknownFeatureError,
    feature_store_audit_event,
)


def make_store():
    store = FeatureStore()
    store.register("age_days", "ml-platform", "int", 100)
    store.register("churn_score", "ml-platform", "float", 50)
    return store


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(FEATURE_STORE_VERSION, "feature-store.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.feature-store.v1")
        self.assertEqual(AUDIT_FORMAT, "audit.ndjson/1")

    def test_definition_digest(self):
        d = FeatureDefinition(
            name="f", owner="o", value_type="int",
            freshness_sla_seqs=10,
        )
        self.assertTrue(d.digest.startswith("sha256:"))
        self.assertEqual(d.as_dict()["schema"], SCHEMA_PIN)


class TestRegister(unittest.TestCase):
    def test_register_happy_path(self):
        store = FeatureStore()
        d = store.register("f1", "team-a", "float", 10, "desc")
        self.assertEqual(d.name, "f1")
        self.assertEqual(d.owner, "team-a")
        self.assertEqual(store.feature_names(), ("f1",))

    def test_register_duplicate(self):
        store = FeatureStore()
        store.register("f1", "team-a", "int", 10)
        with self.assertRaises(DuplicateFeatureError):
            store.register("f1", "team-b", "int", 10)

    def test_register_bad_name(self):
        store = FeatureStore()
        for bad in ("", True, 123, None):
            with self.assertRaises((TypeError, ValueError)):
                store.register(bad, "team-a", "int", 10)

    def test_register_bad_value_type(self):
        store = FeatureStore()
        with self.assertRaises(ValueError):
            store.register("f1", "team-a", "blob", 10)

    def test_register_bad_freshness(self):
        store = FeatureStore()
        for bad in (True, -1, "10"):
            with self.assertRaises(ValueError):
                store.register("f1", "team-a", "int", bad)

    def test_definition_unknown(self):
        store = FeatureStore()
        with self.assertRaises(UnknownFeatureError):
            store.definition("nope")


class TestServe(unittest.TestCase):
    def test_ingest_and_serve(self):
        store = make_store()
        store.ingest("u1", "age_days", 365, event_seq=10, seq=1)
        vec = store.serve("u1", ["age_days"], 15, 2)
        self.assertEqual(vec.get("age_days"), 365)
        self.assertEqual(vec.as_of_seq, 15)

    def test_point_in_time_correctness(self):
        store = make_store()
        store.ingest("u1", "churn_score", 0.7, event_seq=10, seq=1)
        store.ingest("u1", "churn_score", 0.9, event_seq=20, seq=2)
        old = store.serve("u1", ["churn_score"], 15, 3)
        self.assertEqual(old.get("churn_score"), 0.7)
        new = store.serve("u1", ["churn_score"], 25, 4)
        self.assertEqual(new.get("churn_score"), 0.9)

    def test_serve_missing_value_is_none(self):
        store = make_store()
        vec = store.serve("u1", ["age_days"], 99, 1)
        self.assertIsNone(vec.get("age_days"))

    def test_serve_unknown_feature(self):
        store = make_store()
        with self.assertRaises(UnknownFeatureError):
            store.serve("u1", ["nope"], 99, 1)

    def test_ingest_unknown_feature(self):
        store = FeatureStore()
        with self.assertRaises(UnknownFeatureError):
            store.ingest("u1", "nope", 1, event_seq=1, seq=1)

    def test_ingest_type_mismatch(self):
        store = make_store()
        with self.assertRaises(TypeError):
            store.ingest("u1", "age_days", "not-an-int", event_seq=1, seq=1)
        with self.assertRaises(TypeError):
            store.ingest("u1", "churn_score", True, event_seq=1, seq=1)


class TestBackfill(unittest.TestCase):
    def test_backfill_happy_path(self):
        store = make_store()
        store.ingest("u1", "churn_score", 0.7, event_seq=10, seq=1)
        store.ingest("u2", "churn_score", 0.8, event_seq=20, seq=2)
        report = store.backfill("churn_score", 25, 3)
        self.assertIsInstance(report, BackfillReport)
        self.assertEqual(report.rows_written, 2)
        self.assertEqual(report.rows_skipped, 0)
        self.assertTrue(report.digest.startswith("sha256:"))

    def test_backfill_does_not_regress(self):
        store = make_store()
        store.ingest("u1", "churn_score", 0.7, event_seq=10, seq=1)
        store.ingest("u1", "churn_score", 0.9, event_seq=30, seq=2)
        report = store.backfill("churn_score", 20, 3)
        self.assertEqual(report.rows_written, 0)
        self.assertEqual(report.rows_skipped, 2)
        # The online store must not be regressed to older data.
        vec = store.serve("u1", ["churn_score"], 99, 4)
        self.assertEqual(vec.get("churn_score"), 0.9)

    def test_backfill_unknown_feature(self):
        store = make_store()
        with self.assertRaises(UnknownFeatureError):
            store.backfill("nope", 10, 1)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("registered", "ingested", "served", "backfilled",
                     "rejected"):
            event = feature_store_audit_event(kind, seq=3)
            self.assertEqual(event["format"], "audit.ndjson/1")
            self.assertEqual(event["schema"], SCHEMA_PIN)
            self.assertEqual(event["kind"], kind)
            self.assertEqual(event["seq"], 3)

    def test_audit_bad_kind(self):
        with self.assertRaises(ValueError):
            feature_store_audit_event("nope", seq=1)

    def test_audit_bad_seq(self):
        with self.assertRaises((TypeError, ValueError)):
            feature_store_audit_event("served", seq=True)

    def test_main(self):
        from feature_store import main
        main()


if __name__ == "__main__":
    unittest.main()
