"""Tests for feature_store entity ledger: entity(), feature(), serve()."""

import dataclasses
import subprocess
import sys
import unittest

from feature_store import (
    AUDIT_FORMAT,
    SCHEMA_PIN,
    FEATURE_STORE_VERSION,
    DuplicateEntityError,
    EntityRecord,
    FeatureDefinition,
    FeatureStore,
    FeatureStoreError,
    UnknownEntityError,
    UnknownFeatureError,
    feature_store_audit_event,
)


def make_store():
    store = FeatureStore()
    store.register("age_days", "ml-platform", "int", 100)
    store.register("churn_score", "ml-platform", "float", 50)
    return store


class TestEntityLedger(unittest.TestCase):
    def test_entity_roundtrip(self):
        store = FeatureStore()
        rec = store.entity("user-1", "churn experiment cohort")
        self.assertIsInstance(rec, EntityRecord)
        self.assertEqual(rec.entity_id, "user-1")
        self.assertEqual(rec.description, "churn experiment cohort")
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_entity_default_description(self):
        store = FeatureStore()
        rec = store.entity("user-1")
        self.assertEqual(rec.description, "")

    def test_entity_duplicate_refused(self):
        store = FeatureStore()
        store.entity("user-1")
        with self.assertRaises(DuplicateEntityError):
            store.entity("user-1")

    def test_entity_bad_ids(self):
        store = FeatureStore()
        for bad in ("", True, 123, None):
            with self.assertRaises((TypeError, ValueError)):
                store.entity(bad)

    def test_entity_record_lookup(self):
        store = FeatureStore()
        rec = store.entity("user-1")
        self.assertIs(store.entity_record("user-1"), rec)

    def test_entity_record_unknown(self):
        store = FeatureStore()
        with self.assertRaises(UnknownEntityError):
            store.entity_record("ghost")

    def test_entity_ids_sorted_view(self):
        store = FeatureStore()
        store.entity("user-9")
        store.entity("user-1")
        store.entity("user-5")
        self.assertEqual(store.entity_ids(), ("user-1", "user-5", "user-9"))

    def test_entity_record_frozen(self):
        store = FeatureStore()
        rec = store.entity("user-1")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            rec.entity_id = "user-2"  # type: ignore[misc]

    def test_entity_digest_deterministic(self):
        a = FeatureStore().entity("user-1", "cohort-a")
        b = FeatureStore().entity("user-1", "cohort-a")
        self.assertEqual(a.digest, b.digest)
        c = FeatureStore().entity("user-2", "cohort-a")
        self.assertNotEqual(a.digest, c.digest)

    def test_entity_as_dict_schema_pin(self):
        store = FeatureStore()
        d = store.entity("user-1").as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["entity_id"], "user-1")


class TestFeatureAlias(unittest.TestCase):
    def test_feature_returns_definition(self):
        store = make_store()
        d = store.feature("churn_score")
        self.assertIsInstance(d, FeatureDefinition)
        self.assertEqual(d.name, "churn_score")
        self.assertEqual(d.value_type, "float")

    def test_feature_unknown_raises(self):
        store = make_store()
        with self.assertRaises(UnknownFeatureError):
            store.feature("nope")


class TestServeUnchanged(unittest.TestCase):
    def test_serve_after_entity_booking(self):
        store = make_store()
        store.entity("user-1")
        store.ingest("user-1", "age_days", 365, event_seq=10, seq=1)
        store.ingest("user-1", "churn_score", 0.7, event_seq=10, seq=2)
        vec = store.serve("user-1", ["age_days", "churn_score"], 15, 3)
        self.assertEqual(vec.get("age_days"), 365)
        self.assertEqual(vec.get("churn_score"), 0.7)

    def test_audit_vocabulary_unchanged(self):
        event = feature_store_audit_event("registered", seq=1)
        self.assertEqual(event["format"], "audit.ndjson/1")
        self.assertEqual(event["schema"], SCHEMA_PIN)
        self.assertEqual(FEATURE_STORE_VERSION, "feature-store.v1")

    def test_main(self):
        from feature_store import main
        main()


if __name__ == "__main__":
    unittest.main()
