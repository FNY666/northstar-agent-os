"""Tests for dataset_version.py: DVC-style dataset versioning."""

import unittest

import dataset_version as dv
from dataset_version import (
    DatasetVersion,
    DatasetDiff,
    DatasetVersionError,
    KeyChange,
    UnknownVersionError,
    VersionRecord,
    dataset_version_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(dv.DATASET_VERSION_VERSION, "dataset-version.v1")

    def test_schema_pin(self):
        self.assertEqual(dv.DATASET_VERSION_SCHEMA, "northstar.dataset-version.v1")


class TestVersionRecord(unittest.TestCase):
    def test_record_shape(self):
        rec = VersionRecord(version=0, digest="sha256:abc", seq=5, shape="mapping")
        self.assertEqual(rec.as_dict()["schema"], "northstar.dataset-version.v1")
        self.assertEqual(rec.as_dict()["version"], 0)

    def test_record_bad_version(self):
        with self.assertRaises((TypeError, ValueError)):
            VersionRecord(version=True, digest="sha256:abc", seq=0, shape="mapping")
        with self.assertRaises(ValueError):
            VersionRecord(version=-1, digest="sha256:abc", seq=0, shape="mapping")

    def test_record_bad_digest(self):
        with self.assertRaises(ValueError):
            VersionRecord(version=0, digest="md5:abc", seq=0, shape="mapping")

    def test_record_bad_shape(self):
        with self.assertRaises(ValueError):
            VersionRecord(version=0, digest="sha256:abc", seq=0, shape="graph")

    def test_key_change_validation(self):
        with self.assertRaises(ValueError):
            KeyChange(key="", old=1, new=2)


class TestCommit(unittest.TestCase):
    def test_label_required(self):
        with self.assertRaises(DatasetVersionError):
            DatasetVersion("")

    def test_commit_mapping(self):
        store = DatasetVersion("x")
        rec = store.commit({"a": 1}, 0)
        self.assertEqual(rec.version, 0)
        self.assertEqual(rec.shape, "mapping")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(len(store), 1)

    def test_commit_sequence(self):
        store = DatasetVersion("x")
        rec = store.commit([1, 2, 3], 0)
        self.assertEqual(rec.shape, "sequence")

    def test_commit_tuple_becomes_list(self):
        store = DatasetVersion("x")
        store.commit((1, 2), 0)
        self.assertEqual(store.checkout(0), [1, 2])

    def test_commit_rejects_non_dataset(self):
        store = DatasetVersion("x")
        for bad in (None, True, 42, "str"):
            with self.assertRaises(DatasetVersionError):
                store.commit(bad, 0)

    def test_commit_rejects_non_str_key(self):
        store = DatasetVersion("x")
        with self.assertRaises(DatasetVersionError):
            store.commit({1: "a"}, 0)

    def test_commit_rejects_bad_seq(self):
        store = DatasetVersion("x")
        for bad in (-1, True, "0"):
            with self.assertRaises(DatasetVersionError):
                store.commit({"a": 1}, bad)

    def test_versions_ordered(self):
        store = DatasetVersion("x")
        store.commit({"a": 1}, 0)
        store.commit({"a": 2}, 1)
        versions = store.versions()
        self.assertEqual([r.version for r in versions], [0, 1])

    def test_record_lookup(self):
        store = DatasetVersion("x")
        store.commit({"a": 1}, 7)
        rec = store.record(0)
        self.assertEqual(rec.seq, 7)

    def test_record_unknown(self):
        store = DatasetVersion("x")
        with self.assertRaises(UnknownVersionError):
            store.record(0)
        with self.assertRaises(TypeError):
            store.record(True)


class TestCheckout(unittest.TestCase):
    def test_checkout_returns_copy(self):
        store = DatasetVersion("x")
        store.commit({"a": [1, 2]}, 0)
        snap = store.checkout(0)
        snap["a"].append(99)
        self.assertEqual(store.checkout(0), {"a": [1, 2]})

    def test_checkout_unknown(self):
        store = DatasetVersion("x")
        store.commit({"a": 1}, 0)
        with self.assertRaises(UnknownVersionError):
            store.checkout(3)
        with self.assertRaises(UnknownVersionError):
            store.checkout(-1)

    def test_commit_does_not_alias_caller(self):
        store = DatasetVersion("x")
        data = {"a": 1}
        store.commit(data, 0)
        data["a"] = 999
        self.assertEqual(store.checkout(0), {"a": 1})


class TestDiff(unittest.TestCase):
    def test_mapping_diff(self):
        store = DatasetVersion("x")
        store.commit({"a": 1, "b": 2}, 0)
        store.commit({"a": 1, "b": 3, "c": 4}, 1)
        d = store.diff(0, 1)
        self.assertEqual(d.added, ("c",))
        self.assertEqual(d.removed, ())
        self.assertEqual(len(d.changed), 1)
        self.assertEqual(d.changed[0].key, "b")
        self.assertEqual(d.changed[0].old, 2)
        self.assertEqual(d.changed[0].new, 3)
        self.assertFalse(d.is_empty())
        self.assertTrue(d.digest.startswith("sha256:"))

    def test_mapping_removed(self):
        store = DatasetVersion("x")
        store.commit({"a": 1, "b": 2}, 0)
        store.commit({"a": 1}, 1)
        d = store.diff(0, 1)
        self.assertEqual(d.removed, ("b",))

    def test_self_diff_empty(self):
        store = DatasetVersion("x")
        store.commit({"a": 1}, 0)
        self.assertTrue(store.diff(0, 0).is_empty())

    def test_sequence_diff(self):
        store = DatasetVersion("x")
        store.commit([1, 2, 3], 0)
        store.commit([1, 9, 3, 4], 1)
        d = store.diff(0, 1)
        self.assertEqual(d.changed_indices, (1,))
        self.assertEqual(d.appended, (3,))
        self.assertEqual(d.truncated, ())

    def test_sequence_truncated(self):
        store = DatasetVersion("x")
        store.commit([1, 2, 3], 0)
        store.commit([1, 2], 1)
        d = store.diff(0, 1)
        self.assertEqual(d.truncated, (2,))
        self.assertEqual(d.appended, ())

    def test_shape_mismatch_refused(self):
        store = DatasetVersion("x")
        store.commit({"a": 1}, 0)
        store.commit([1], 1)
        with self.assertRaises(DatasetVersionError):
            store.diff(0, 1)

    def test_diff_unknown_version(self):
        store = DatasetVersion("x")
        store.commit({"a": 1}, 0)
        with self.assertRaises(UnknownVersionError):
            store.diff(0, 5)

    def test_diff_record_shape(self):
        store = DatasetVersion("x")
        store.commit({"a": 1}, 0)
        store.commit({"a": 2}, 1)
        d = store.diff(0, 1)
        self.assertEqual(d.as_dict()["schema"], "northstar.dataset-version.v1")
        self.assertEqual(d.from_version, 0)
        self.assertEqual(d.to_version, 1)

    def test_diff_reversed(self):
        store = DatasetVersion("x")
        store.commit({"a": 1}, 0)
        store.commit({"a": 1, "b": 2}, 1)
        d = store.diff(1, 0)
        self.assertEqual(d.removed, ("b",))


class TestVerify(unittest.TestCase):
    def test_verify_clean(self):
        store = DatasetVersion("x")
        store.commit({"a": 1}, 0)
        store.commit([1, 2], 1)
        self.assertTrue(store.verify())

    def test_verify_detects_tamper(self):
        store = DatasetVersion("x")
        store.commit({"a": 1}, 0)
        store._snapshots[0]["a"] = 999
        self.assertFalse(store.verify())


class TestAuditEvent(unittest.TestCase):
    def test_shapes(self):
        ev = dataset_version_audit_event("committed", 3, label="x", version=0,
                                         digest="sha256:abc")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "dataset-version.committed")
        self.assertEqual(ev["seq"], 3)
        self.assertEqual(ev["version"], 0)

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            dataset_version_audit_event("nope", 0)

    def test_bad_seq(self):
        with self.assertRaises(ValueError):
            dataset_version_audit_event("committed", -1)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        dv.main()


if __name__ == "__main__":
    unittest.main()
