"""Tests for mvcc_store.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mvcc_store
from mvcc_store import (
    CommitRecord,
    MVCC_VERSION,
    MVCCError,
    MVCCStore,
    ReadResult,
    SCHEMA_PIN,
    Version,
    WriteConflictError,
    mvcc_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(MVCC_VERSION, "mvcc-store.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.mvcc-store.v1")


class TestBegin(unittest.TestCase):
    def test_begin_returns_snapshot_point(self):
        store = MVCCStore()
        self.assertEqual(store.begin("t1"), 0)

    def test_begin_snapshot_advances_with_commits(self):
        store = MVCCStore()
        store.begin("t1")
        store.commit("t1")
        self.assertEqual(store.begin("t2"), 1)

    def test_begin_empty_txn_id(self):
        store = MVCCStore()
        with self.assertRaises(ValueError):
            store.begin("")

    def test_begin_non_str_txn_id(self):
        store = MVCCStore()
        with self.assertRaises(TypeError):
            store.begin(42)

    def test_begin_duplicate_txn_id(self):
        store = MVCCStore()
        store.begin("t1")
        with self.assertRaises(MVCCError):
            store.begin("t1")

    def test_active_txns_view(self):
        store = MVCCStore()
        store.begin("b")
        store.begin("a")
        self.assertEqual(store.active_txns(), ("a", "b"))


class TestWrite(unittest.TestCase):
    def test_write_then_commit_visible(self):
        store = MVCCStore()
        store.begin("t1")
        store.write("k", "v", "t1")
        rec = store.commit("t1")
        self.assertEqual(rec.keys, ("k",))
        self.assertEqual(rec.commit_seq, 1)
        store.begin("t2")
        self.assertEqual(store.read("k", "t2").value, "v")

    def test_write_empty_key(self):
        store = MVCCStore()
        store.begin("t1")
        with self.assertRaises(ValueError):
            store.write("", "v", "t1")

    def test_write_non_str_key(self):
        store = MVCCStore()
        store.begin("t1")
        with self.assertRaises(TypeError):
            store.write(1, "v", "t1")

    def test_write_unknown_txn(self):
        store = MVCCStore()
        with self.assertRaises(MVCCError):
            store.write("k", "v", "nope")

    def test_write_nan_rejected(self):
        store = MVCCStore()
        store.begin("t1")
        with self.assertRaises(TypeError):
            store.write("k", float("nan"), "t1")

    def test_write_inf_rejected(self):
        store = MVCCStore()
        store.begin("t1")
        with self.assertRaises(TypeError):
            store.write("k", float("inf"), "t1")

    def test_write_non_str_dict_key_rejected(self):
        store = MVCCStore()
        store.begin("t1")
        with self.assertRaises(TypeError):
            store.write("k", {1: "x"}, "t1")

    def test_write_arbitrary_object_rejected(self):
        store = MVCCStore()
        store.begin("t1")
        with self.assertRaises(TypeError):
            store.write("k", object(), "t1")

    def test_write_nested_value_ok(self):
        store = MVCCStore()
        store.begin("t1")
        store.write("k", {"a": [1, 2.5, True, None, "s"]}, "t1")
        store.commit("t1")
        store.begin("t2")
        self.assertEqual(
            store.read("k", "t2").value, {"a": [1, 2.5, True, None, "s"]}
        )


class TestRead(unittest.TestCase):
    def test_read_missing_key(self):
        store = MVCCStore()
        store.begin("t1")
        res = store.read("nope", "t1")
        self.assertFalse(res.found)
        self.assertIsNone(res.value)

    def test_read_your_writes(self):
        store = MVCCStore()
        store.begin("t1")
        store.write("k", "uncommitted", "t1")
        res = store.read("k", "t1")
        self.assertTrue(res.found)
        self.assertEqual(res.value, "uncommitted")

    def test_snapshot_isolation_hides_later_commit(self):
        store = MVCCStore()
        store.begin("reader")
        store.begin("writer")
        store.write("k", "new", "writer")
        store.commit("writer")
        self.assertFalse(store.read("k", "reader").found)

    def test_snapshot_isolation_sees_older_commit(self):
        store = MVCCStore()
        store.begin("w1")
        store.write("k", "old", "w1")
        store.commit("w1")
        store.begin("reader")
        store.begin("w2")
        store.write("k", "new", "w2")
        store.commit("w2")
        res = store.read("k", "reader")
        self.assertTrue(res.found)
        self.assertEqual(res.value, "old")
        self.assertEqual(res.commit_seq, 1)

    def test_read_unknown_txn(self):
        store = MVCCStore()
        with self.assertRaises(MVCCError):
            store.read("k", "nope")


class TestConflict(unittest.TestCase):
    def test_first_committer_wins(self):
        store = MVCCStore()
        store.begin("a")
        store.begin("b")
        store.write("k", "from-a", "a")
        store.write("k", "from-b", "b")
        store.commit("a")
        with self.assertRaises(WriteConflictError) as ctx:
            store.commit("b")
        self.assertEqual(ctx.exception.conflicting_keys, ("k",))
        store.begin("r")
        self.assertEqual(store.read("k", "r").value, "from-a")

    def test_conflict_names_multiple_keys(self):
        store = MVCCStore()
        store.begin("a")
        store.begin("b")
        store.write("k1", 1, "a")
        store.write("k2", 2, "a")
        store.write("k1", 10, "b")
        store.write("k2", 20, "b")
        store.commit("a")
        with self.assertRaises(WriteConflictError) as ctx:
            store.commit("b")
        self.assertEqual(ctx.exception.conflicting_keys, ("k1", "k2"))

    def test_non_overlapping_writes_both_commit(self):
        store = MVCCStore()
        store.begin("a")
        store.begin("b")
        store.write("k1", "a", "a")
        store.write("k2", "b", "b")
        store.commit("a")
        rec = store.commit("b")
        self.assertEqual(rec.commit_seq, 2)
        store.begin("r")
        self.assertEqual(store.read("k1", "r").value, "a")
        self.assertEqual(store.read("k2", "r").value, "b")

    def test_conflicted_txn_not_active(self):
        store = MVCCStore()
        store.begin("a")
        store.begin("b")
        store.write("k", 1, "a")
        store.write("k", 2, "b")
        store.commit("a")
        with self.assertRaises(WriteConflictError):
            store.commit("b")
        with self.assertRaises(MVCCError):
            store.commit("b")


class TestAbort(unittest.TestCase):
    def test_abort_discards_writes(self):
        store = MVCCStore()
        store.begin("t1")
        store.write("k", "discarded", "t1")
        store.abort("t1")
        store.begin("r")
        self.assertFalse(store.read("k", "r").found)

    def test_abort_unknown_txn(self):
        store = MVCCStore()
        with self.assertRaises(MVCCError):
            store.abort("nope")

    def test_commit_unknown_txn(self):
        store = MVCCStore()
        with self.assertRaises(MVCCError):
            store.commit("nope")

    def test_double_commit(self):
        store = MVCCStore()
        store.begin("t1")
        store.commit("t1")
        with self.assertRaises(MVCCError):
            store.commit("t1")


class TestRecords(unittest.TestCase):
    def test_frozen_records(self):
        v = Version(key="k", value=1, value_digest="sha256:x",
                    commit_seq=1, txn_id="t")
        with self.assertRaises(Exception):
            v.key = "other"
        r = CommitRecord(txn_id="t", commit_seq=1, keys=("k",))
        with self.assertRaises(Exception):
            r.commit_seq = 2
        rr = ReadResult(value=1, found=True, commit_seq=1, txn_id="t")
        with self.assertRaises(Exception):
            rr.value = 2

    def test_version_digest_pinned(self):
        store = MVCCStore()
        store.begin("t1")
        store.write("k", {"n": 1}, "t1")
        store.commit("t1")
        (v,) = store.versions("k")
        self.assertTrue(v.value_digest.startswith("sha256:"))
        self.assertEqual(len(v.value_digest), len("sha256:") + 64)

    def test_versions_view(self):
        store = MVCCStore()
        for i, txn in enumerate(("a", "b")):
            store.begin(txn)
            store.write("k", i, txn)
            store.commit(txn)
        versions = store.versions("k")
        self.assertEqual(len(versions), 2)
        self.assertEqual([v.commit_seq for v in versions], [1, 2])
        self.assertEqual(store.versions("missing"), ())

    def test_as_dict_schema(self):
        v = Version(key="k", value=1, value_digest="sha256:x",
                    commit_seq=1, txn_id="t")
        self.assertEqual(v.as_dict()["schema"], SCHEMA_PIN)
        r = CommitRecord(txn_id="t", commit_seq=1, keys=("k",))
        self.assertEqual(r.as_dict()["schema"], SCHEMA_PIN)


class TestAudit(unittest.TestCase):
    def test_audit_event_shape(self):
        ev = mvcc_audit_event("commit", {"txn_id": "t"}, 3)
        self.assertEqual(ev["event"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "mvcc-commit")
        self.assertEqual(ev["audit_seq"], 3)
        self.assertEqual(ev["schema"], SCHEMA_PIN)

    def test_audit_bad_kind(self):
        with self.assertRaises(ValueError):
            mvcc_audit_event("explode", {}, 0)

    def test_audit_bad_seq(self):
        with self.assertRaises(ValueError):
            mvcc_audit_event("commit", {}, -1)
        with self.assertRaises(ValueError):
            mvcc_audit_event("commit", {}, True)

    def test_audit_bad_record(self):
        with self.assertRaises(TypeError):
            mvcc_audit_event("commit", "not-a-mapping", 0)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        mvcc_store.main()


if __name__ == "__main__":
    unittest.main()
