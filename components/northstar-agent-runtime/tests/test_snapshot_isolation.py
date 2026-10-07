"""Tests for snapshot_isolation.py."""

import unittest

from snapshot_isolation import (
    SCHEMA_PIN,
    SNAPSHOT_ISOLATION_VERSION,
    CommitRecord,
    ReadResult,
    SIDatabase,
    SnapshotConflict,
    SnapshotError,
    VersionRecord,
    snapshot_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SNAPSHOT_ISOLATION_VERSION, "snapshot-isolation.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.snapshot-isolation.v1")


class TestBegin(unittest.TestCase):
    def test_begin_start_seq_is_current(self):
        db = SIDatabase()
        self.assertEqual(db.current_seq(), 0)
        txn = db.begin("t1")
        self.assertEqual(txn.start_seq, 0)
        self.assertEqual(txn.txn_id, "t1")
        self.assertFalse(txn.is_closed)

    def test_begin_after_commit_sees_new_seq(self):
        db = SIDatabase()
        t1 = db.begin("t1")
        t1.write("k", 1)
        t1.commit(1)
        t2 = db.begin("t2")
        self.assertEqual(t2.start_seq, 1)

    def test_begin_bad_txn_id(self):
        db = SIDatabase()
        with self.assertRaises(TypeError):
            db.begin(123)
        with self.assertRaises(ValueError):
            db.begin("")


class TestReadWrite(unittest.TestCase):
    def test_read_missing(self):
        db = SIDatabase()
        txn = db.begin("t1")
        got = txn.read("nope")
        self.assertIsInstance(got, ReadResult)
        self.assertFalse(got.found)
        self.assertIsNone(got.value)

    def test_read_your_own_writes(self):
        db = SIDatabase()
        txn = db.begin("t1")
        txn.write("k", "v")
        got = txn.read("k")
        self.assertTrue(got.found)
        self.assertEqual(got.value, "v")

    def test_uncommitted_invisible_to_others(self):
        db = SIDatabase()
        t1 = db.begin("t1")
        t1.write("k", "v")
        t2 = db.begin("t2")
        self.assertFalse(t2.read("k").found)

    def test_delete_stages_tombstone(self):
        db = SIDatabase()
        t1 = db.begin("t1")
        t1.write("k", "v")
        t1.commit(1)
        t2 = db.begin("t2")
        self.assertTrue(t2.read("k").found)
        t2.delete("k")
        self.assertFalse(t2.read("k").found)
        t2.commit(2)
        t3 = db.begin("t3")
        self.assertFalse(t3.read("k").found)

    def test_write_bad_key(self):
        db = SIDatabase()
        txn = db.begin("t1")
        with self.assertRaises(TypeError):
            txn.write(42, "v")
        with self.assertRaises(ValueError):
            txn.write("", "v")
        with self.assertRaises(TypeError):
            txn.read(None)

    def test_write_non_canonicalizable_value_rejected(self):
        db = SIDatabase()
        txn = db.begin("t1")
        with self.assertRaises(ValueError):
            txn.write("k", float("nan"))
        with self.assertRaises(ValueError):
            txn.write("k", {("tuple", "key"): "not-canonicalizable"})

    def test_pending_keys_sorted(self):
        db = SIDatabase()
        txn = db.begin("t1")
        txn.write("b", 1)
        txn.write("a", 2)
        self.assertEqual(txn.pending_keys(), ("a", "b"))


class TestCommit(unittest.TestCase):
    def test_commit_happy_path(self):
        db = SIDatabase()
        txn = db.begin("t1")
        txn.write("k", "v")
        rec = txn.commit(1)
        self.assertIsInstance(rec, CommitRecord)
        self.assertEqual(rec.txn_id, "t1")
        self.assertEqual(rec.commit_seq, 1)
        self.assertEqual(rec.write_keys, ("k",))
        self.assertEqual(rec.start_seq, 0)
        self.assertTrue(txn.is_closed)
        self.assertEqual(db.current_seq(), 1)

    def test_commit_read_only(self):
        db = SIDatabase()
        txn = db.begin("t1")
        rec = txn.commit(1)
        self.assertEqual(rec.write_keys, ())

    def test_commit_seq_must_advance(self):
        db = SIDatabase()
        t1 = db.begin("t1")
        t1.commit(5)
        t2 = db.begin("t2")
        with self.assertRaises(SnapshotError):
            t2.commit(5)
        with self.assertRaises(SnapshotError):
            t2.commit(3)

    def test_commit_bad_seq_type(self):
        db = SIDatabase()
        txn = db.begin("t1")
        with self.assertRaises(TypeError):
            txn.commit(True)
        with self.assertRaises(ValueError):
            txn.commit(-1)

    def test_double_commit_rejected(self):
        db = SIDatabase()
        txn = db.begin("t1")
        txn.commit(1)
        with self.assertRaises(SnapshotError):
            txn.commit(2)

    def test_read_after_close_rejected(self):
        db = SIDatabase()
        txn = db.begin("t1")
        txn.abort()
        with self.assertRaises(SnapshotError):
            txn.read("k")
        with self.assertRaises(SnapshotError):
            txn.write("k", "v")


class TestFirstCommitterWins(unittest.TestCase):
    def test_write_write_conflict(self):
        db = SIDatabase()
        t1 = db.begin("t1")
        t2 = db.begin("t2")
        t1.write("k", "from-t1")
        t2.write("k", "from-t2")
        t1.commit(1)
        with self.assertRaises(SnapshotConflict) as ctx:
            t2.commit(2)
        self.assertEqual(ctx.exception.txn_id, "t2")
        self.assertEqual(ctx.exception.conflicting_keys, ("k",))

    def test_loser_writes_not_applied(self):
        db = SIDatabase()
        t1 = db.begin("t1")
        t2 = db.begin("t2")
        t1.write("k", "winner")
        t2.write("k", "loser")
        t1.commit(1)
        with self.assertRaises(SnapshotConflict):
            t2.commit(2)
        t3 = db.begin("t3")
        self.assertEqual(t3.read("k").value, "winner")

    def test_disjoint_write_sets_no_conflict(self):
        db = SIDatabase()
        t1 = db.begin("t1")
        t2 = db.begin("t2")
        t1.write("a", 1)
        t2.write("b", 2)
        t1.commit(1)
        rec = t2.commit(2)  # no conflict: different keys
        self.assertEqual(rec.write_keys, ("b",))

    def test_read_only_never_conflicts(self):
        db = SIDatabase()
        t1 = db.begin("t1")
        t1.write("k", 1)
        t1.commit(1)
        t2 = db.begin("t2")  # snapshot after t1
        t3 = db.begin("t3")
        t3.write("k", 2)
        t3.commit(2)
        t4 = db.begin("t4")
        t4.write("other", 3)
        t4.commit(3)
        # t2 only read; committing it (even late) cannot conflict
        rec = t2.commit(4)
        self.assertEqual(rec.write_keys, ())

    def test_multi_key_conflict_names_all(self):
        db = SIDatabase()
        t1 = db.begin("t1")
        t2 = db.begin("t2")
        t1.write("b", 1)
        t1.write("a", 1)
        t2.write("a", 2)
        t2.write("b", 2)
        t1.commit(1)
        with self.assertRaises(SnapshotConflict) as ctx:
            t2.commit(2)
        self.assertEqual(ctx.exception.conflicting_keys, ("a", "b"))

    def test_write_skew_is_allowed_and_documented(self):
        # The known SI anomaly: no write-write conflict, both commit.
        db = SIDatabase()
        t1 = db.begin("t1")
        t1.write("x", 50)
        t1.write("y", 50)
        t1.commit(1)
        ta = db.begin("ta")
        tb = db.begin("tb")
        xa = ta.read("x").value
        yb = tb.read("y").value
        ta.write("y", 0)  # withdraw from y after seeing x >= 0
        tb.write("x", 0)  # withdraw from x after seeing y >= 0
        ta.commit(2)
        tb.commit(3)  # no conflict: disjoint write sets
        t = db.begin("t")
        self.assertEqual(t.read("x").value, 0)
        self.assertEqual(t.read("y").value, 0)
        self.assertEqual((xa, yb), (50, 50))


class TestSnapshotVisibility(unittest.TestCase):
    def test_old_snapshot_sees_old_version(self):
        db = SIDatabase()
        t1 = db.begin("t1")
        t1.write("k", "v1")
        t1.commit(1)
        old = db.begin("old")  # snapshot at seq 1
        t2 = db.begin("t2")
        t2.write("k", "v2")
        t2.commit(2)
        self.assertEqual(old.read("k").value, "v1")
        new = db.begin("new")
        self.assertEqual(new.read("k").value, "v2")

    def test_abort_discards_workspace(self):
        db = SIDatabase()
        t1 = db.begin("t1")
        t1.write("k", "v")
        t1.abort()
        self.assertTrue(t1.is_closed)
        t2 = db.begin("t2")
        self.assertFalse(t2.read("k").found)
        self.assertEqual(db.current_seq(), 0)  # abort advances nothing


class TestRecords(unittest.TestCase):
    def test_commit_record_digest_stable(self):
        db = SIDatabase()
        txn = db.begin("t1")
        txn.write("k", "v")
        rec = txn.commit(1)
        self.assertTrue(rec.digest().startswith("sha256:"))
        self.assertEqual(rec.digest(), rec.digest())
        d = rec.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["digest"], rec.digest())

    def test_version_record_as_dict(self):
        rec = VersionRecord(
            key="k", value="v", deleted=False, commit_seq=1, writer_txn_id="t1"
        )
        d = rec.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertTrue(d["value_digest"].startswith("sha256:"))
        self.assertFalse(d["deleted"])

    def test_read_result_as_dict(self):
        got = ReadResult(key="k", found=True, value="v")
        d = got.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertTrue(d["value_digest"].startswith("sha256:"))
        miss = ReadResult(key="k", found=False)
        self.assertIsNone(miss.as_dict()["value_digest"])


class TestAuditEvents(unittest.TestCase):
    def test_audit_event_shapes(self):
        for kind in ("begun", "committed", "aborted", "conflict"):
            ev = snapshot_audit_event(kind, "t1", 7, {"k": "v"})
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["kind"], f"snapshot-isolation.{kind}")
            self.assertEqual(ev["txn_id"], "t1")
            self.assertEqual(ev["audit_seq"], 7)
            self.assertEqual(ev["k"], "v")

    def test_audit_event_bad_kind(self):
        with self.assertRaises(ValueError):
            snapshot_audit_event("exploded", "t1", 1)

    def test_audit_event_bad_seq(self):
        with self.assertRaises(TypeError):
            snapshot_audit_event("begun", "t1", True)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import snapshot_isolation

        snapshot_isolation.main()


if __name__ == "__main__":
    unittest.main()
