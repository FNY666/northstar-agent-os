"""Tests for lsm_tree.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lsm_tree import (  # noqa: E402
    LSM_TREE_VERSION,
    SCHEMA_PIN,
    LSMTree,
    LSMTreeError,
    SSTable,
    CompactionReport,
    TreeStats,
    lsm_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(LSM_TREE_VERSION, "lsm-tree.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.lsm-tree.v1")


class TestConstructorValidation(unittest.TestCase):
    def test_bad_threshold(self):
        for bad in (0, -1, True, "3", 2.5, None):
            with self.assertRaises(LSMTreeError, msg=f"threshold={bad!r}"):
                LSMTree(memtable_entry_threshold=bad)

    def test_threshold_one(self):
        tree = LSMTree(memtable_entry_threshold=1)
        tree.put("a", "v")
        # threshold 1 flushes immediately
        self.assertEqual(len(tree._sstables), 1)


class TestPutGet(unittest.TestCase):
    def test_roundtrip(self):
        tree = LSMTree()
        tree.put("k", "v")
        self.assertEqual(tree.get("k"), b"v")

    def test_bytes_value(self):
        tree = LSMTree()
        tree.put("k", b"\x00\x01")
        self.assertEqual(tree.get("k"), b"\x00\x01")

    def test_missing_key(self):
        tree = LSMTree()
        self.assertIsNone(tree.get("nope"))

    def test_overwrite_keeps_newest(self):
        tree = LSMTree()
        tree.put("k", "old")
        tree.put("k", "new")
        self.assertEqual(tree.get("k"), b"new")

    def test_empty_key_rejected(self):
        tree = LSMTree()
        with self.assertRaises(LSMTreeError):
            tree.put("", "v")
        with self.assertRaises(LSMTreeError):
            tree.get("")

    def test_non_str_key_rejected(self):
        tree = LSMTree()
        for bad in (123, b"k", None, True):
            with self.assertRaises(LSMTreeError, msg=f"key={bad!r}"):
                tree.put(bad, "v")
            with self.assertRaises(LSMTreeError, msg=f"key={bad!r}"):
                tree.get(bad)

    def test_bad_value_rejected(self):
        tree = LSMTree()
        for bad in (123, None, True, ["v"], {"v": 1}):
            with self.assertRaises(LSMTreeError, msg=f"value={bad!r}"):
                tree.put("k", bad)


class TestDelete(unittest.TestCase):
    def test_delete_hides_value(self):
        tree = LSMTree()
        tree.put("k", "v")
        tree.delete("k")
        self.assertIsNone(tree.get("k"))

    def test_delete_missing_key_is_idempotent(self):
        tree = LSMTree()
        tree.delete("ghost")  # no error
        self.assertIsNone(tree.get("ghost"))

    def test_put_after_delete_resurrects(self):
        tree = LSMTree()
        tree.put("k", "v1")
        tree.delete("k")
        tree.put("k", "v2")
        self.assertEqual(tree.get("k"), b"v2")


class TestFlush(unittest.TestCase):
    def test_threshold_triggers_flush(self):
        tree = LSMTree(memtable_entry_threshold=2)
        tree.put("a", "1")
        self.assertEqual(len(tree._sstables), 0)
        tree.put("b", "2")
        self.assertEqual(len(tree._sstables), 1)

    def test_get_after_flush_reads_sstable(self):
        tree = LSMTree(memtable_entry_threshold=2)
        tree.put("a", "1")
        tree.put("b", "2")  # flush
        self.assertEqual(tree.get("a"), b"1")
        self.assertEqual(tree.get("b"), b"2")

    def test_tombstone_in_memtable_hides_flushed_value(self):
        tree = LSMTree(memtable_entry_threshold=2)
        tree.put("a", "1")
        tree.put("b", "2")  # flush
        tree.delete("a")  # tombstone in memtable
        self.assertIsNone(tree.get("a"))

    def test_manual_flush_empty(self):
        tree = LSMTree()
        self.assertIsNone(tree.flush())

    def test_sstable_sorted_and_digest_pinned(self):
        tree = LSMTree(memtable_entry_threshold=3)
        tree.put("c", "3")
        tree.put("a", "1")
        tree.put("b", "2")  # flush
        table = tree._sstables[0]
        keys = [k for k, _ in table.entries]
        self.assertEqual(keys, ["a", "b", "c"])
        self.assertTrue(table.digest.startswith("sha256:"))
        self.assertIsInstance(table, SSTable)


class TestCompact(unittest.TestCase):
    def test_compact_empty_tree(self):
        tree = LSMTree()
        report = tree.compact(seq=0)
        self.assertIsInstance(report, CompactionReport)
        self.assertEqual(report.tables_merged, 0)
        self.assertEqual(report.live_keys, 0)

    def test_compact_merges_and_drops_tombstones(self):
        tree = LSMTree(memtable_entry_threshold=2)
        tree.put("a", "1")
        tree.put("b", "2")  # flush -> sstable-1
        tree.put("a", "3")  # overwrite in memtable
        tree.delete("b")  # tombstone in memtable -> flush -> sstable-2
        tree.put("c", "4")
        tree.put("d", "5")  # flush -> sstable-3
        report = tree.compact(seq=7)
        self.assertEqual(report.tables_merged, 3)
        self.assertEqual(report.live_keys, 3)  # a, c, d
        self.assertEqual(report.tombstones_dropped, 1)  # b
        self.assertEqual(report.seq, 7)
        self.assertEqual(len(tree._sstables), 1)
        self.assertEqual(tree.get("a"), b"3")
        self.assertIsNone(tree.get("b"))

    def test_compact_bad_seq_rejected(self):
        tree = LSMTree()
        for bad in (-1, True, "1", None):
            with self.assertRaises(LSMTreeError, msg=f"seq={bad!r}"):
                tree.compact(seq=bad)


class TestRecordsAndAudit(unittest.TestCase):
    def test_frozen_records(self):
        tree = LSMTree(memtable_entry_threshold=2)
        tree.put("a", "1")
        tree.put("b", "2")
        table = tree._sstables[0]
        with self.assertRaises(Exception):
            table.table_id = "x"  # frozen
        report = tree.compact(seq=0)
        with self.assertRaises(Exception):
            report.live_keys = 99  # frozen

    def test_stats(self):
        tree = LSMTree(memtable_entry_threshold=2)
        tree.put("a", "1")
        tree.put("b", "2")  # flush
        tree.get("a")
        stats = tree.stats()
        self.assertIsInstance(stats, TreeStats)
        self.assertEqual(stats.puts, 2)
        self.assertEqual(stats.gets, 1)
        self.assertEqual(stats.flushes, 1)
        self.assertEqual(stats.sstable_count, 1)
        self.assertEqual(stats.as_dict()["schema"], SCHEMA_PIN)

    def test_audit_event_shapes(self):
        event = lsm_audit_event("put", 3, {"key": "k"})
        self.assertEqual(event["kind"], "lsm-put")
        self.assertEqual(event["audit_seq"], 3)
        self.assertEqual(event["detail"], {"key": "k"})
        for kind in ("put", "delete", "get", "flush", "compact"):
            self.assertEqual(lsm_audit_event(kind, 0)["kind"], f"lsm-{kind}")
        with self.assertRaises(LSMTreeError):
            lsm_audit_event("drop-table", 0)
        with self.assertRaises(LSMTreeError):
            lsm_audit_event("put", -1)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import lsm_tree

        lsm_tree.main()  # should not raise


if __name__ == "__main__":
    unittest.main()
