"""Tests for btree_index.py (B-tree ordered key-value index)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from btree_index import (  # noqa: E402
    AUDIT_KINDS,
    BTREE_INDEX_VERSION,
    SCHEMA_PIN,
    BTree,
    BTreeEntry,
    BTreeError,
    btree_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(BTREE_INDEX_VERSION, "btree-index.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.btree-index.v1")

    def test_audit_kinds_fixed(self):
        self.assertEqual(AUDIT_KINDS, ("insert", "delete", "search", "range-query"))


class TestConstructor(unittest.TestCase):
    def test_default_min_degree(self):
        tree = BTree()
        tree.insert(1, "a")
        self.assertEqual(tree.search(1), "a")

    def test_min_degree_one_rejected(self):
        with self.assertRaises(BTreeError):
            BTree(min_degree=1)

    def test_min_degree_zero_rejected(self):
        with self.assertRaises(BTreeError):
            BTree(min_degree=0)

    def test_min_degree_bool_rejected(self):
        with self.assertRaises(BTreeError):
            BTree(min_degree=True)

    def test_min_degree_str_rejected(self):
        with self.assertRaises(BTreeError):
            BTree(min_degree="2")

    def test_empty_tree(self):
        tree = BTree()
        self.assertEqual(len(tree), 0)
        self.assertEqual(tree.height(), 0)
        self.assertEqual(tree.keys(), ())
        self.assertEqual(tree.items(), ())


class TestInsertSearch(unittest.TestCase):
    def test_insert_search_roundtrip(self):
        tree = BTree()
        tree.insert(10, "ten")
        self.assertEqual(tree.search(10), "ten")

    def test_search_missing_returns_none(self):
        tree = BTree()
        tree.insert(1, "a")
        self.assertIsNone(tree.search(999))

    def test_search_empty_tree(self):
        tree = BTree()
        self.assertIsNone(tree.search(1))

    def test_duplicate_replaces_value(self):
        tree = BTree()
        tree.insert(1, "old")
        tree.insert(1, "new")
        self.assertEqual(tree.search(1), "new")
        self.assertEqual(len(tree), 1)

    def test_contains(self):
        tree = BTree()
        tree.insert(7, "x")
        self.assertIn(7, tree)
        self.assertNotIn(8, tree)

    def test_descending_inserts_stay_ordered(self):
        tree = BTree()
        for k in range(20, 0, -1):
            tree.insert(k, k * 2)
        self.assertEqual(tree.keys(), tuple(range(1, 21)))

    def test_many_inserts_all_searchable(self):
        tree = BTree(min_degree=2)
        for k in range(200):
            tree.insert(k, f"v{k}")
        self.assertEqual(len(tree), 200)
        self.assertGreater(tree.height(), 1)
        for k in range(200):
            self.assertEqual(tree.search(k), f"v{k}")

    def test_str_keys(self):
        tree = BTree()
        for k in ("delta", "alpha", "charlie", "bravo"):
            tree.insert(k, k.upper())
        self.assertEqual(tree.keys(), ("alpha", "bravo", "charlie", "delta"))
        self.assertEqual(tree.search("bravo"), "BRAVO")

    def test_mixed_key_types_rejected(self):
        tree = BTree()
        tree.insert(1, "int-tree")
        with self.assertRaises(BTreeError):
            tree.insert("two", "str-key")
        with self.assertRaises(BTreeError):
            tree.search("two")

    def test_bool_key_rejected(self):
        tree = BTree()
        with self.assertRaises(BTreeError):
            tree.insert(True, "nope")

    def test_float_key_rejected(self):
        tree = BTree()
        with self.assertRaises(BTreeError):
            tree.insert(1.5, "nope")

    def test_len_tracks_inserts(self):
        tree = BTree()
        for k in range(5):
            tree.insert(k, k)
        self.assertEqual(len(tree), 5)


class TestDelete(unittest.TestCase):
    def test_delete_existing(self):
        tree = BTree()
        tree.insert(1, "a")
        self.assertTrue(tree.delete(1))
        self.assertIsNone(tree.search(1))
        self.assertEqual(len(tree), 0)

    def test_delete_missing_returns_false(self):
        tree = BTree()
        tree.insert(1, "a")
        self.assertFalse(tree.delete(2))
        self.assertEqual(len(tree), 1)

    def test_delete_empty_tree(self):
        tree = BTree()
        self.assertFalse(tree.delete(1))

    def test_delete_many_down_to_empty(self):
        tree = BTree(min_degree=2)
        for k in range(100):
            tree.insert(k, k)
        for k in range(100):
            self.assertTrue(tree.delete(k))
        self.assertEqual(len(tree), 0)
        self.assertEqual(tree.keys(), ())
        for k in range(100):
            self.assertIsNone(tree.search(k))

    def test_delete_reinsert(self):
        tree = BTree()
        tree.insert(1, "a")
        self.assertTrue(tree.delete(1))
        tree.insert(1, "b")
        self.assertEqual(tree.search(1), "b")
        self.assertEqual(len(tree), 1)

    def test_delete_intermixed_with_search(self):
        tree = BTree(min_degree=3)
        keys = list(range(50))
        for k in keys:
            tree.insert(k, k)
        for k in keys[::2]:  # delete evens
            self.assertTrue(tree.delete(k))
        for k in keys:
            if k % 2 == 0:
                self.assertIsNone(tree.search(k))
            else:
                self.assertEqual(tree.search(k), k)
        self.assertEqual(len(tree), 25)


class TestRangeQuery(unittest.TestCase):
    def test_range_basic(self):
        tree = BTree()
        for k in range(10):
            tree.insert(k, f"v{k}")
        got = tree.range_query(3, 6)
        self.assertEqual([e.key for e in got], [3, 4, 5, 6])
        self.assertEqual([e.value for e in got], ["v3", "v4", "v5", "v6"])

    def test_range_single_key(self):
        tree = BTree()
        tree.insert(5, "five")
        got = tree.range_query(5, 5)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].key, 5)

    def test_range_no_hits(self):
        tree = BTree()
        for k in range(10):
            tree.insert(k, k)
        self.assertEqual(tree.range_query(50, 60), ())

    def test_range_empty_tree(self):
        tree = BTree()
        self.assertEqual(tree.range_query(0, 100), ())

    def test_range_start_gt_end_rejected(self):
        tree = BTree()
        tree.insert(1, "a")
        with self.assertRaises(BTreeError):
            tree.range_query(9, 1)

    def test_range_mixed_bound_types_rejected(self):
        tree = BTree()
        with self.assertRaises(BTreeError):
            tree.range_query(1, "z")

    def test_range_bound_type_mismatch_tree_rejected(self):
        tree = BTree()
        tree.insert(1, "int-tree")
        with self.assertRaises(BTreeError):
            tree.range_query("a", "z")

    def test_range_str_keys(self):
        tree = BTree()
        for k in ("a", "b", "c", "d"):
            tree.insert(k, k)
        got = tree.range_query("b", "c")
        self.assertEqual([e.key for e in got], ["b", "c"])

    def test_range_entries_are_frozen_records(self):
        tree = BTree()
        tree.insert(1, "a")
        entry = tree.range_query(1, 1)[0]
        self.assertIsInstance(entry, BTreeEntry)
        self.assertEqual(entry.as_dict()["schema"], SCHEMA_PIN)
        with self.assertRaises(Exception):
            entry.key = 2  # frozen


class TestAuditEvent(unittest.TestCase):
    def test_all_kinds(self):
        for kind in AUDIT_KINDS:
            ev = btree_audit_event(kind, 42, 7)
            self.assertEqual(ev["kind"], kind)
            self.assertEqual(ev["key"], 42)
            self.assertEqual(ev["audit_seq"], 7)
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["module"], SCHEMA_PIN)

    def test_bad_kind_rejected(self):
        with self.assertRaises(BTreeError):
            btree_audit_event("nuke", 1, 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(BTreeError):
            btree_audit_event("insert", 1, -1)
        with self.assertRaises(BTreeError):
            btree_audit_event("insert", 1, True)

    def test_bad_key_rejected(self):
        with self.assertRaises(BTreeError):
            btree_audit_event("insert", 1.5, 0)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        from btree_index import main

        main()


if __name__ == "__main__":
    unittest.main()
