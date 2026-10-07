"""Targeted tests for the document_store module (batch 17)."""

import ast
import copy
import unittest
from pathlib import Path

from document_store import (
    DOCUMENT_STORE_VERSION,
    SCHEMA_PIN,
    DuplicateKeyError,
    Document,
    DocumentError,
    DocumentStore,
    IndexDefinition,
    IndexError,
    QueryError,
    QueryPlan,
    UniqueViolationError,
    UnknownDocumentError,
    WriteResult,
    document_store_audit_event,
    main,
)


def _fresh() -> DocumentStore:
    return DocumentStore()


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(DOCUMENT_STORE_VERSION, "document-store.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.document-store.v1")

    def test_inserted_document_carries_pins(self):
        store = _fresh()
        r = store.insert({"name": "a"})
        self.assertEqual(r.op, "insert")
        doc = store.get(r.doc_id)
        self.assertEqual(doc.version, DOCUMENT_STORE_VERSION)
        self.assertTrue(doc.digest.startswith("sha256:"))
        self.assertEqual(len(doc.digest), len("sha256:") + 64)


class TestInsert(unittest.TestCase):
    def test_auto_id(self):
        store = _fresh()
        r1 = store.insert({"x": 1})
        r2 = store.insert({"x": 2})
        self.assertEqual(r1.doc_id, "doc-1")
        self.assertEqual(r2.doc_id, "doc-2")
        self.assertNotEqual(r1.doc_id, r2.doc_id)

    def test_explicit_id(self):
        store = _fresh()
        r = store.insert({"_id": "custom", "x": 1})
        self.assertEqual(r.doc_id, "custom")
        self.assertEqual(store.get("custom").payload["x"], 1)

    def test_duplicate_id_refused(self):
        store = _fresh()
        store.insert({"_id": "k", "x": 1})
        with self.assertRaises(DuplicateKeyError):
            store.insert({"_id": "k", "x": 2})

    def test_duplicate_id_state_untouched(self):
        store = _fresh()
        store.insert({"_id": "k", "x": 1})
        with self.assertRaises(DuplicateKeyError):
            store.insert({"_id": "k", "x": 2})
        self.assertEqual(store.count(), 1)
        self.assertEqual(store.get("k").payload["x"], 1)

    def test_insert_validation(self):
        store = _fresh()
        with self.assertRaises(DocumentError):
            store.insert([("x", 1)])  # not a mapping
        with self.assertRaises(DocumentError):
            store.insert({1: "bad"})  # non-str key
        with self.assertRaises(DocumentError):
            store.insert({"x": float("nan")})  # not canonicalizable
        with self.assertRaises(DocumentError):
            store.insert({"x": b"bytes"})  # not canonicalizable
        with self.assertRaises(DocumentError):
            store.insert({"_id": True, "x": 1})  # bool _id

    def test_insert_deep_copies_caller_payload(self):
        store = _fresh()
        payload = {"nested": {"n": [1, 2]}}
        store.insert({"_id": "c", **payload})
        payload["nested"]["n"].append(3)
        self.assertEqual(store.get("c").payload["nested"]["n"], [1, 2])


class TestFind(unittest.TestCase):
    def _seed(self) -> DocumentStore:
        store = _fresh()
        store.insert({"_id": "a", "name": "alice", "age": 30,
                      "addr": {"city": "gz"}})
        store.insert({"_id": "b", "name": "bob", "age": 25,
                      "addr": {"city": "sz"}})
        store.insert({"_id": "c", "name": "cara", "age": 35})
        return store

    def test_find_all_insertion_order(self):
        store = self._seed()
        self.assertEqual([d.doc_id for d in store.find()], ["a", "b", "c"])

    def test_find_equality(self):
        store = self._seed()
        found = store.find({"name": "bob"})
        self.assertEqual([d.doc_id for d in found], ["b"])

    def test_find_dotted_path(self):
        store = self._seed()
        found = store.find({"addr.city": "sz"})
        self.assertEqual([d.doc_id for d in found], ["b"])

    def test_find_no_match(self):
        store = self._seed()
        self.assertEqual(store.find({"name": "nobody"}), [])

    def test_find_operators(self):
        store = self._seed()
        self.assertEqual(
            sorted(d.doc_id for d in store.find({"age": {"$gte": 30}})), ["a", "c"])
        self.assertEqual(
            [d.doc_id for d in store.find({"age": {"$lt": 30}})], ["b"])
        self.assertEqual(
            sorted(d.doc_id for d in store.find({"name": {"$in": ["bob", "cara"]}})),
            ["b", "c"])
        self.assertEqual(
            sorted(d.doc_id for d in store.find({"name": {"$ne": "alice"}})),
            ["b", "c"])

    def test_find_unknown_operator_refused(self):
        store = self._seed()
        with self.assertRaises(QueryError):
            store.find({"age": {"$regex": "3"}})

    def test_find_bad_in_refused(self):
        store = self._seed()
        with self.assertRaises(QueryError):
            store.find({"age": {"$in": []}})

    def test_find_one(self):
        store = self._seed()
        doc = store.find_one({"age": {"$gt": 20}})
        self.assertIsNotNone(doc)
        self.assertEqual(store.find_one({"name": "nobody"}), None)

    def test_find_deep_copies(self):
        store = self._seed()
        docs = store.find()
        docs[0].payload["name"] = "hacked"
        self.assertEqual(store.get("a").payload["name"], "alice")

    def test_count(self):
        store = self._seed()
        self.assertEqual(store.count(), 3)
        self.assertEqual(store.count({"age": {"$gte": 30}}), 2)


class TestUpdate(unittest.TestCase):
    def test_set_and_inc(self):
        store = _fresh()
        store.insert({"_id": "a", "n": 1})
        r = store.update({"_id": "a"}, {"$set": {"s": "x"}, "$inc": {"n": 4}})
        self.assertEqual((r.matched, r.modified), (1, 1))
        self.assertEqual(store.get("a").payload, {"_id": "a", "n": 5, "s": "x"})

    def test_inc_missing_field_starts_at_zero(self):
        store = _fresh()
        store.insert({"_id": "a"})
        store.update({"_id": "a"}, {"$inc": {"n": 2}})
        self.assertEqual(store.get("a").payload["n"], 2)

    def test_unset(self):
        store = _fresh()
        store.insert({"_id": "a", "x": 1, "y": 2})
        r = store.update({"_id": "a"}, {"$unset": {"x": ""}})
        self.assertEqual(r.modified, 1)
        self.assertNotIn("x", store.get("a").payload)
        self.assertIn("y", store.get("a").payload)

    def test_unset_missing_field_no_modify(self):
        store = _fresh()
        store.insert({"_id": "a", "x": 1})
        r = store.update({"_id": "a"}, {"$unset": {"nope": ""}})
        self.assertEqual((r.matched, r.modified), (1, 0))

    def test_dotted_set(self):
        store = _fresh()
        store.insert({"_id": "a"})
        store.update({"_id": "a"}, {"$set": {"addr.city": "gz"}})
        self.assertEqual(store.get("a").payload["addr"]["city"], "gz")

    def test_update_no_match(self):
        store = _fresh()
        r = store.update({"name": "ghost"}, {"$set": {"x": 1}})
        self.assertEqual((r.matched, r.modified), (0, 0))

    def test_update_multi(self):
        store = _fresh()
        store.insert({"g": 1, "v": 0})
        store.insert({"g": 1, "v": 0})
        store.insert({"g": 2, "v": 0})
        r = store.update({"g": 1}, {"$inc": {"v": 1}})
        self.assertEqual((r.matched, r.modified), (2, 2))

    def test_bare_replacement_refused(self):
        store = _fresh()
        store.insert({"_id": "a", "x": 1})
        with self.assertRaises(QueryError):
            store.update({"_id": "a"}, {"x": 2})  # no operator: refused

    def test_unknown_operator_refused(self):
        store = _fresh()
        store.insert({"_id": "a", "x": 1})
        with self.assertRaises(QueryError):
            store.update({"_id": "a"}, {"$rename": {"x": "y"}})

    def test_id_immutable(self):
        store = _fresh()
        store.insert({"_id": "a", "x": 1})
        with self.assertRaises(QueryError):
            store.update({"_id": "a"}, {"$set": {"_id": "b"}})
        self.assertIsNotNone(store.get("a"))  # still there

    def test_inc_non_numeric_refused(self):
        store = _fresh()
        store.insert({"_id": "a", "x": "str"})
        with self.assertRaises(QueryError):
            store.update({"_id": "a"}, {"$inc": {"x": 1}})


class TestDelete(unittest.TestCase):
    def test_delete_matching(self):
        store = _fresh()
        store.insert({"_id": "a", "g": 1})
        store.insert({"_id": "b", "g": 1})
        store.insert({"_id": "c", "g": 2})
        r = store.delete({"g": 1})
        self.assertEqual(r.op, "delete")
        self.assertEqual(r.deleted, 2)
        self.assertEqual([d.doc_id for d in store.find()], ["c"])

    def test_delete_no_match(self):
        store = _fresh()
        store.insert({"_id": "a"})
        r = store.delete({"x": "nope"})
        self.assertEqual(r.deleted, 0)
        self.assertEqual(store.count(), 1)

    def test_get_unknown_refused(self):
        store = _fresh()
        with self.assertRaises(UnknownDocumentError):
            store.get("missing")


class TestIndexes(unittest.TestCase):
    def test_create_list_drop(self):
        store = _fresh()
        definition = store.create_index("name")
        self.assertIsInstance(definition, IndexDefinition)
        self.assertEqual(definition.field, "name")
        self.assertFalse(definition.unique)
        self.assertEqual(len(store.list_indexes()), 1)
        store.drop_index(definition.name)
        self.assertEqual(store.list_indexes(), [])
        with self.assertRaises(IndexError):
            store.drop_index(definition.name)

    def test_duplicate_index_name_refused(self):
        store = _fresh()
        store.create_index("name", name="n1")
        with self.assertRaises(IndexError):
            store.create_index("name", name="n1")

    def test_explain_index_scan_vs_collection_scan(self):
        store = _fresh()
        store.insert({"name": "a"})
        plan = store.explain({"name": "a"})
        self.assertIsInstance(plan, QueryPlan)
        self.assertEqual(plan.strategy, "collection-scan")
        store.create_index("name")
        plan = store.explain({"name": "a"})
        self.assertEqual(plan.strategy, "index-scan")
        self.assertIsNotNone(plan.index)

    def test_index_backfill_and_find(self):
        store = _fresh()
        store.insert({"name": "alice"})
        store.insert({"name": "bob"})
        store.insert({})  # doc without the field: skipped by the index
        store.create_index("name")
        self.assertEqual([d.doc_id for d in store.find({"name": "alice"})],
                         ["doc-1"])
        self.assertEqual(store.count({"name": "alice"}), 1)

    def test_index_maintained_on_update(self):
        store = _fresh()
        store.insert({"_id": "a", "name": "alice"})
        store.create_index("name")
        store.update({"_id": "a"}, {"$set": {"name": "alicia"}})
        self.assertEqual(store.find({"name": "alice"}), [])
        self.assertEqual([d.doc_id for d in store.find({"name": "alicia"})], ["a"])

    def test_index_maintained_on_delete(self):
        store = _fresh()
        store.insert({"_id": "a", "name": "alice"})
        store.create_index("name")
        store.delete({"_id": "a"})
        self.assertEqual(store.find({"name": "alice"}), [])

    def test_unique_index_enforced_on_insert(self):
        store = _fresh()
        store.create_index("email", unique=True)
        store.insert({"email": "a@x.io"})
        with self.assertRaises(UniqueViolationError):
            store.insert({"email": "a@x.io"})
        self.assertEqual(store.count(), 1)

    def test_unique_index_enforced_on_update(self):
        store = _fresh()
        store.create_index("email", unique=True)
        store.insert({"_id": "a", "email": "a@x.io"})
        store.insert({"_id": "b"})
        with self.assertRaises(UniqueViolationError):
            store.update({"_id": "b"}, {"$set": {"email": "a@x.io"}})
        # failed update rolled back: old index entries intact
        self.assertNotIn("email", store.get("b").payload)
        self.assertEqual([d.doc_id for d in store.find({"email": "a@x.io"})], ["a"])

    def test_unique_index_creation_backfill_refused(self):
        store = _fresh()
        store.insert({"email": "dup@x.io"})
        store.insert({"email": "dup@x.io"})
        with self.assertRaises(UniqueViolationError):
            store.create_index("email", unique=True)
        self.assertEqual(store.list_indexes(), [])

    def test_malformed_index_refused(self):
        store = _fresh()
        with self.assertRaises(QueryError):
            store.create_index("a..b")
        with self.assertRaises(IndexError):
            store.create_index("a", unique="yes")  # type: ignore[arg-type]


class TestAuditAndRecords(unittest.TestCase):
    def test_audit_event_shapes(self):
        for op in ("insert", "update", "delete"):
            event = document_store_audit_event(3, op)
            self.assertEqual(event["version"], SCHEMA_PIN)
            self.assertEqual(event["event"], "document-store")
            self.assertEqual(event["op"], op)
            self.assertEqual(event["audit_seq"], 3)
        r = WriteResult(version=DOCUMENT_STORE_VERSION, op="insert", doc_id="doc-1")
        event = document_store_audit_event(0, "insert", r)
        self.assertEqual(event["result"]["doc_id"], "doc-1")

    def test_audit_event_rejections(self):
        with self.assertRaises(DocumentError):
            document_store_audit_event(-1, "insert")
        with self.assertRaises(DocumentError):
            document_store_audit_event(True, "insert")
        with self.assertRaises(DocumentError):
            document_store_audit_event(0, "drop")

    def test_records_frozen(self):
        store = _fresh()
        doc = store.insert({"x": 1})
        record = store.get(doc.doc_id)
        self.assertIsInstance(record, Document)
        with self.assertRaises(Exception):
            record.digest = "tampered"  # type: ignore[misc]

    def test_stdlib_only(self):
        path = Path(__file__).resolve().parent.parent / "document_store.py"
        tree = ast.parse(path.read_text())
        stdlib = {
            "__future__", "copy", "hashlib", "threading", "dataclasses", "typing",
            "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], stdlib)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], stdlib)

    def test_main_self_check(self):
        main()

    def test_thread_safety(self):
        import threading as th

        store = _fresh()
        errors: List[Exception] = []

        def worker(n: int) -> None:
            try:
                for i in range(25):
                    store.insert({"w": n, "i": i})
                    store.find({"w": n})
                    store.count()
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [th.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(store.count(), 200)


if __name__ == "__main__":
    unittest.main()
