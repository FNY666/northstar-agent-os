"""Tests for vector_db.py: brute-force vector database interface."""

import ast
import math
import threading
import unittest
from pathlib import Path

import vector_db
from vector_db import (
    METRICS,
    VECTOR_DB_SCHEMA,
    VECTOR_DB_VERSION,
    DeleteRecord,
    InvalidIdError,
    InvalidMetricError,
    InvalidVectorError,
    SearchHit,
    SearchResult,
    StoredVector,
    UnknownVectorError,
    UpsertRecord,
    VectorDB,
    VectorDBError,
    vector_db_audit_event,
)


class PinsTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(VECTOR_DB_VERSION, "vector-db.v1")

    def test_schema_pin(self):
        self.assertEqual(VECTOR_DB_SCHEMA, "northstar.vector-db.v1")

    def test_metrics(self):
        self.assertEqual(METRICS, ("cosine", "euclidean", "dot"))


class ConstructorTest(unittest.TestCase):
    def test_happy_path(self):
        db = VectorDB(4)
        self.assertEqual(db.dim, 4)
        self.assertEqual(db.size(), 0)
        self.assertEqual(db.ids(), ())

    def test_bad_dim(self):
        for bad in (0, -3, True, 1.5, "4", None):
            with self.assertRaises(VectorDBError, msg=f"dim={bad!r}"):
                VectorDB(bad)


class UpsertTest(unittest.TestCase):
    def setUp(self):
        self.db = VectorDB(2)

    def test_happy_path(self):
        rec = self.db.upsert("a", (1.0, 0.0), 0)
        self.assertIsInstance(rec, UpsertRecord)
        self.assertFalse(rec.replaced)
        self.assertEqual(rec.vector_id, "a")
        self.assertEqual(rec.dim, 2)
        self.assertEqual(rec.seq, 0)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(self.db.size(), 1)
        self.assertEqual(self.db.ids(), ("a",))

    def test_replace(self):
        self.db.upsert("a", (1.0, 0.0), 0)
        rec = self.db.upsert("a", (0.0, 1.0), 1)
        self.assertTrue(rec.replaced)
        self.assertEqual(self.db.size(), 1)
        self.assertEqual(self.db.get("a").vector, (0.0, 1.0))

    def test_digest_deterministic(self):
        a = self.db.upsert("x", (1.0, 2.0), 0)
        b = VectorDB(2).upsert("x", (1.0, 2.0), 9)
        self.assertEqual(a.digest, b.digest)

    def test_int_components_accepted(self):
        rec = self.db.upsert("i", (1, 0), 0)
        self.assertEqual(self.db.get("i").vector, (1.0, 0.0))
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_bad_ids(self):
        for bad in ("", True, 5, None, b"a"):
            with self.assertRaises(InvalidIdError, msg=f"id={bad!r}"):
                self.db.upsert(bad, (1.0, 0.0), 0)

    def test_bad_vectors(self):
        cases = [
            (1.0, 0.0, 0.0),          # wrong dim
            (1.0,),                    # wrong dim
            (float("nan"), 0.0),       # NaN
            (float("inf"), 0.0),       # inf
            (True, 0.0),               # bool component
            ("1", 0.0),                # str component
            ("ab",),                   # str vector of wrong dim
            (0.0, 0.0),                # zero vector
            (None, 0.0),               # None component
        ]
        for bad in cases:
            with self.assertRaises(InvalidVectorError, msg=f"vector={bad!r}"):
                self.db.upsert("x", bad, 0)
        with self.assertRaises(InvalidVectorError):
            self.db.upsert("x", "ab", 0)  # str is not a vector
        with self.assertRaises(InvalidVectorError):
            self.db.upsert("x", None, 0)

    def test_bad_seq(self):
        for bad in (True, -1, 1.5, "0"):
            with self.assertRaises(VectorDBError, msg=f"seq={bad!r}"):
                self.db.upsert("x", (1.0, 0.0), bad)

    def test_metadata_stored_and_isolated(self):
        meta = {"source": "doc1", "page": 3}
        self.db.upsert("m", (1.0, 0.0), 0, metadata=meta)
        meta["source"] = "MUTATED"  # caller mutation must not leak in
        got = self.db.get("m")
        self.assertEqual(got.metadata, {"source": "doc1", "page": 3})
        got.metadata["source"] = "MUTATED2"  # returned copy is detached
        self.assertEqual(self.db.get("m").metadata["source"], "doc1")

    def test_bad_metadata(self):
        with self.assertRaises(VectorDBError):
            self.db.upsert("x", (1.0, 0.0), 0, metadata="nope")
        with self.assertRaises(VectorDBError):
            self.db.upsert("x", (1.0, 0.0), 0, metadata={"k": float("nan")})
        with self.assertRaises(VectorDBError):
            self.db.upsert("x", (1.0, 0.0), 0, metadata={"k": True})
        with self.assertRaises(VectorDBError):
            self.db.upsert("x", (1.0, 0.0), 0, metadata={"": 1})


class SearchTest(unittest.TestCase):
    def setUp(self):
        self.db = VectorDB(2)
        self.db.upsert("a", (1.0, 0.0), 0)
        self.db.upsert("b", (0.0, 1.0), 1)
        self.db.upsert("c", (1.0, 1.0), 2)

    def test_cosine_exact_scores(self):
        res = self.db.search((1.0, 0.0), 3, 0)
        self.assertIsInstance(res, SearchResult)
        self.assertEqual(res.metric, "cosine")
        self.assertEqual(res.k, 3)
        self.assertEqual([h.vector_id for h in res.hits], ["a", "c", "b"])
        self.assertEqual(res.hits[0].score, 1.0)
        self.assertAlmostEqual(res.hits[1].score, 1 / math.sqrt(2))
        self.assertEqual(res.hits[2].score, 0.0)
        self.assertEqual([h.rank for h in res.hits], [0, 1, 2])

    def test_k_clamps_to_size(self):
        res = self.db.search((1.0, 0.0), 100, 0)
        self.assertEqual(len(res.hits), 3)

    def test_k_one(self):
        res = self.db.search((1.0, 0.0), 1, 0)
        self.assertEqual([h.vector_id for h in res.hits], ["a"])

    def test_euclidean_ordering(self):
        res = self.db.search((1.0, 0.0), 3, 0, metric="euclidean")
        # dist: a=0, c=1, b=sqrt(2); scores are negative distances
        self.assertEqual([h.vector_id for h in res.hits], ["a", "c", "b"])
        self.assertEqual(res.hits[0].score, 0.0)
        self.assertEqual(res.hits[1].score, -1.0)

    def test_dot_ordering(self):
        res = self.db.search((2.0, 1.0), 3, 0, metric="dot")
        # a: 2, c: 3, b: 1
        self.assertEqual([h.vector_id for h in res.hits], ["c", "a", "b"])
        self.assertEqual(res.hits[0].score, 3.0)

    def test_tie_break_by_id(self):
        db = VectorDB(2)
        db.upsert("z", (1.0, 0.0), 0)
        db.upsert("m", (1.0, 0.0), 1)
        db.upsert("a", (1.0, 0.0), 2)
        res = db.search((1.0, 0.0), 3, 3)
        self.assertEqual([h.vector_id for h in res.hits], ["a", "m", "z"])

    def test_empty_db(self):
        res = VectorDB(2).search((1.0, 0.0), 5, 0)
        self.assertEqual(res.hits, ())
        self.assertEqual(res.seq, 0)

    def test_bad_query_dim(self):
        with self.assertRaises(InvalidVectorError):
            self.db.search((1.0, 0.0, 0.0), 1, 0)

    def test_zero_query_cosine_rejected(self):
        with self.assertRaises(InvalidVectorError):
            self.db.search((0.0, 0.0), 1, 0, metric="cosine")

    def test_zero_query_euclidean_ok(self):
        res = self.db.search((0.0, 0.0), 1, 0, metric="euclidean")
        # nearest to origin: a and b tie at dist 1 -> id order
        self.assertEqual(res.hits[0].vector_id, "a")

    def test_bad_k(self):
        for bad in (0, -2, True, 1.5):
            with self.assertRaises(VectorDBError, msg=f"k={bad!r}"):
                self.db.search((1.0, 0.0), bad, 0)

    def test_unknown_metric(self):
        with self.assertRaises(InvalidMetricError):
            self.db.search((1.0, 0.0), 1, 0, metric="manhattan")

    def test_hits_frozen(self):
        res = self.db.search((1.0, 0.0), 1, 0)
        hit = res.hits[0]
        self.assertIsInstance(hit, SearchHit)
        with self.assertRaises(Exception):
            hit.score = 0.0
        d = hit.as_dict()
        self.assertEqual(d["schema"], VECTOR_DB_SCHEMA)
        self.assertEqual(d["metric"], "cosine")


class GetDeleteTest(unittest.TestCase):
    def setUp(self):
        self.db = VectorDB(3)
        self.db.upsert("v1", (1.0, 2.0, 3.0), 0, metadata={"n": 1})

    def test_get_roundtrip(self):
        got = self.db.get("v1")
        self.assertIsInstance(got, StoredVector)
        self.assertEqual(got.vector, (1.0, 2.0, 3.0))
        self.assertEqual(got.metadata, {"n": 1})
        self.assertTrue(got.digest.startswith("sha256:"))
        d = got.as_dict()
        self.assertEqual(d["schema"], VECTOR_DB_SCHEMA)

    def test_get_unknown(self):
        with self.assertRaises(UnknownVectorError):
            self.db.get("nope")

    def test_delete_happy_path(self):
        rec = self.db.delete("v1", 5)
        self.assertIsInstance(rec, DeleteRecord)
        self.assertEqual(rec.vector_id, "v1")
        self.assertEqual(rec.seq, 5)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(self.db.size(), 0)
        with self.assertRaises(UnknownVectorError):
            self.db.get("v1")

    def test_delete_unknown_fail_closed(self):
        with self.assertRaises(UnknownVectorError):
            self.db.delete("nope", 0)

    def test_delete_bad_seq(self):
        with self.assertRaises(VectorDBError):
            self.db.delete("v1", True)

    def test_upsert_after_delete(self):
        self.db.delete("v1", 1)
        rec = self.db.upsert("v1", (9.0, 9.0, 9.0), 2)
        self.assertFalse(rec.replaced)
        self.assertEqual(self.db.get("v1").vector, (9.0, 9.0, 9.0))


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.db = VectorDB(2)
        self.db.upsert("a", (1.0, 0.0), 0)

    def test_shapes(self):
        for kind in ("upserted", "deleted", "searched"):
            ev = vector_db_audit_event(kind, self.db, 3)
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["kind"], f"vector-db.{kind}")
            self.assertEqual(ev["module"], VECTOR_DB_SCHEMA)
            self.assertEqual(ev["version"], VECTOR_DB_VERSION)
            self.assertEqual(ev["seq"], 3)
            self.assertEqual(ev["size"], 1)
            self.assertEqual(ev["dim"], 2)

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            vector_db_audit_event("nope", self.db, 0)

    def test_bad_db(self):
        with self.assertRaises(TypeError):
            vector_db_audit_event("upserted", object(), 0)

    def test_bad_seq(self):
        with self.assertRaises(VectorDBError):
            vector_db_audit_event("upserted", self.db, -1)


class ConcurrencyTest(unittest.TestCase):
    def test_concurrent_upserts(self):
        db = VectorDB(2)
        errors = []

        def worker(n):
            try:
                for i in range(20):
                    db.upsert(f"w{n}-{i}", (float(i + 1), float(n + 1)), n * 20 + i)
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(db.size(), 100)


class StdlibOnlyTest(unittest.TestCase):
    def test_stdlib_only(self):
        tree = ast.parse(Path(vector_db.__file__).read_text())
        allowed = {"copy", "hashlib", "math", "threading", "dataclasses", "typing", "__future__"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class MainTest(unittest.TestCase):
    def test_main(self):
        vector_db.main()  # raises on any failed assertion


if __name__ == "__main__":
    unittest.main()
