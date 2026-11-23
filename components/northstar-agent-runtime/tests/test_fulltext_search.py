"""Tests for the fulltext_search module (TF-IDF inverted index)."""

import math
import unittest

from fulltext_search import (
    AUDIT_INDEXED,
    AUDIT_REJECTED,
    AUDIT_SEARCHED,
    FULLTEXT_SEARCH_VERSION,
    SCHEMA_PIN,
    DuplicateDocumentError,
    FulltextError,
    FulltextSearch,
    IndexRecord,
    ScoredDoc,
    SearchResults,
    UnknownDocumentError,
    fulltext_search_audit_event,
)


class VersionPinTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(FULLTEXT_SEARCH_VERSION, "fulltext-search.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.fulltext-search.v1")


class IndexTests(unittest.TestCase):
    def setUp(self):
        self.idx = FulltextSearch()

    def test_index_happy_path(self):
        rec = self.idx.index("d1", "hello world hello", 1)
        self.assertIsInstance(rec, IndexRecord)
        self.assertEqual(rec.doc_id, "d1")
        self.assertEqual(rec.term_count, 3)
        self.assertEqual(rec.unique_terms, 2)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(rec.seq, 1)
        self.assertEqual(len(self.idx), 1)

    def test_index_tokenization_lowercase(self):
        self.idx.index("d1", "Hello WORLD", 1)
        self.assertEqual(self.idx.doc_ids(), ("d1",))
        hits = self.idx.rank("hello", 2)
        self.assertEqual(len(hits), 1)

    def test_index_duplicate_doc_id_refused(self):
        self.idx.index("d1", "one", 1)
        with self.assertRaises(DuplicateDocumentError):
            self.idx.index("d1", "two", 2)

    def test_index_validation(self):
        for bad in ("", 123, None):
            with self.assertRaises(FulltextError):
                self.idx.index(bad, "text", 1)  # type: ignore[arg-type]
        for bad in (True, -1, "x"):
            with self.assertRaises(FulltextError):
                self.idx.index("d", "text", bad)  # type: ignore[arg-type]
        with self.assertRaises(FulltextError):
            self.idx.index("d", 123, 1)  # type: ignore[arg-type]

    def test_index_empty_text_ok(self):
        rec = self.idx.index("d1", "", 1)
        self.assertEqual(rec.term_count, 0)
        self.assertEqual(rec.unique_terms, 0)


class RecordTests(unittest.TestCase):
    def test_record_roundtrip(self):
        idx = FulltextSearch()
        rec = idx.index("d1", "alpha beta alpha", 1)
        view = idx.record("d1")
        self.assertEqual(view.doc_id, "d1")
        self.assertEqual(view.digest, rec.digest)
        self.assertEqual(view.term_count, 3)

    def test_record_unknown(self):
        idx = FulltextSearch()
        with self.assertRaises(UnknownDocumentError):
            idx.record("nope")

    def test_index_record_bad_digest(self):
        with self.assertRaises(FulltextError):
            IndexRecord(
                doc_id="d",
                term_count=1,
                unique_terms=1,
                digest="bogus",
                seq=1,
            )


class RankTests(unittest.TestCase):
    def setUp(self):
        self.idx = FulltextSearch()
        self.idx.index("d1", "the quick brown fox jumps over the lazy dog", 1)
        self.idx.index("d2", "never jump over the lazy dog quickly", 2)
        self.idx.index("d3", "bright vixens jump; dozy fowl quack", 3)

    def test_rare_term_tops(self):
        hits = self.idx.rank("fox", 4)
        self.assertEqual(hits[0].doc_id, "d1")
        self.assertEqual(hits[0].matched_terms, ("fox",))

    def test_tf_breaks_common_term_ties(self):
        ranked = {s.doc_id: s for s in self.idx.rank("the", 5)}
        self.assertEqual(set(ranked), {"d1", "d2"})
        self.assertGreater(ranked["d1"].score, ranked["d2"].score)

    def test_multi_term_sum(self):
        single = {s.doc_id: s for s in self.idx.rank("fox", 5)}
        multi = {s.doc_id: s for s in self.idx.rank("fox dog", 5)}
        self.assertGreater(multi["d1"].score, single["d1"].score)

    def test_no_shared_terms_no_hits(self):
        self.assertEqual(self.idx.rank("zyxwvu", 5), ())

    def test_rank_restricted_doc_ids(self):
        hits = self.idx.rank("jump", 5, doc_ids=["d2", "d3"])
        self.assertEqual({h.doc_id for h in hits}, {"d2", "d3"})

    def test_rank_unknown_doc_id_refused(self):
        with self.assertRaises(UnknownDocumentError):
            self.idx.rank("jump", 5, doc_ids=["d9"])

    def test_rank_deterministic(self):
        a = [h.doc_id for h in self.idx.rank("jump", 5)]
        b = [h.doc_id for h in self.idx.rank("jump", 6)]
        self.assertEqual(a, b)

    def test_rank_scores_finite_nonnegative(self):
        for hit in self.idx.rank("jump lazy fox", 5):
            self.assertTrue(math.isfinite(hit.score))
            self.assertGreaterEqual(hit.score, 0)

    def test_scored_doc_bad_score_refused(self):
        with self.assertRaises(FulltextError):
            ScoredDoc(doc_id="d", score=float("nan"), matched_terms=())

    def test_rank_query_validation(self):
        for bad in ("", "   ", 123):
            with self.assertRaises(FulltextError):
                self.idx.rank(bad, 1)  # type: ignore[arg-type]


class SearchTests(unittest.TestCase):
    def setUp(self):
        self.idx = FulltextSearch()
        self.idx.index("d1", "the quick brown fox", 1)
        self.idx.index("d2", "lazy dog sleeps", 2)

    def test_search_top_k(self):
        res = self.idx.search("fox dog", 3, top_k=1)
        self.assertIsInstance(res, SearchResults)
        self.assertEqual(len(res.hits), 1)
        self.assertEqual(res.total_scored, 2)
        self.assertTrue(res.query_digest.startswith("sha256:"))

    def test_search_top_k_none_all(self):
        res = self.idx.search("fox dog", 3, top_k=None)
        self.assertEqual(len(res.hits), 2)

    def test_search_no_hits(self):
        res = self.idx.search("zyxwvu", 3)
        self.assertEqual(res.hits, ())
        self.assertEqual(res.total_scored, 0)

    def test_search_bad_top_k(self):
        for bad in (0, -1, True, "2"):
            with self.assertRaises(FulltextError):
                self.idx.search("fox", 3, top_k=bad)  # type: ignore[arg-type]

    def test_search_results_bad_digest(self):
        with self.assertRaises(FulltextError):
            SearchResults(
                query="q",
                query_digest="bogus",
                hits=(),
                total_scored=0,
                seq=1,
            )


class AuditTests(unittest.TestCase):
    def test_audit_shapes(self):
        ev = fulltext_search_audit_event(AUDIT_INDEXED, 1, doc_id="d1")
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertEqual(ev["module_version"], FULLTEXT_SEARCH_VERSION)
        self.assertEqual(ev["kind"], AUDIT_INDEXED)
        ev2 = fulltext_search_audit_event(AUDIT_SEARCHED, 2, hits=3)
        self.assertEqual(ev2["kind"], AUDIT_SEARCHED)
        ev3 = fulltext_search_audit_event(AUDIT_REJECTED, 3)
        self.assertEqual(ev3["kind"], AUDIT_REJECTED)

    def test_audit_unknown_kind(self):
        with self.assertRaises(FulltextError):
            fulltext_search_audit_event("bogus-kind", 1)


class MainTests(unittest.TestCase):
    def test_main_self_check(self):
        from fulltext_search import main

        main()  # asserts internally


class AsDictTests(unittest.TestCase):
    def test_record_shapes(self):
        idx = FulltextSearch()
        rec = idx.index("d1", "one two", 1)
        d = rec.as_dict()
        self.assertEqual(d["doc_id"], "d1")
        self.assertEqual(d["version"], FULLTEXT_SEARCH_VERSION)
        self.assertEqual(d["schema"], SCHEMA_PIN)
        res = idx.search("one", 2)
        rd = res.as_dict()
        self.assertEqual(rd["query"], "one")
        self.assertEqual(len(rd["hits"]), 1)
        self.assertEqual(rd["hits"][0]["doc_id"], "d1")
        self.assertIn("matched_terms", rd["hits"][0])


class StdlibOnlyTests(unittest.TestCase):
    def test_ast_stdlib_only(self):
        import ast
        from pathlib import Path

        src = Path(__file__).parent.parent / "fulltext_search.py"
        tree = ast.parse(src.read_text())
        allowed = {
            "hashlib",
            "math",
            "re",
            "dataclasses",
            "typing",
            "__future__",
            "json",
            "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.assertIn(node.module.split(".")[0], allowed)


if __name__ == "__main__":
    unittest.main()
