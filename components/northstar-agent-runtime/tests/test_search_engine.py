"""Targeted tests for the search-engine interface."""

import ast
import unittest
from pathlib import Path

from search_engine import (
    AUDIT_INDEXED,
    AUDIT_QUERY_PARSED,
    AUDIT_RANKED,
    AUDIT_REJECTED,
    AUDIT_SCHEMA,
    SCHEMA_PIN,
    SEARCH_ENGINE_VERSION,
    BadQueryError,
    DuplicateDocumentError,
    SearchEngine,
    SearchEngineError,
    SeqOrderError,
    UnknownDocumentError,
    UnknownQueryError,
    main,
    search_engine_audit_event,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "search_engine.py"

CORPUS = {
    "d1": "the quick brown fox jumps over the lazy dog",
    "d2": "never jump over the lazy dog quickly",
    "d3": "bright vixens jump; dozy fowl quack",
}


def make_engine():
    eng = SearchEngine()
    seq = 0
    for doc_id, text in CORPUS.items():
        seq += 1
        eng.index(doc_id, text, seq)
    return eng, seq


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(SEARCH_ENGINE_VERSION, "search-engine.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.search-engine.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {
            "__future__",
            "hashlib",
            "math",
            "re",
            "threading",
            "dataclasses",
            "typing",
            "canonical_json",
            "json",  # inside the defensive fallback only
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_audit_kinds(self):
        self.assertEqual(
            {AUDIT_INDEXED, AUDIT_QUERY_PARSED, AUDIT_RANKED, AUDIT_REJECTED},
            {"indexed", "query-parsed", "ranked", "rejected"},
        )


class TestIndex(unittest.TestCase):
    def test_index_happy_path(self):
        eng = SearchEngine()
        rec = eng.index("d1", CORPUS["d1"], 1)
        self.assertEqual(rec.doc_id, "d1")
        self.assertEqual(rec.term_count, 9)
        self.assertEqual(rec.unique_terms, 8)  # "the" twice
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(rec.seq, 1)
        self.assertEqual(len(eng), 1)
        self.assertEqual(eng.doc_ids(), ("d1",))

    def test_duplicate_doc_refused(self):
        eng = SearchEngine()
        eng.index("d1", "hello", 1)
        with self.assertRaises(DuplicateDocumentError):
            eng.index("d1", "world", 2)

    def test_failed_mutation_consumes_seq(self):
        eng = SearchEngine()
        eng.index("d1", "hello", 1)
        with self.assertRaises(DuplicateDocumentError):
            eng.index("d1", "world", 2)
        # seq 2 was consumed by the failed duplicate; reusing it fails.
        with self.assertRaises(SeqOrderError):
            eng.index("d2", "world", 2)

    def test_seq_must_strictly_increase(self):
        eng = SearchEngine()
        eng.index("d1", "hello", 5)
        with self.assertRaises(SeqOrderError):
            eng.index("d2", "world", 5)
        with self.assertRaises(SeqOrderError):
            eng.index("d2", "world", 3)

    def test_bad_inputs(self):
        eng = SearchEngine()
        with self.assertRaises(SearchEngineError):
            eng.index("", "hello", 1)
        with self.assertRaises(SearchEngineError):
            eng.index("d1", 123, 1)  # type: ignore[arg-type]
        with self.assertRaises(SearchEngineError):
            eng.index("d1", "hello", True)  # bool seq
        with self.assertRaises(SearchEngineError):
            eng.index("d1", "hello", -1)

    def test_digest_pin_deterministic_across_instances(self):
        e1, e2 = SearchEngine(), SearchEngine()
        r1 = e1.index("d1", CORPUS["d1"], 1)
        r2 = e2.index("d1", CORPUS["d1"], 1)
        self.assertEqual(r1.digest, r2.digest)

    def test_doc_record_unknown(self):
        eng = SearchEngine()
        with self.assertRaises(UnknownDocumentError):
            eng.doc_record("nope")


class TestQueryParse(unittest.TestCase):
    def test_single_term(self):
        eng = SearchEngine()
        rec = eng.query("fox", 1)
        self.assertEqual(rec.query_id, "q-1")
        self.assertEqual(rec.query, "fox")
        self.assertEqual(tuple(rec.plan_json), ("TERM", "fox"))
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_query_ids_monotonic(self):
        eng = SearchEngine()
        self.assertEqual(eng.query("a", 1).query_id, "q-1")
        self.assertEqual(eng.query("b", 2).query_id, "q-2")
        self.assertEqual(eng.query_ids(), ("q-1", "q-2"))

    def test_implicit_and(self):
        eng = SearchEngine()
        rec = eng.query("fox dog", 1)
        self.assertEqual(
            list(rec.plan_json),
            ["AND", [["TERM", "fox"], ["TERM", "dog"]]],
        )

    def test_explicit_and_or(self):
        eng = SearchEngine()
        rec = eng.query("fox AND dog OR cat", 1)
        self.assertEqual(
            list(rec.plan_json),
            [
                "OR",
                [
                    ["AND", [["TERM", "fox"], ["TERM", "dog"]]],
                    ["TERM", "cat"],
                ],
            ],
        )

    def test_precedence_not_over_and_over_or(self):
        eng = SearchEngine()
        rec = eng.query("NOT fox AND dog", 1)
        self.assertEqual(
            list(rec.plan_json),
            [
                "AND",
                [
                    ["NOT", ["TERM", "fox"]],
                    ["TERM", "dog"],
                ],
            ],
        )

    def test_minus_shorthand(self):
        eng = SearchEngine()
        rec = eng.query("-fox", 1)
        self.assertEqual(list(rec.plan_json), ["NOT", ["TERM", "fox"]])

    def test_phrase(self):
        eng = SearchEngine()
        rec = eng.query('"quick brown"', 1)
        self.assertEqual(
            list(rec.plan_json), ["PHRASE", ["quick", "brown"]]
        )

    def test_parens(self):
        eng = SearchEngine()
        rec = eng.query("(fox OR dog) AND cat", 1)
        self.assertEqual(
            list(rec.plan_json),
            [
                "AND",
                [
                    ["OR", [["TERM", "fox"], ["TERM", "dog"]]],
                    ["TERM", "cat"],
                ],
            ],
        )

    def test_operators_case_insensitive(self):
        eng = SearchEngine()
        rec = eng.query("fox aNd dog oR cat", 1)
        self.assertEqual(rec.plan_json[0], "OR")

    def test_bad_queries(self):
        eng = SearchEngine()
        for bad in (
            "",
            "   ",
            '"unterminated',
            "(fox",
            "fox)",
            "AND",
            "fox AND",
            "fox OR",
            '" "',
            "fox ) (",
        ):
            # Empty strings fail input validation; the rest fail parsing.
            # Both are fail-closed SearchEngineError refusals.
            with self.assertRaises(SearchEngineError, msg=bad):
                eng.query(bad, 1)

    def test_failed_query_consumes_seq(self):
        eng = SearchEngine()
        with self.assertRaises(BadQueryError):
            eng.query("(oops", 1)
        with self.assertRaises(SeqOrderError):
            eng.query("fox", 1)

    def test_unknown_query_record(self):
        eng = SearchEngine()
        with self.assertRaises(UnknownQueryError):
            eng.query_record("q-99")


class TestRank(unittest.TestCase):
    def test_term_rank_bm25_orders_by_tf(self):
        eng, _ = make_engine()
        q = eng.query("the", 10)
        res = eng.rank(q.query_id, 11)
        by_id = {h.doc_id: h for h in res.hits}
        self.assertEqual(set(by_id), {"d1", "d2"})
        # d1 has tf=2, d2 has tf=1 -> d1 outranks d2.
        self.assertGreater(by_id["d1"].score, by_id["d2"].score)
        for h in res.hits:
            self.assertGreaterEqual(h.score, 0)
            self.assertEqual(h.matched_terms, ("the",))
        self.assertEqual(res.query_digest, q.digest)
        self.assertEqual(res.total_matched, 2)

    def test_phrase_matches_consecutive_only(self):
        eng, _ = make_engine()
        q = eng.query('"lazy dog"', 10)
        res = eng.rank(q.query_id, 11)
        # Both d1 and d2 match; d2 is shorter (7 vs 9 tokens) so BM25
        # length normalization ranks it first on equal term frequency.
        self.assertEqual([h.doc_id for h in res.hits], ["d2", "d1"])
        # Non-consecutive order never matches.
        q2 = eng.query('"dog lazy"', 12)
        res2 = eng.rank(q2.query_id, 13)
        self.assertEqual(res2.hits, ())
        self.assertEqual(res2.total_matched, 0)

    def test_not_excludes(self):
        eng, _ = make_engine()
        q = eng.query("jump AND NOT quickly", 10)
        res = eng.rank(q.query_id, 11)
        self.assertEqual([h.doc_id for h in res.hits], ["d3"])

    def test_or_union(self):
        eng, _ = make_engine()
        q = eng.query("fox OR vixens", 10)
        res = eng.rank(q.query_id, 11)
        self.assertEqual(
            {h.doc_id for h in res.hits}, {"d1", "d3"}
        )

    def test_parens_grouping(self):
        eng, _ = make_engine()
        q = eng.query("(fox OR vixens) AND jump", 10)
        res = eng.rank(q.query_id, 11)
        self.assertEqual([h.doc_id for h in res.hits], ["d3"])

    def test_no_match_is_empty_not_error(self):
        eng, _ = make_engine()
        q = eng.query("zyxwvu", 10)
        res = eng.rank(q.query_id, 11)
        self.assertEqual(res.hits, ())
        self.assertEqual(res.total_matched, 0)

    def test_top_k_truncation(self):
        eng, _ = make_engine()
        q = eng.query("lazy dog", 10)
        res = eng.rank(q.query_id, 11, top_k=1)
        self.assertEqual(len(res.hits), 1)
        self.assertEqual(res.total_matched, 2)
        with self.assertRaises(SearchEngineError):
            eng.rank(q.query_id, 12, top_k=0)

    def test_unknown_query_id(self):
        eng, _ = make_engine()
        with self.assertRaises(UnknownQueryError):
            eng.rank("q-99", 11)

    def test_rank_is_deterministic(self):
        eng, _ = make_engine()
        q = eng.query("the", 10)
        first = [h.doc_id for h in eng.rank(q.query_id, 11).hits]
        second = [h.doc_id for h in eng.rank(q.query_id, 12).hits]
        self.assertEqual(first, second)

    def test_rank_seq_is_a_read_not_consumed(self):
        eng, _ = make_engine()
        q = eng.query("the", 10)
        eng.rank(q.query_id, 11)
        eng.rank(q.query_id, 11)  # same seq is fine for reads
        # mutation seqs still advance from the last mutation (10).
        rec = eng.query("fox", 11)
        self.assertEqual(rec.query_id, "q-2")

    def test_scores_finite(self):
        import math

        eng, _ = make_engine()
        q = eng.query("the quick brown", 10)
        res = eng.rank(q.query_id, 11)
        for h in res.hits:
            self.assertTrue(math.isfinite(h.score))
            self.assertGreaterEqual(h.score, 0)


class TestAudit(unittest.TestCase):
    def test_audit_event_shapes(self):
        ev = search_engine_audit_event(AUDIT_INDEXED, 3, doc_id="d1")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["audit_seq"], 3)
        self.assertEqual(ev["kind"], AUDIT_INDEXED)
        self.assertEqual(ev["module_version"], "search-engine.v1")

    def test_unknown_audit_kind(self):
        with self.assertRaises(SearchEngineError):
            search_engine_audit_event("bogus", 1)

    def test_mutations_append_audit_log(self):
        eng = SearchEngine()
        eng.index("d1", "hello world", 1)
        eng.query("hello", 2)
        kinds = [e["kind"] for e in eng.audit_log()]
        self.assertEqual(kinds, [AUDIT_INDEXED, AUDIT_QUERY_PARSED])
        eng.rank("q-1", 3)
        self.assertEqual(eng.audit_log()[-1]["kind"], AUDIT_RANKED)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        main()  # raises on failure


if __name__ == "__main__":
    unittest.main()
