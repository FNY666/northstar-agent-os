"""Tests for full_text_search.py (15 tests)."""

import ast
import math
import subprocess
import sys
import threading

import pytest

from full_text_search import (
    AUDIT_FORMAT,
    SCHEMA_PIN,
    FULL_TEXT_SEARCH_VERSION,
    STOP_WORDS,
    EmptyQueryError,
    FullTextSearch,
    FullTextSearchError,
    SeqOrderError,
    UnknownDocumentError,
    UnknownQueryError,
    full_text_search_audit_event,
)


def make_indexed() -> FullTextSearch:
    fts = FullTextSearch()
    fts.index("d1", "the quick brown fox jumps over the lazy dog", 0)
    fts.index("d2", "a quick brown dog barks loudly at night", 1)
    fts.index("d3", "completely unrelated words about plumbing", 2)
    return fts


def test_version_and_schema_pins():
    assert FULL_TEXT_SEARCH_VERSION == "full-text-search.v1"
    assert SCHEMA_PIN == "northstar.full-text-search.v1"
    assert AUDIT_FORMAT == "audit.ndjson/1"
    assert "the" in STOP_WORDS
    fts = FullTextSearch()
    rec = fts.tokenize("hello world", 0)
    assert rec.version == FULL_TEXT_SEARCH_VERSION
    assert rec.schema == SCHEMA_PIN


def test_stdlib_only():
    import full_text_search

    tree = ast.parse(open(full_text_search.__file__).read())
    allowed = {
        "hashlib", "math", "re", "threading", "dataclasses", "typing",
        "canonical_json", "json", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_tokenize_analyzer():
    fts = FullTextSearch()
    rec = fts.tokenize("The QUICK brown fox, fox!", 0)
    # lowercase + stop-word removal ("the" dropped) + length floor
    assert rec.tokens == ("quick", "brown", "fox", "fox")
    assert rec.token_count == 4
    assert rec.tokenize_id == "tok-1"
    assert rec.verify()
    # min-length floor of 2
    rec2 = fts.tokenize("a b c", 1)
    assert rec2.tokens == ()
    assert rec2.verify()


def test_tokenize_bad_inputs():
    fts = FullTextSearch()
    with pytest.raises(FullTextSearchError):
        fts.tokenize(123, 0)  # type: ignore
    with pytest.raises(FullTextSearchError):
        fts.tokenize("x" * (1_048_576 + 1), 1)


def test_index_roundtrip_and_record_verify():
    fts = FullTextSearch()
    rec = fts.index("d1", "fox fox dog", 0)
    assert rec.doc_id == "d1"
    assert dict(rec.term_freqs) == {"fox": 2, "dog": 1}
    assert rec.total_terms == 3
    assert rec.unique_terms == 2
    assert rec.verify()
    assert fts.record("d1").digest == rec.digest
    assert fts.doc_ids() == ("d1",)
    with pytest.raises(UnknownDocumentError):
        fts.record("nope")


def test_index_duplicate_and_bad_inputs():
    fts = FullTextSearch()
    fts.index("d1", "fox", 0)
    with pytest.raises(FullTextSearchError):
        fts.index("d1", "fox", 1)  # duplicate
    with pytest.raises(FullTextSearchError):
        fts.index("", "fox", 2)  # bad doc id
    with pytest.raises(FullTextSearchError):
        fts.index("d2", 42, 3)  # type: ignore # bad text
    # failed mutations consume their seq + book a rejected audit row
    kinds = [e["kind"] for e in fts.audit_log()]
    assert "full-text-search.rejected" in kinds
    fts.index("d9", "fox", 4)  # next fresh seq still works


def test_query_booking_and_empty_refusal():
    fts = make_indexed()
    q = fts.query("quick fox", 3)
    assert q.query_id == "q-1"
    assert q.terms == ("fox", "quick")  # sorted unique
    assert q.term_count == 2
    assert q.verify()
    with pytest.raises(EmptyQueryError):
        fts.query("the and is", 4)  # analyzes to zero terms
    with pytest.raises(UnknownQueryError):
        fts.query_record("q-999")


def test_rank_order_and_coverage():
    fts = make_indexed()
    q = fts.query("quick fox", 3)
    report = fts.rank(q.query_id, 4)
    assert report.verify()
    assert report.total_indexed == 3
    assert [h.doc_id for h in report.hits] == ["d1", "d2"]
    assert report.hits[0].score > report.hits[1].score
    assert report.hits[0].matched_terms == ("fox", "quick")
    assert report.hits[1].matched_terms == ("quick",)
    # deterministic: same corpus, same order across instances
    fts2 = make_indexed()
    q2 = fts2.query("quick fox", 3)
    report2 = fts2.rank(q2.query_id, 4)
    assert [h.doc_id for h in report2.hits] == [h.doc_id for h in report.hits]
    assert [h.score for h in report2.hits] == [h.score for h in report.hits]


def test_rank_top_k_and_no_hits():
    fts = make_indexed()
    q = fts.query("quick", 3)
    report = fts.rank(q.query_id, 4, top_k=1)
    assert len(report.hits) == 1
    q2 = fts.query("plumbing", 5)
    report2 = fts.rank(q2.query_id, 6)
    assert [h.doc_id for h in report2.hits] == ["d3"]
    q3 = fts.query("xylophone", 7)
    report3 = fts.rank(q3.query_id, 8)
    assert report3.hits == ()


def test_seq_ordering_and_rewind():
    fts = FullTextSearch()
    fts.index("d1", "fox", 0)
    with pytest.raises(SeqOrderError):
        fts.index("d2", "fox", 0)  # rewind raises bare, consumes nothing
    fts.index("d2", "fox", 1)  # same seq still usable after bare rewind
    with pytest.raises(FullTextSearchError):
        fts.index("d1", "fox", 1)  # duplicate consumes seq 1
    with pytest.raises(SeqOrderError):
        fts.index("d3", "fox", 1)  # seq 1 was consumed by the failed mutation
    fts.index("d3", "fox", 2)


def test_views_do_not_consume_seq():
    fts = make_indexed()
    stats = fts.stats(3)
    assert stats["documents"] == 3
    assert stats["unique_terms"] > 0
    assert stats["queries"] == 0
    assert stats["version"] == FULL_TEXT_SEARCH_VERSION
    # a pure read with a rewound seq is fine; then a mutation at 3 still works
    fts.stats(0)
    q = fts.query("fox", 3)
    assert q.query_id == "q-1"


def test_audit_shapes_and_boundary():
    fts = make_indexed()
    q = fts.query("fox", 3)
    fts.rank(q.query_id, 4)
    kinds = [e["kind"] for e in fts.audit_log()]
    assert "full-text-search.indexed" in kinds
    assert "full-text-search.queried" in kinds
    assert "full-text-search.ranked" in kinds
    for event in fts.audit_log():
        assert event["format"] == AUDIT_FORMAT
        for banned in ("text", "tokens", "terms", "term_freqs"):
            assert banned not in event
    with pytest.raises(FullTextSearchError):
        full_text_search_audit_event("bogus-kind", 0)
    with pytest.raises(FullTextSearchError):
        full_text_search_audit_event("tokenized", 0, text="raw leak")


def test_score_is_sane():
    fts = make_indexed()
    q = fts.query("quick fox", 3)
    report = fts.rank(q.query_id, 4)
    for hit in report.hits:
        assert math.isfinite(hit.score) and hit.score > 0
        assert hit.matched_terms


def test_concurrency_smoke():
    fts = FullTextSearch()
    errors = []

    def worker(n):
        try:
            fts.index(f"d{n}", f"document number {n} with fox", n)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(fts) == 8


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, "-m", "full_text_search"],
        capture_output=True,
        text=True,
        cwd="/home/hatch/workspace/wt/northstar-pushchain/components/northstar-agent-runtime",
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "full-text-search OK" in proc.stdout
