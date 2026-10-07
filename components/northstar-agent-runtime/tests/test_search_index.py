"""Tests for search_index: Elasticsearch-shaped index lifecycle ledger."""

import ast
import subprocess
import sys

import pytest

import search_index as si
from search_index import SearchIndex


def _module_path():
    return si.__file__


# ---------------------------------------------------------------------------
# pins & stdlib-only
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert si.SEARCH_INDEX_VERSION == "search-index.v1"
    assert si.SEARCH_INDEX_SCHEMA == "northstar.search-index.v1"
    assert si.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(open(_module_path(), encoding="utf-8").read())
    allowed = {
        "hashlib", "math", "re", "threading", "dataclasses", "typing",
        "__future__", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# index
# ---------------------------------------------------------------------------


def test_index_roundtrip_and_digest():
    idx = SearchIndex()
    rec = idx.index("d1", {"title": "Quick brown fox", "body": "fox jumps"}, 1)
    assert rec.doc_id == "d1"
    assert rec.field_names == ("body", "title")
    assert rec.term_count == 5
    assert rec.unique_terms == 5  # per-field uniques: fox in title and body
    assert rec.digest.startswith("sha256:")
    assert rec.segment == 0
    assert rec.replaced is False
    assert rec.verify("d1", {"title": "Quick brown fox", "body": "fox jumps"})
    assert not rec.verify("d1", {"title": "tampered"})
    view = idx.document("d1")
    assert view is not None and view.digest == rec.digest


def test_index_replace_updates_postings():
    idx = SearchIndex()
    idx.index("d1", {"body": "alpha beta"}, 1)
    assert idx.search(("alpha",), 2).total_matched == 1
    rec = idx.index("d1", {"body": "gamma delta"}, 3)
    assert rec.replaced is True
    assert idx.search(("alpha",), 4).total_matched == 0
    assert idx.search(("gamma",), 5).total_matched == 1


def test_index_bad_inputs_consume_seq_and_audit_rejected():
    idx = SearchIndex()
    before = len(idx.audit_log())
    with pytest.raises(si.BadDocError):
        idx.index("", {"title": "x"}, 1)
    with pytest.raises(si.BadFieldError):
        idx.index("d1", {}, 2)
    with pytest.raises(si.BadFieldError):
        idx.index("d1", {"Bad Name": "x"}, 3)
    with pytest.raises(si.BadFieldError):
        idx.index("d1", {"title": 42}, 4)
    rows = idx.audit_log()[before:]
    assert all(r["kind"] == si.KIND_REJECTED for r in rows)
    assert len(rows) == 4
    # failed mutations consumed their seqs: next mutation needs seq > 4
    with pytest.raises(si.SeqOrderError):
        idx.index("d1", {"title": "x"}, 4)
    rec = idx.index("d1", {"title": "x"}, 5)
    assert rec.doc_id == "d1"


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------


def test_delete_terminal_and_tombstone():
    idx = SearchIndex()
    idx.index("d1", {"body": "alpha"}, 1)
    rec = idx.delete("d1", 2)
    assert rec.doc_id == "d1"
    assert idx.document("d1") is None
    assert idx.search(("alpha",), 3).total_matched == 0
    assert idx.retired_ids() == ("d1",)
    # re-index after delete is refused fail-closed
    with pytest.raises(si.DeletedDocError):
        idx.index("d1", {"body": "alpha"}, 4)
    # unknown delete is refused
    with pytest.raises(si.UnknownDocError):
        idx.delete("nope", 5)


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------


def test_search_ranking_and_top_k():
    idx = SearchIndex()
    idx.index("d1", {"body": "fox fox fox dog"}, 1)
    idx.index("d2", {"body": "fox dog"}, 2)
    idx.index("d3", {"body": "unrelated words here"}, 3)
    res = idx.search(("fox",), 4)
    assert res.total_matched == 2
    assert [h.doc_id for h in res.hits] == ["d1", "d2"]
    assert res.hits[0].score > res.hits[1].score
    assert res.query_digest.startswith("sha256:")
    limited = idx.search(("fox", "dog"), 5, top_k=1)
    assert len(limited.hits) == 1
    assert limited.total_matched == 2


def test_search_fielded_and_boost_changes_ranking():
    idx = SearchIndex()
    idx.index("d1", {"title": "fox", "body": "fox fox fox fox fox"}, 1)
    idx.index("d2", {"title": "fox fox fox fox fox", "body": "fox"}, 2)
    plain = idx.search(("fox",), 3)
    assert [h.doc_id for h in plain.hits] == ["d1", "d2"]
    boosted = idx.search(("fox",), 4, boosts={"title": 100.0})
    assert [h.doc_id for h in boosted.hits] == ["d2", "d1"]
    fielded = idx.search(("fox",), 5, fields=("title",))
    assert fielded.total_matched == 2
    assert all("title:fox" in h.matched_terms for h in fielded.hits)


def test_search_is_pure_read():
    idx = SearchIndex()
    idx.index("d1", {"body": "alpha"}, 1)
    n_audit = len(idx.audit_log())
    res = idx.search(("alpha",), 1)  # seq reuse allowed on pure reads
    assert res.total_matched == 1
    res2 = idx.search(("alpha",), 1)
    assert res2.query_digest == res.query_digest
    assert len(idx.audit_log()) == n_audit
    # mutation after a pure read at the same seq still works
    idx.index("d2", {"body": "beta"}, 2)
    assert idx.search(("beta",), 2).total_matched == 1


def test_search_bad_inputs():
    idx = SearchIndex()
    idx.index("d1", {"body": "alpha"}, 1)
    with pytest.raises(si.BadQueryError):
        idx.search((), 2)
    with pytest.raises(si.BadQueryError):
        idx.search("alpha", 3)
    with pytest.raises(si.BadQueryError):
        idx.search(("!!!",), 4)
    with pytest.raises(si.BadBoostError):
        idx.search(("alpha",), 5, boosts={"body": -1.0})
    with pytest.raises(si.BadBoostError):
        idx.search(("alpha",), 6, boosts={"body": True})
    with pytest.raises(si.BadTopKError):
        idx.search(("alpha",), 7, top_k=0)
    with pytest.raises(si.SeqOrderError):
        idx.search(("alpha",), -1)


# ---------------------------------------------------------------------------
# refresh / merge / commit
# ---------------------------------------------------------------------------


def test_refresh_declares_new_segment():
    idx = SearchIndex()
    idx.index("d1", {"body": "alpha"}, 1)
    ref = idx.refresh(2)
    assert ref.segment == 1
    assert ref.docs_visible == 1
    assert ref.digest.startswith("sha256:")
    assert idx.document("d1").segment == 1
    assert idx.stats(2)["segments"] == [0, 1]


def test_merge_compacts_segments():
    idx = SearchIndex()
    idx.index("d1", {"body": "alpha"}, 1)
    idx.refresh(2)
    idx.index("d2", {"body": "beta"}, 3)
    mg = idx.merge(4)
    assert mg.segments_merged == 2
    assert mg.docs_visible == 2
    assert idx.stats(4)["segments"] == [mg.segment]
    # search still works across the merged segment
    assert idx.search(("alpha",), 5).total_matched == 1
    assert idx.search(("beta",), 6).total_matched == 1


def test_commit_pins_state():
    idx = SearchIndex()
    idx.index("d1", {"body": "alpha"}, 1)
    idx.delete("d1", 2)
    cm = idx.commit(3)
    assert cm.commit_digest.startswith("sha256:")
    assert cm.docs_visible == 0
    assert cm.tombstones == 1
    assert cm.segments == (0,)
    rows = [r for r in idx.audit_log() if r["kind"] == si.KIND_COMMITTED]
    assert rows and rows[0]["detail"]["tombstones"] == 1


# ---------------------------------------------------------------------------
# seq discipline / audit boundary
# ---------------------------------------------------------------------------


def test_seq_ordering_rewind_refused_bare():
    idx = SearchIndex()
    idx.index("d1", {"body": "alpha"}, 5)
    with pytest.raises(si.SeqOrderError):
        idx.index("d2", {"body": "beta"}, 5)
    with pytest.raises(si.SeqOrderError):
        idx.index("d2", {"body": "beta"}, 3)
    with pytest.raises(si.SeqOrderError):
        idx.index("d2", {"body": "beta"}, True)
    n_rejected = sum(
        1 for r in idx.audit_log() if r["kind"] == si.KIND_REJECTED
    )
    assert n_rejected == 0  # rewinds raise bare, no audit row


def test_audit_shapes_and_text_leak_ban():
    idx = SearchIndex()
    idx.index("d1", {"title": "secret text here", "body": "more words"}, 1)
    idx.delete("d1", 2)
    idx.refresh(3)
    idx.merge(4)
    idx.commit(5)
    kinds = {r["kind"] for r in idx.audit_log()}
    assert kinds == {
        si.KIND_INDEXED, si.KIND_DELETED, si.KIND_REFRESHED,
        si.KIND_MERGED, si.KIND_COMMITTED,
    }
    blob = str(idx.audit_log())
    assert "secret text here" not in blob
    assert "more words" not in blob
    for row in idx.audit_log():
        assert row["schema"] == si.AUDIT_SCHEMA
        assert row["module"] == si.SEARCH_INDEX_VERSION
    with pytest.raises(si.AuditKindError):
        si.search_index_audit_event("bogus-kind", {}, 6)
    with pytest.raises(si.AuditKindError):
        si.search_index_audit_event(si.KIND_INDEXED, {"text": "x"}, 7)


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, _module_path()],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0
    assert "search-index OK" in proc.stdout
