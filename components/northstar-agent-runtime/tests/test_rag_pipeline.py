"""Tests for rag_pipeline: retrieval-augmented generation bookkeeping."""

import ast
import subprocess
import sys

import pytest

import rag_pipeline as rp
from rag_pipeline import RAGPipeline


def _module_path():
    return rp.__file__


# ---------------------------------------------------------------------------
# pins & stdlib-only
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert rp.RAG_PIPELINE_VERSION == "rag-pipeline.v1"
    assert rp.RAG_PIPELINE_SCHEMA == "northstar.rag-pipeline.v1"
    assert rp.AUDIT_SCHEMA == "audit.ndjson/1"


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
# ingest
# ---------------------------------------------------------------------------


def test_ingest_roundtrip_and_digest():
    pipe = RAGPipeline()
    rec = pipe.ingest("c1", "the quick brown fox", 1, source="doc-a")
    assert rec.chunk_id == "c1"
    assert rec.source == "doc-a"
    assert rec.term_count == 4
    assert rec.unique_terms == 4
    assert rec.digest.startswith("sha256:")
    assert rec.verify("c1", "the quick brown fox")
    assert not rec.verify("c1", "tampered text")
    view = pipe.chunk("c1")
    assert view is not None and view["digest"] == rec.digest
    assert "the quick brown fox" not in str(view)


def test_ingest_duplicate_retired_and_bad_inputs_consume_seq():
    pipe = RAGPipeline()
    pipe.ingest("c1", "alpha beta", 1)
    with pytest.raises(rp.DuplicateChunkError):
        pipe.ingest("c1", "alpha beta", 2)
    with pytest.raises(rp.BadChunkError):
        pipe.ingest("", "alpha beta", 3)
    with pytest.raises(rp.BadChunkError):
        pipe.ingest("c2", "", 4)
    rejected = [r for r in pipe.audit_log() if r["kind"] == "rag-pipeline.rejected"]
    assert len(rejected) == 3
    pipe.retire("c1", 5)
    with pytest.raises(rp.RetiredChunkError):
        pipe.ingest("c1", "alpha beta", 6)
    with pytest.raises(rp.RetiredChunkError):
        pipe.retire("c1", 7)
    assert pipe.chunk_ids() == ()


def test_retire_terminality_and_unknown():
    pipe = RAGPipeline()
    with pytest.raises(rp.UnknownChunkError):
        pipe.retire("ghost", 1)
    pipe.ingest("c1", "alpha beta gamma", 2)
    pipe.ingest("c2", "delta epsilon", 3)
    assert pipe.chunk_ids() == ("c1", "c2")
    rec = pipe.retire("c1", 4, reason="stale")
    assert rec.chunk_id == "c1" and rec.reason == "stale"
    assert pipe.retired_ids() == ("c1",)
    assert pipe.chunk("c1") is None
    # retired chunk no longer matches retrieval
    ret = pipe.retrieve("alpha", 5)
    assert ret.total_matched == 0


# ---------------------------------------------------------------------------
# retrieve
# ---------------------------------------------------------------------------


def test_retrieve_ranking_order_and_scores():
    pipe = RAGPipeline()
    pipe.ingest("c1", "quick brown fox jumps", 1)
    pipe.ingest("c2", "quick quick quick", 2)
    pipe.ingest("c3", "unrelated words here", 3)
    ret = pipe.retrieve("quick fox", 4)
    assert ret.retrieval_id == "ret-0"
    assert ret.query_terms == ("quick", "fox")
    assert ret.total_matched == 2
    # c1 matches both query terms (coverage 1.0); c2 only "quick"
    assert ret.hits[0].chunk_id == "c1"
    assert ret.hits[1].chunk_id == "c2"
    assert ret.hits[0].score > ret.hits[1].score
    assert all(h.score > 0 for h in ret.hits)
    assert ret.verify("quick fox", [(h.chunk_id, h.score) for h in ret.hits])


def test_retrieve_top_k_truncation_and_empty_as_data():
    pipe = RAGPipeline()
    for i in range(5):
        pipe.ingest(f"c{i}", "shared token", i + 1)
    ret = pipe.retrieve("shared", 6, top_k=2)
    assert ret.total_matched == 2
    assert [h.chunk_id for h in ret.hits] == ["c0", "c1"]  # tiebreak by id
    empty = pipe.retrieve("no such terms xyzzy", 7)
    assert empty.total_matched == 0
    assert empty.hits == ()
    empty_corpus = RAGPipeline().retrieve("anything", 1)
    assert empty_corpus.total_matched == 0


def test_retrieve_bad_inputs_consume_seq_and_audit_rejected():
    pipe = RAGPipeline()
    with pytest.raises(rp.BadQueryError):
        pipe.retrieve("", 1)
    with pytest.raises(rp.BadQueryError):
        pipe.retrieve("!!! ???", 2)
    with pytest.raises(rp.BadTopKError):
        pipe.retrieve("hello", 3, top_k=0)
    with pytest.raises(rp.BadTopKError):
        pipe.retrieve("hello", 4, top_k=1001)
    rejected = [r for r in pipe.audit_log() if r["kind"] == "rag-pipeline.rejected"]
    assert len(rejected) == 4
    assert pipe.stats()["retrievals"] == 0


def test_retrieve_cross_instance_determinism():
    def build():
        p = RAGPipeline()
        p.ingest("c1", "alpha beta gamma", 1)
        p.ingest("c2", "beta beta delta", 2)
        return p.retrieve("alpha beta", 3)

    a, b = build(), build()
    assert a.digest == b.digest
    assert [(h.chunk_id, h.score) for h in a.hits] == [
        (h.chunk_id, h.score) for h in b.hits
    ]


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------


def test_generate_roundtrip_grounding_and_digest():
    pipe = RAGPipeline()
    pipe.ingest("c1", "the eiffel tower is in paris", 1)
    pipe.ingest("c2", "the louvre is in paris", 2)
    ret = pipe.retrieve("eiffel tower paris", 3)
    gen = pipe.generate(
        "eiffel tower paris", ret.retrieval_id, 4,
        "The Eiffel Tower is in Paris.", ("c1",),
    )
    assert gen.generation_id == "gen-0"
    assert gen.retrieval_id == ret.retrieval_id
    assert gen.grounded_chunks == ("c1",)
    assert gen.draft_digest.startswith("sha256:")
    assert gen.verify(
        "eiffel tower paris", ret.retrieval_id, ["c1"],
        "The Eiffel Tower is in Paris.",
    )
    assert not gen.verify(
        "eiffel tower paris", ret.retrieval_id, ["c1"], "tampered draft",
    )
    view = pipe.generation("gen-0")
    assert view is not None and view.digest == gen.digest


def test_generate_fail_closed_on_query_mismatch_unknowns_and_uncited():
    pipe = RAGPipeline()
    pipe.ingest("c1", "alpha beta", 1)
    pipe.ingest("c2", "gamma delta", 2)
    ret = pipe.retrieve("alpha", 3)
    with pytest.raises(rp.UnknownRetrievalError):
        pipe.generate("alpha", "ret-99", 4, "draft text", ("c1",))
    with pytest.raises(rp.BadQueryError):
        pipe.generate("different query", ret.retrieval_id, 5, "draft", ("c1",))
    # c2 is live but not in this retrieval's ranked set
    with pytest.raises(rp.UncitedChunkError):
        pipe.generate("alpha", ret.retrieval_id, 6, "draft", ("c2",))
    with pytest.raises(rp.BadDraftError):
        pipe.generate("alpha", ret.retrieval_id, 7, "", ("c1",))
    pipe.retire("c1", 8)
    with pytest.raises(rp.UnknownChunkError):
        pipe.generate("alpha", ret.retrieval_id, 9, "draft", ("c1",))
    rejected = [r for r in pipe.audit_log() if r["kind"] == "rag-pipeline.rejected"]
    assert len(rejected) == 5


# ---------------------------------------------------------------------------
# cite
# ---------------------------------------------------------------------------


def test_cite_roundtrip_and_claim_pin():
    pipe = RAGPipeline()
    pipe.ingest("c1", "water boils at 100 celsius", 1)
    ret = pipe.retrieve("water boils celsius", 2)
    gen = pipe.generate(
        "water boils celsius", ret.retrieval_id, 3,
        "Water boils at 100 C.", ("c1",),
    )
    cit = pipe.cite(gen.generation_id, "water boils at 100 C", "c1", 4)
    assert cit.citation_id == "cite-0"
    assert cit.generation_id == gen.generation_id
    assert cit.chunk_id == "c1"
    assert cit.claim_digest.startswith("sha256:")
    assert cit.verify(gen.generation_id, "water boils at 100 C", "c1")
    assert not cit.verify(gen.generation_id, "different claim", "c1")
    cites = pipe.citations_for(gen.generation_id)
    assert len(cites) == 1 and cites[0].citation_id == "cite-0"
    assert pipe.citations_for("gen-99") == ()


def test_cite_fail_closed():
    pipe = RAGPipeline()
    pipe.ingest("c1", "alpha beta", 1)
    pipe.ingest("c2", "gamma delta", 2)
    ret = pipe.retrieve("alpha", 3)
    gen = pipe.generate("alpha", ret.retrieval_id, 4, "draft", ("c1",))
    with pytest.raises(rp.UnknownGenerationError):
        pipe.cite("gen-99", "claim", "c1", 5)
    # c2 live but not grounded in this generation
    with pytest.raises(rp.UncitedChunkError):
        pipe.cite(gen.generation_id, "claim", "c2", 6)
    with pytest.raises(rp.BadClaimError):
        pipe.cite(gen.generation_id, "", "c1", 7)
    rejected = [r for r in pipe.audit_log() if r["kind"] == "rag-pipeline.rejected"]
    assert len(rejected) == 3


# ---------------------------------------------------------------------------
# seq discipline, views, audit, main
# ---------------------------------------------------------------------------


def test_seq_discipline_rewind_refused_and_failed_mutations_consume():
    pipe = RAGPipeline()
    pipe.ingest("c1", "alpha", 1)
    with pytest.raises(rp.SeqOrderError):
        pipe.ingest("c2", "beta", 1)  # rewind
    with pytest.raises(rp.SeqOrderError):
        pipe.retrieve("alpha", True)  # bool refused
    with pytest.raises(rp.SeqOrderError):
        pipe.retrieve("alpha", -2)  # negative refused
    with pytest.raises(rp.SeqOrderError):
        pipe.retrieve("alpha", "3")  # non-int refused
    # failed mutation consumed its seq: next valid seq must exceed 4
    with pytest.raises(rp.BadQueryError):
        pipe.retrieve("", 4)
    ret = pipe.retrieve("alpha", 5)
    assert ret.seq == 5
    assert pipe.stats()["last_seq"] == 5
    # views validate seq shape but consume nothing and write no audit rows
    before = len(pipe.audit_log())
    assert pipe.chunk("c1") is not None
    assert pipe.chunk_ids() == ("c1",)
    assert pipe.retrieval("ret-0") is ret
    assert len(pipe.audit_log()) == before


def test_audit_shapes_leak_ban_and_bad_kind():
    pipe = RAGPipeline()
    pipe.ingest("c1", "secret sauce recipe", 1)
    kinds = {r["kind"] for r in pipe.audit_log()}
    assert kinds == {"rag-pipeline.ingested"}
    row = pipe.audit_log()[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "rag-pipeline.v1"
    assert row["seq"] == 1
    detail_str = str(row["detail"])
    assert "secret sauce recipe" not in detail_str
    with pytest.raises(rp.AuditKindError):
        rp.rag_pipeline_audit_event("nope.unknown", {}, 1)
    with pytest.raises(rp.AuditKindError):
        rp.rag_pipeline_audit_event("rag-pipeline.ingested", {"text": "x"}, 1)
    with pytest.raises(rp.AuditKindError):
        rp.rag_pipeline_audit_event("rag-pipeline.generated", {"draft": "x"}, 1)


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, _module_path()],
        capture_output=True,
        text=True,
        cwd="/tmp",
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "rag-pipeline OK" in proc.stdout
