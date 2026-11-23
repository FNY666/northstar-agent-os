"""Targeted tests for vector_search.py (HNSW-shaped ANN bookkeeping)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import vector_search as vs
from vector_search import (
    AuditKindError,
    BadIdError,
    BadMetricError,
    BadParamError,
    BadVectorError,
    DuplicateVectorError,
    InsertRecord,
    QueryReport,
    SeqOrderError,
    UnknownVectorError,
    VectorSearch,
    VectorSearchError,
    _assign_level,
    vector_search_audit_event,
)

MODULE_PATH = Path(vs.__file__)


def test_version_schema_pins():
    assert vs.VECTOR_SEARCH_VERSION == "vector-search.v1"
    assert vs.VECTOR_SEARCH_SCHEMA == "northstar.vector-search.v1"
    assert vs.METRICS == ("euclidean", "cosine")
    assert vs.MAX_LEVEL == 16


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "hashlib",
        "heapq",
        "math",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "json",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_insert_roundtrip_verify():
    idx = VectorSearch(3)
    rec = idx.insert("v1", (1.0, 2.0, 3.0), 0)
    assert isinstance(rec, InsertRecord)
    assert rec.vector_id == "v1"
    assert rec.level == _assign_level("v1", 16)
    assert 0 <= rec.level <= vs.MAX_LEVEL
    assert rec.digest.startswith("sha256:")
    assert rec.seq == 0
    assert idx.size() == 1 and idx.ids() == ("v1",)
    stored = idx.vector_record("v1")
    assert stored.vector == (1.0, 2.0, 3.0)
    assert stored.level == rec.level
    assert stored.verify()
    # Layer-0 links of the second insert point back at the first.
    idx.insert("v2", (1.1, 2.1, 3.1), 1)
    assert "v1" in idx.links("v2", 0)
    assert "v2" in idx.links("v1", 0)


def test_insert_duplicate_and_retired_refused():
    idx = VectorSearch(2)
    idx.insert("a", (1.0, 0.0), 0)
    with pytest.raises(DuplicateVectorError):
        idx.insert("a", (1.0, 0.0), 1)
    # Failed mutation consumed seq 1 and booked a rejection row.
    assert idx._seq == 1
    assert idx.audit_log()[-1]["kind"] == "vector-search.rejected"
    idx.delete("a", 2)
    # Retired id can never be re-inserted.
    with pytest.raises(DuplicateVectorError):
        idx.insert("a", (1.0, 0.0), 3)
    with pytest.raises(UnknownVectorError):
        idx.vector_record("a")


def test_insert_bad_inputs():
    idx = VectorSearch(2)
    cases = [
        ("", (1.0, 0.0), BadIdError),
        (True, (1.0, 0.0), BadIdError),
        ("x", (1.0,), BadVectorError),
        ("x", (1.0, 0.0, 0.0), BadVectorError),
        ("x", (1.0, float("nan")), BadVectorError),
        ("x", (1.0, float("inf")), BadVectorError),
        ("x", (1.0, True), BadVectorError),
        ("x", "ab", BadVectorError),
        ("x", (1.0, "s"), BadVectorError),
    ]
    seq = 0
    for vid, vec, exc in cases:
        with pytest.raises(exc):
            idx.insert(vid, vec, seq)
        seq += 1  # each failed mutation burns its seq
    assert idx._seq == seq - 1
    assert idx.size() == 0
    # Cosine rejects the zero vector.
    cidx = VectorSearch(2, metric="cosine")
    with pytest.raises(BadVectorError):
        cidx.insert("z", (0.0, 0.0), 0)
    # Euclidean allows it.
    eidx = VectorSearch(2, metric="euclidean")
    eidx.insert("z", (0.0, 0.0), 0)
    assert eidx.size() == 1
    # Constructor refusals.
    with pytest.raises(VectorSearchError):
        VectorSearch(0)
    with pytest.raises(VectorSearchError):
        VectorSearch(True)
    with pytest.raises(BadParamError):
        VectorSearch(2, m=1)
    with pytest.raises(BadParamError):
        VectorSearch(2, m=129)
    with pytest.raises(BadMetricError):
        VectorSearch(2, metric="manhattan")


def test_nearest_roundtrip_sorted():
    idx = VectorSearch(2)
    idx.insert("a", (1.0, 0.0), 0)
    idx.insert("b", (0.0, 1.0), 1)
    idx.insert("c", (10.0, 10.0), 2)
    rep = idx.nearest((1.0, 0.1), 2, 3)
    assert isinstance(rep, QueryReport)
    assert rep.k == 2 and rep.metric == "euclidean"
    assert len(rep.neighbors) == 2
    assert rep.neighbors[0].vector_id == "a"
    assert rep.neighbors[0].rank == 0
    assert rep.neighbors[0].distance <= rep.neighbors[1].distance
    assert rep.digest.startswith("sha256:")
    assert 0.0 <= rep.recall_at_k <= 1.0
    # k larger than the corpus returns everything.
    rep_all = idx.nearest((1.0, 0.1), 10, 4)
    assert len(rep_all.neighbors) == 3


def test_nearest_recall_and_determinism():
    idx = VectorSearch(2)
    points = {
        "p1": (1.0, 0.0),
        "p2": (0.9, 0.1),
        "p3": (0.0, 1.0),
        "p4": (-1.0, 0.0),
        "p5": (0.1, 0.9),
    }
    for s, (vid, vec) in enumerate(points.items()):
        idx.insert(vid, vec, s)
    rep = idx.nearest((1.0, 0.0), 3, 99, ef=10)
    # Recall is booked as data against the exact oracle.
    assert 0.0 <= rep.recall_at_k <= 1.0
    assert rep.recall_at_k == 1.0  # tiny corpus: beam finds the exact set
    # Cross-instance determinism: same inserts -> identical answer order.
    idx2 = VectorSearch(2)
    for s, (vid, vec) in enumerate(points.items()):
        idx2.insert(vid, vec, s)
    rep2 = idx2.nearest((1.0, 0.0), 3, 99, ef=10)
    assert [n.vector_id for n in rep2.neighbors] == [
        n.vector_id for n in rep.neighbors
    ]
    assert [n.distance for n in rep2.neighbors] == [
        n.distance for n in rep.neighbors
    ]


def test_nearest_empty_index_is_data():
    idx = VectorSearch(3)
    rep = idx.nearest((1.0, 0.0, 0.0), 5, 0)
    assert rep.neighbors == ()
    assert rep.recall_at_k == 1.0  # vacuous: nothing to miss


def test_nearest_bad_inputs():
    idx = VectorSearch(2)
    idx.insert("a", (1.0, 0.0), 0)
    with pytest.raises(BadParamError):
        idx.nearest((1.0, 0.0), 0, 1)  # k must be positive
    with pytest.raises(BadParamError):
        idx.nearest((1.0, 0.0), True, 1)
    with pytest.raises(BadParamError):
        idx.nearest((1.0, 0.0), 3, 1, ef=2)  # ef < k
    with pytest.raises(BadParamError):
        idx.nearest((1.0, 0.0), 3, 1, ef=5000)
    with pytest.raises(BadVectorError):
        idx.nearest((1.0,), 1, 1)
    with pytest.raises(BadVectorError):
        idx.nearest((1.0, float("nan")), 1, 1)
    with pytest.raises(SeqOrderError):
        idx.nearest((1.0, 0.0), 1, True)
    with pytest.raises(SeqOrderError):
        idx.nearest((1.0, 0.0), 1, -1)
    # nearest() is a pure read: seq not consumed.
    before = idx._seq
    idx.nearest((1.0, 0.0), 1, 1)
    assert idx._seq == before


def test_delete_lifecycle():
    idx = VectorSearch(2)
    idx.insert("a", (1.0, 0.0), 0)
    idx.insert("b", (0.9, 0.1), 1)
    assert "b" in idx.links("a", 0)
    d = idx.delete("a", 2)
    assert d.digest.startswith("sha256:")
    assert d.seq == 2
    assert idx.size() == 1 and idx.ids() == ("b",)
    # Links pruned on survivors.
    assert "a" not in idx.links("b", 0)
    # Tombstoned vector no longer returned by queries.
    rep = idx.nearest((1.0, 0.0), 5, 3)
    assert all(n.vector_id != "a" for n in rep.neighbors)
    assert [n.vector_id for n in rep.neighbors] == ["b"]
    # Deleting the entry point recomputes it.
    assert idx._entry_id == "b"


def test_delete_unknown_refused():
    idx = VectorSearch(2)
    idx.insert("a", (1.0, 0.0), 0)
    with pytest.raises(UnknownVectorError):
        idx.delete("zz", 1)
    assert idx._seq == 1  # failed mutation consumed its seq
    assert idx.audit_log()[-1]["kind"] == "vector-search.rejected"
    with pytest.raises(SeqOrderError):
        idx.delete("a", 1)  # rewind: seq 1 already burned
    idx.delete("a", 2)
    with pytest.raises(UnknownVectorError):
        idx.delete("a", 3)  # already tombstoned


def test_seq_discipline():
    idx = VectorSearch(2)
    with pytest.raises(SeqOrderError):
        idx.insert("a", (1.0, 0.0), True)
    with pytest.raises(SeqOrderError):
        idx.insert("a", (1.0, 0.0), -1)
    with pytest.raises(SeqOrderError):
        idx.insert("a", (1.0, 0.0), 1.5)
    assert idx._seq == -1  # malformed seqs consume nothing
    idx.insert("a", (1.0, 0.0), 0)
    with pytest.raises(SeqOrderError):
        idx.insert("b", (0.0, 1.0), 0)  # rewind raises bare, no consume
    assert idx._seq == 0
    with pytest.raises(BadVectorError):
        idx.insert("b", (0.0,), 1)  # bad payload burns seq 1
    assert idx._seq == 1
    idx.insert("b", (0.0, 1.0), 2)
    assert idx._seq == 2


def test_audit_shapes_and_leak_ban():
    idx = VectorSearch(2)
    idx.insert("a", (1.0, 0.0), 0)
    idx.delete("a", 1)
    rows = idx.audit_log()
    kinds = [r["kind"] for r in rows]
    assert kinds == ["vector-search.inserted", "vector-search.deleted"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "northstar.vector-search.v1"
        assert row["version"] == "vector-search.v1"
        for banned in ("vector", "payload", "value", "raw", "components"):
            assert banned not in row, banned
    ev = vector_search_audit_event("queried", idx, 2)
    assert ev["kind"] == "vector-search.queried"
    assert ev["size"] == 0 and ev["dim"] == 2
    with pytest.raises(AuditKindError):
        vector_search_audit_event("bogus", idx, 2)
    with pytest.raises(TypeError):
        vector_search_audit_event("inserted", object(), 2)
    with pytest.raises(SeqOrderError):
        vector_search_audit_event("inserted", idx, True)


def test_level_assignment_deterministic():
    for vid in ("alpha", "beta", "gamma", "delta"):
        assert _assign_level(vid, 16) == _assign_level(vid, 16)
        assert 0 <= _assign_level(vid, 16) <= vs.MAX_LEVEL
    # Larger m -> smaller ml -> levels skew lower on average.
    levels_small_m = [_assign_level(f"n{i}", 4) for i in range(200)]
    levels_big_m = [_assign_level(f"n{i}", 64) for i in range(200)]
    assert sum(levels_big_m) <= sum(levels_small_m)
    assert max(levels_small_m) >= 1  # some node rises above layer 0


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "vector-search OK" in proc.stdout
