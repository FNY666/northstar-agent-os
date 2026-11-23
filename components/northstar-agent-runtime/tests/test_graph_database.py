"""Tests for graph_database: named property-graph database bookkeeping."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import graph_database
from graph_database import (
    AuditKindError,
    BadDepthError,
    BadEdgeTypeError,
    BadGraphError,
    BadIdError,
    BadLabelError,
    BadModeError,
    BadPropertyError,
    DropRecord,
    DuplicateEdgeError,
    DuplicateGraphError,
    DuplicateNodeError,
    EdgeRecord,
    GraphDatabase,
    GraphDatabaseError,
    GraphRecord,
    NodeRecord,
    ParallelEdgeError,
    SeqOrderError,
    TraverseReport,
    UnknownEdgeError,
    UnknownGraphError,
    UnknownNodeError,
    graph_database_audit_event,
)


def _good() -> GraphDatabase:
    return GraphDatabase()


# ---------------------------------------------------------------------------
# 1. pins
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert graph_database.GRAPH_DATABASE_VERSION == "graph-database.v1"
    assert graph_database.GRAPH_DATABASE_SCHEMA == "northstar.graph-database.v1"
    assert graph_database.AUDIT_SCHEMA == "audit.ndjson/1"
    db = _good()
    assert db.stats().schema == graph_database.GRAPH_DATABASE_SCHEMA


# ---------------------------------------------------------------------------
# 2. stdlib-only
# ---------------------------------------------------------------------------


def test_stdlib_only():
    tree = ast.parse(Path(graph_database.__file__).read_text())
    allowed = {"__future__", "hashlib", "threading", "dataclasses",
               "typing", "json", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# 3. graph create roundtrip + verify
# ---------------------------------------------------------------------------


def test_graph_roundtrip_and_verify():
    db = _good()
    rec = db.graph("movies", 1)
    assert isinstance(rec, GraphRecord)
    assert rec.graph_name == "movies" and rec.seq == 1
    assert rec.verify()
    assert rec.schema == graph_database.GRAPH_DATABASE_SCHEMA
    assert db.graph_names() == ("movies",)


def test_graph_duplicate_and_retired_refused():
    db = _good()
    db.graph("movies", 1)
    with pytest.raises(DuplicateGraphError):
        db.graph("movies", 2)
    db.drop("movies", 3)
    with pytest.raises(DuplicateGraphError):
        db.graph("movies", 4)
    for i, bad in enumerate(("", "   ", 0, True, None), start=5):
        with pytest.raises(BadGraphError):
            db.graph(bad, i)


# ---------------------------------------------------------------------------
# 4. node roundtrip + verify
# ---------------------------------------------------------------------------


def test_node_roundtrip_and_verify():
    db = _good()
    db.graph("movies", 1)
    rec = db.node("movies", "keanu", 2, labels=("Person",),
                  properties={"born": 1964})
    assert isinstance(rec, NodeRecord)
    assert rec.labels == ("Person",)
    assert rec.verify()
    assert rec.schema == graph_database.GRAPH_DATABASE_SCHEMA
    view = db.node_view("movies", "keanu")
    assert view is not None and view.labels == ("Person",)
    assert db.node_view("movies", "missing") is None
    assert db.node_ids("movies") == ("keanu",)


def test_node_unknown_graph_duplicate_and_bad_inputs():
    db = _good()
    with pytest.raises(UnknownGraphError):
        db.node("nope", "n1", 1)
    db.graph("g", 2)
    db.node("g", "dup", 3)
    with pytest.raises(DuplicateNodeError):
        db.node("g", "dup", 4)
    for i, bad_id in enumerate(("", 0, True, None), start=5):
        with pytest.raises(BadIdError):
            db.node("g", bad_id, i)
    for i, bad_label in enumerate((("",), ("x" * 200,)), start=9):
        with pytest.raises(BadLabelError):
            db.node("g", "bad", i, labels=bad_label)
    for i, bad_props in enumerate(
        ({"x": 2**60}, {"x": float("nan")}), start=11
    ):
        with pytest.raises(BadPropertyError):
            db.node("g", "bad", i, properties=bad_props)
    # failed mutations consume their seq
    rec = db.node("g", "ok", 13)
    assert rec.seq == 13


# ---------------------------------------------------------------------------
# 5. edge roundtrip + verify
# ---------------------------------------------------------------------------


def test_edge_roundtrip_and_verify():
    db = _good()
    db.graph("g", 1)
    db.node("g", "a", 2)
    db.node("g", "b", 3)
    rec = db.edge("g", "e1", "a", "b", "KNOWS", 4,
                  properties={"since": 2020})
    assert isinstance(rec, EdgeRecord)
    assert (rec.from_node, rec.to_node, rec.edge_type) == (
        "a", "b", "KNOWS")
    assert rec.verify()
    view = db.edge_view("g", "e1")
    assert view is not None and view.edge_type == "KNOWS"
    assert db.edge_view("g", "missing") is None
    assert db.neighbors("g", "a") == ("b",)
    assert db.neighbors("g", "b") == ()


def test_edge_fail_closed_branches():
    db = _good()
    db.graph("g", 1)
    db.node("g", "a", 2)
    db.node("g", "b", 3)
    db.edge("g", "e1", "a", "b", "KNOWS", 4)
    with pytest.raises(UnknownGraphError):
        db.edge("nope", "e2", "a", "b", "KNOWS", 5)
    with pytest.raises(DuplicateEdgeError):
        db.edge("g", "e1", "a", "b", "LIKES", 6)
    with pytest.raises(UnknownNodeError):
        db.edge("g", "e2", "a", "ghost", "KNOWS", 7)
    with pytest.raises(UnknownNodeError):
        db.edge("g", "e2", "ghost", "a", "KNOWS", 8)
    with pytest.raises(ParallelEdgeError):
        db.edge("g", "e2", "a", "b", "KNOWS", 9)
    with pytest.raises(BadEdgeTypeError):
        db.edge("g", "e2", "a", "b", "", 10)
    # self-loop is allowed
    self_loop = db.edge("g", "e3", "a", "a", "KNOWS", 11)
    assert self_loop.verify()


# ---------------------------------------------------------------------------
# 6. traverse: BFS visit order
# ---------------------------------------------------------------------------


def test_traverse_bfs_order():
    db = _good()
    db.graph("g", 1)
    for i, nid in enumerate(("root", "left", "right", "leaf"), start=2):
        db.node("g", nid, i)
    db.edge("g", "e1", "root", "right", "REL", 6)
    db.edge("g", "e2", "root", "left", "REL", 7)
    db.edge("g", "e3", "left", "leaf", "REL", 8)
    report = db.traverse("g", "root", 9)
    assert isinstance(report, TraverseReport)
    assert report.mode == "bfs"
    # edge-id-sorted adjacency: e1(root->right) before e2(root->left)
    assert report.visited == ("root", "right", "left", "leaf")
    assert report.edge_count == 3
    # read purity: same seq again is fine, no audit rows, no seq burn
    report2 = db.traverse("g", "root", 9)
    assert report2.visited == report.visited
    rec = db.node("g", "fresh", 10)
    assert rec.seq == 10


def test_traverse_dfs_order():
    db = _good()
    db.graph("g", 1)
    for i, nid in enumerate(("root", "left", "right", "leaf"), start=2):
        db.node("g", nid, i)
    db.edge("g", "e1", "root", "right", "REL", 6)
    db.edge("g", "e2", "root", "left", "REL", 7)
    db.edge("g", "e3", "left", "leaf", "REL", 8)
    report = db.traverse("g", "root", 9, mode="dfs")
    assert report.mode == "dfs"
    assert report.visited[0] == "root"
    assert set(report.visited) == {"root", "left", "right", "leaf"}
    # deterministic across instances
    db2 = _good()
    db2.graph("g", 1)
    for i, nid in enumerate(("root", "left", "right", "leaf"), start=2):
        db2.node("g", nid, i)
    db2.edge("g", "e1", "root", "right", "REL", 6)
    db2.edge("g", "e2", "root", "left", "REL", 7)
    db2.edge("g", "e3", "left", "leaf", "REL", 8)
    assert db2.traverse("g", "root", 9, mode="dfs").visited == (
        report.visited)


# ---------------------------------------------------------------------------
# 7. traverse filters and depth
# ---------------------------------------------------------------------------


def test_traverse_filters_and_max_depth():
    db = _good()
    db.graph("g", 1)
    db.node("g", "root", 2, labels=("Hub",))
    db.node("g", "movie", 3, labels=("Movie",))
    db.node("g", "person", 4, labels=("Person",))
    db.edge("g", "e1", "root", "movie", "TAGGED", 5)
    db.edge("g", "e2", "root", "person", "ACTED", 6)
    by_type = db.traverse("g", "root", 7, edge_types=("ACTED",))
    assert set(by_type.visited) == {"root", "person"}
    by_label = db.traverse("g", "root", 8, labels=("Movie",))
    assert by_label.visited[0] == "root"
    assert set(by_label.visited) == {"root", "movie"}
    depth_one = db.traverse("g", "root", 9, max_depth=1)
    assert set(depth_one.visited) == {"root", "movie", "person"}
    with pytest.raises(BadModeError):
        db.traverse("g", "root", 10, mode="random")
    with pytest.raises(BadDepthError):
        db.traverse("g", "root", 11, max_depth=-1)
    with pytest.raises(UnknownGraphError):
        db.traverse("nope", "root", 12)
    with pytest.raises(UnknownNodeError):
        db.traverse("g", "ghost", 13)


# ---------------------------------------------------------------------------
# 8. seq ordering
# ---------------------------------------------------------------------------


def test_seq_ordering_and_rewind_without_consume():
    db = _good()
    db.graph("g", 1)
    with pytest.raises(SeqOrderError):
        db.graph("h", 1)          # rewind
    with pytest.raises(SeqOrderError):
        db.graph("h", True)       # bool refused
    with pytest.raises(SeqOrderError):
        db.graph("h", -1)         # negative refused
    with pytest.raises(SeqOrderError):
        db.graph("h", 1.5)        # float refused
    db.graph("h", 2)              # rewind did not consume
    assert db.graph_names() == ("g", "h")


# ---------------------------------------------------------------------------
# 9. drop terminality
# ---------------------------------------------------------------------------


def test_drop_terminality():
    db = _good()
    db.graph("g", 1)
    db.node("g", "n1", 2)
    rec = db.drop("g", 3, "cleanup")
    assert isinstance(rec, DropRecord)
    assert rec.verify()
    assert db.stats().graphs == 0
    assert db.stats().dropped == 1
    with pytest.raises(UnknownGraphError):
        db.drop("g", 4)
    with pytest.raises(UnknownGraphError):
        db.node("g", "n2", 5)
    with pytest.raises(UnknownGraphError):
        db.node_ids("g")


# ---------------------------------------------------------------------------
# 10. stats and views
# ---------------------------------------------------------------------------


def test_stats_and_views():
    db = _good()
    db.graph("g1", 1)
    db.graph("g2", 2)
    db.node("g1", "a", 3)
    db.node("g1", "b", 4)
    db.edge("g1", "e1", "a", "b", "REL", 5)
    stats = db.stats()
    assert (stats.graphs, stats.nodes, stats.edges) == (2, 2, 1)
    assert db.graph_names() == ("g1", "g2")
    assert db.node_ids("g1") == ("a", "b")
    assert db.edge_ids("g1") == ("e1",)
    assert db.neighbors("g1", "a") == ("b",)


# ---------------------------------------------------------------------------
# 11. audit shapes + banned keys
# ---------------------------------------------------------------------------


def test_audit_shapes_and_banned_keys():
    db = _good()
    db.graph("g", 1)
    db.node("g", "n1", 2, properties={"secret": "x"})
    db.edge("g", "e1", "n1", "n1", "LOOP", 3)
    db.drop("g", 4)
    kinds = [row["kind"] for row in db.audit_log()]
    assert kinds == [
        "graph-database.graph-created",
        "graph-database.node-pinned",
        "graph-database.edge-pinned",
        "graph-database.graph-dropped",
    ]
    for row in db.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "graph-database.v1"
        for banned in ("properties", "payload", "value", "raw"):
            assert banned not in row["detail"]
    # failed mutations book a rejected row
    db2 = _good()
    db2.graph("g", 1)
    with pytest.raises(DuplicateGraphError):
        db2.graph("g", 2)
    rejected = db2.audit_log()[-1]
    assert rejected["kind"] == "graph-database.rejected"


def test_audit_event_bad_kind():
    with pytest.raises(AuditKindError):
        graph_database_audit_event("nope", {}, 1)
    with pytest.raises(AuditKindError):
        graph_database_audit_event(
            graph_database.KIND_NODE_PINNED, {"properties": {}}, 1)


# ---------------------------------------------------------------------------
# 12. frozen records
# ---------------------------------------------------------------------------


def test_records_frozen():
    db = _good()
    rec = db.graph("g", 1)
    with pytest.raises(Exception):
        rec.graph_name = "h"  # type: ignore
    node_rec = db.node("g", "n1", 2, properties={"k": "v"})
    with pytest.raises(Exception):
        node_rec.node_id = "x"  # type: ignore


# ---------------------------------------------------------------------------
# 13. digest pins differ by content
# ---------------------------------------------------------------------------


def test_digest_pins_differ_by_content():
    db = _good()
    db.graph("g", 1)
    n1 = db.node("g", "n1", 2, properties={"k": "v"})
    n2 = db.node("g", "n2", 3, properties={"k": "w"})
    assert n1.properties_digest != n2.properties_digest
    assert n1.digest != n2.digest


# ---------------------------------------------------------------------------
# 14. main() subprocess check
# ---------------------------------------------------------------------------


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, graph_database.__file__],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("graph-database OK")
