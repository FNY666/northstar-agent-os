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


# ---------------------------------------------------------------------------
# 15. a record that cannot be canonicalized is NOT intact -- it does not raise
# ---------------------------------------------------------------------------
#
# `verify()` answers a QUESTION: "is this record intact?".  The answer
# for a record whose fields cannot be canonicalized is `False` -- the
# record cannot be shown to be intact, so it is not.
#
# The defect: `_pin()` delegates to `canonical_json`, which refuses a
# lone surrogate with its OWN error type -- `JcsError`, a `ValueError`.
# The `except GraphDatabaseError` clause around `_pin` does NOT catch
# it, so `verify()` RAISED instead of answering.
#
# Measured 2026-11-25 on the tree as it stood:
#
#     >>> GraphRecord(graph_name="\ud800", digest="sha256:"+"0"*64, seq=5).verify()
#     JcsError: lone surrogate U+D800 is not JCS-serializable
#
# Two consequences, both measured:
#
# * `verify()` RAISED instead of answering `False`, so a caller asking
#   "is this record intact?" got an exception.
# * `JcsError` is a `ValueError`, so a caller guarding with `except
#   ValueError` treats a TAMPERED record as a PARSE error and moves on
#   -- the record is neither verified nor rejected.
#
# The repo already has the fix pattern: `job_queue.py`'s `_canonical`
# translates the sibling helper's error into its OWN taxonomy
# (see `job_queue.py`, "Canonical encoding and digest pins").  The same
# translation belongs here.
#
# The stdlib fallback path raises `GraphDatabaseError`, so the two
# configurations must agree -- that is the control.


def _unencodable_records():
    """One record per kind, each carrying a lone surrogate."""
    surrogate = "\ud800"
    return [
        GraphRecord(graph_name=surrogate, digest="sha256:" + "0" * 64, seq=1),
        DropRecord(
            graph_name=surrogate,
            reason="r",
            digest="sha256:" + "0" * 64,
            seq=1,
        ),
        NodeRecord(
            graph_name=surrogate,
            node_id="n",
            labels=("L",),
            properties_digest="sha256:" + "0" * 64,
            digest="sha256:" + "0" * 64,
            seq=1,
        ),
        EdgeRecord(
            graph_name=surrogate,
            edge_id="e",
            from_node="a",
            to_node="b",
            edge_type="t",
            properties_digest="sha256:" + "0" * 64,
            digest="sha256:" + "0" * 64,
            seq=1,
        ),
    ]


@pytest.mark.parametrize("record", _unencodable_records())
def test_verify_answers_false_for_a_record_it_cannot_canonicalize(record):
    """`verify()` answers a question; a question is not an exception."""
    assert record.verify() is False


def test_the_two_canonicalizer_configurations_agree():
    """The control: the shipped path and the fallback must agree.

    THE POINT: a config that CAN canonicalize the input must give the
    same answer as the other config.  Both must answer `False` (the
    digest does not match), and neither may raise.

    A note on what this control does NOT claim: the two configs do NOT
    produce the same DIGEST for the same logical payload -- the shipped
    path emits JCS bytes, the fallback emits its own tagged form.  They
    are different byte strings by construction.  So this test cannot
    assert digest equality; it asserts AGREEMENT ON THE ANSWER, which
    is the property a caller depends on.

    (An earlier draft of this control asserted the fallback RAISES for
    a lone surrogate.  Measured, it does not: the fallback's `_tag`
    passes a lone surrogate straight through to `json.dumps`, which
    escapes it as `\\ud800`.  The fallback therefore SILENTLY ACCEPTS a
    lone surrogate and pins a non-JCS canonical form -- a third defect,
    fixed separately below.  The control was passing for the wrong
    reason: the digest mismatch, not an encode failure.)
    """
    surrogate = "\ud800"
    record = GraphRecord(
        graph_name=surrogate, digest="sha256:" + "0" * 64, seq=1
    )

    saved = graph_database._cj
    try:
        # The shipped path: `canonical_json` is present.
        assert graph_database._cj is not None, (
            "the shipped path is not installed, so this control measures "
            "nothing"
        )
        assert record.verify() is False

        # The fallback path: no sibling helper.
        graph_database._cj = None
        assert record.verify() is False
    finally:
        graph_database._cj = saved


def test_a_tampered_record_is_not_mistaken_for_a_parse_error():
    """A caller guarding on `ValueError` must not swallow a bad record.

    `JcsError` is a `ValueError`.  A caller that catches `ValueError`
    around a parse step would treat a record that cannot be
    canonicalized as a parse error and MOVE ON -- the record would be
    neither verified nor rejected.  So `verify()` must not let a
    `ValueError` escape: it must answer.
    """
    record = GraphRecord(
        graph_name="\ud800", digest="sha256:" + "0" * 64, seq=1
    )
    try:
        answer = record.verify()
    except ValueError as exc:
        pytest.fail(
            "verify() let a ValueError escape (%s): a caller guarding on "
            "ValueError would treat a tampered record as a parse error" % exc
        )
    assert answer is False


# ---------------------------------------------------------------------------
# 16. the stdlib fallback must refuse what the shipped path refuses
# ---------------------------------------------------------------------------
#
# Measured 2026-11-25 on the tree as it stood, the two canonicalizer
# configurations disagreed about a lone surrogate:
#
#     shipped  -> GraphDatabaseError   (canonical_json refuses it)
#     fallback -> OK, 49 bytes         (json.dumps escapes it as \ud800)
#
# The fallback therefore SILENTLY ACCEPTED a value the shipped path
# refused, and pinned a canonical form that is NOT JCS -- a digest over
# bytes no other JCS implementation would produce.  That is the
# fail-OPEN direction: the record pins, and verifies, under a form that
# does not round-trip through the shipped path.
#
# The two configurations must agree about what is LEGAL.  They need not
# agree about the resulting DIGEST -- the fallback's tagged form is
# deliberately its own byte string -- but a value one refuses must be
# refused by both.
#
# The control: a value BOTH accept must be accepted by both, or this
# test would be satisfied by a fallback that refuses everything.


def _configs():
    """Yield (label, canonicalizer) for both configurations."""
    saved = graph_database._cj
    try:
        yield "shipped", saved
        yield "fallback", None
    finally:
        graph_database._cj = saved


def _canonical_under(label, payload):
    """Canonicalize under one configuration; return bytes or the error."""
    saved = graph_database._cj
    try:
        graph_database._cj = saved if label == "shipped" else None
        return ("ok", graph_database._canonical(payload))
    except GraphDatabaseError as exc:
        return ("refused", type(exc).__name__)
    finally:
        graph_database._cj = saved


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "\ud800"},
        {"name": "\udfff"},
        {"name": "a\ud800b"},
    ],
)
def test_both_configurations_refuse_a_lone_surrogate(payload):
    """A value the shipped path refuses, the fallback must refuse too."""
    shipped = _canonical_under("shipped", payload)
    fallback = _canonical_under("fallback", payload)

    assert shipped[0] == "refused", (
        "the shipped path accepted a lone surrogate: %r" % (shipped,)
    )
    assert fallback[0] == "refused", (
        "the fallback accepted a lone surrogate that the shipped path "
        "refuses: %r -- the two configurations disagree about legality, "
        "so a digest pinned under one does not verify under the other"
        % (fallback,)
    )


def test_both_configurations_accept_a_value_both_can_canonicalize():
    """The control: the fallback must not refuse everything.

    A fallback that refused every input would satisfy the test above
    vacuously.  So this test pins down that the two configurations
    still ACCEPT a legitimate payload -- the disagreement must be
    narrow, about the values that are actually illegal.
    """
    payload = {"name": "ordinary", "n": 7, "tags": ["a", "b"]}
    shipped = _canonical_under("shipped", payload)
    fallback = _canonical_under("fallback", payload)

    assert shipped[0] == "ok", shipped
    assert fallback[0] == "ok", fallback


def test_a_lone_surrogate_cannot_be_pinned_in_either_configuration():
    """The end-to-end shape: no configuration may pin a surrogate."""
    for label in ("shipped", "fallback"):
        saved = graph_database._cj
        try:
            graph_database._cj = saved if label == "shipped" else None
            db = GraphDatabase()
            with pytest.raises(GraphDatabaseError):
                db.graph("\ud800", 1)
            assert db.graph_names() == ()
        finally:
            graph_database._cj = saved


# ---------------------------------------------------------------------------
# 17. a seq above the safe range must be refused -- it cannot be pinned
# ---------------------------------------------------------------------------
#
# `canonical_json` serializes an integer outside the safe range as an
# IEEE-754 double (RFC 8785 Appendix B note (2)), so 2**53 and 2**53+1
# canonicalize to the SAME bytes:
#
#     _canonical(2**53)   == b'9007199254740992'
#     _canonical(2**53+1) == b'9007199254740992'
#
# So above the safe range the digest stops pinning the seq, and a
# TAMPERED seq still verifies.  Measured 2026-11-25:
#
#     d = _pin("graph", "g", 2**53)
#     GraphRecord(graph_name="g", digest=d, seq=2**53+1).verify()
#     -> True        # the seq was changed; the digest was not
#
# That is a fail-OPEN integrity defect: the digest is the module's
# tamper pin, and it silently stops pinning.
#
# The repo already has this exact rule in `job_queue.py::_check_seq`
# (and in `grant_pin_ledger.py`, `profiler.py`).  `graph_database.py`
# declares `_MAX_INT = 2**53 - 1` and NEVER USES IT -- the bound was
# missing from `_check_seq`, and `seq` was the one unbounded integer in
# a digest here.
#
# The stdlib fallback refuses such an integer outright, so without the
# bound the two configurations also disagreed about whether a large
# seq is legal at all.


def test_a_seq_above_the_safe_range_is_refused():
    """A seq that cannot be pinned must not be accepted."""
    db = GraphDatabase()
    db.graph("g", 1)
    for bad in (2**53, 2**53 + 1, 2**60):
        with pytest.raises(SeqOrderError):
            db.graph("g2", bad)


def test_a_tampered_seq_above_the_safe_range_cannot_verify():
    """The control for the defect: the digest must pin the seq.

    This is the property the bound protects.  If the bound were
    removed, a record whose seq was bumped by one would still verify.

    The record is built from a LEGITIMATE pin (seq 1) and then
    tampered, so the test does not itself depend on the bound: it
    asserts the tampered record does NOT verify.
    """
    digest = graph_database._pin("graph", "g", 1)
    tampered = GraphRecord(graph_name="g", digest=digest, seq=2**53 + 1)
    assert tampered.verify() is False


def test_the_safe_range_boundary_is_accepted():
    """The control: the bound must not cut off a LEGAL seq.

    `2**53 - 1` is the last pin-able integer.  A bound that refused it
    would over-refuse; a bound that accepted `2**53` would under-
    refuse.  Both boundaries are pinned here.
    """
    db = GraphDatabase()
    db.graph("g", 2**53 - 1)
    with pytest.raises(SeqOrderError):
        db.graph("g2", 2**53)


# ---------------------------------------------------------------------------
# 18. a failed mutation books a `rejected` row -- including a failed PIN
# ---------------------------------------------------------------------------
#
# The class docstring promises: "failed mutations consume their seq and
# book a `rejected` audit row".
#
# But the `_pin(...)` calls sit OUTSIDE the try block that books the
# row.  Measured 2026-11-25:
#
#     db.graph("\ud800", 1)   -> raises, and books NO row
#     db.node("g", "n", 2, properties={"p": "\ud800"})
#                          -> raises, and books NO row
#
# while a refusal caught INSIDE the try block does book one:
#
#     db.node("g", "n", 2, properties={"p": object()})
#                          -> raises BadPropertyError, books a row
#
# So the trail cannot tell "the database refused this graph" from "the
# database never saw it" -- the same defect shape the refusal-hold
# wiring forbids for the queue.
#
# After the fixes above these inputs are refused by the VALIDATION
# layer (which sits inside the try block), so the row is booked.  The
# test below therefore pins the PROMISE, not the mechanism: whatever
# the refusal path, a failed mutation books a row.


def test_a_failed_mutation_books_a_rejected_row():
    """A refused mutation must leave a trace."""
    db = GraphDatabase()
    db.graph("g", 1)
    rows_before = len(db.audit_log())

    with pytest.raises(GraphDatabaseError):
        db.node("g", "n", 2, labels=("L",), properties={"p": "\ud800"})

    rows = db.audit_log()
    assert len(rows) == rows_before + 1, (
        "a failed mutation booked no row: the trail cannot tell a refusal "
        "from a never-seen request"
    )
    assert rows[-1]["kind"] == "graph-database.rejected"
    assert rows[-1]["detail"]["reason"], "the rejection row names no reason"


def test_a_failed_mutation_still_consumes_its_seq():
    """A failed mutation consumes its seq -- the docstring's other half."""
    db = GraphDatabase()
    db.graph("g", 1)

    with pytest.raises(GraphDatabaseError):
        db.node("g", "n", 2, labels=("L",), properties={"p": "\ud800"})

    # seq 2 was consumed, so seq 2 is refused as a rewind...
    with pytest.raises(SeqOrderError):
        db.graph("g2", 2)
    # ...and seq 3 is the next usable one.
    db.graph("g2", 3)
    assert "g2" in db.graph_names()


def test_a_pin_refuses_an_integer_outside_the_safe_range():
    """No digest may ever be pinned over a lossy integer.

    THIS is the property that closes the collision.  Without it,
    ``_pin("graph", "g", 2**53)`` and ``_pin("graph", "g", 2**53+1)``
    produce the SAME digest -- both canonicalize to the bytes
    ``9007199254740992`` -- and a record carrying either digest
    verifies against either seq.  So the fix is not "refuse a big seq
    at the door" (that is ``_check_seq``'s job, and it does not cover
    ``verify()``, which recomputes the pin from a record's own fields).

    The pin must REFUSE the integer, so no such digest can be minted
    in the first place.

    The recursion matters: the payload is a NESTED list of pin parts,
    so a top-level-only check would miss the integer entirely.
    """
    for part in (2**53, 2**53 + 1, 2**60, -(2**53)):
        with pytest.raises(GraphDatabaseError):
            graph_database._pin("graph", "g", part)


def test_a_pin_still_accepts_the_last_safe_integer():
    """The control: the refusal must not over-reach.

    ``2**53 - 1`` is the last integer whose canonical form is exact.
    A pin over it must succeed, or the module could not pin anything
    near the bound.
    """
    pinned = graph_database._pin("graph", "g", 2**53 - 1)
    assert pinned.startswith("sha256:")


def test_a_record_carrying_an_unpinnable_seq_does_not_verify():
    """`verify()` must ANSWER, not raise, for an unpinnable seq.

    ``verify()`` recomputes the pin from the record's own fields and
    does NOT go through ``_check_seq`` -- the seq it checks is the one
    on the record, which may have been tampered with.  So the pin's own
    refusal is what stands between a tampered seq and a `True`.
    """
    record = GraphRecord(
        graph_name="g", digest="sha256:" + "0" * 64, seq=2**53 + 1
    )
    assert record.verify() is False
