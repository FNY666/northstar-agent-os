"""Tests for the mechanistic circuit-tracing / ablation ledger."""

from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from mechanistic import (
    AUDIT_SCHEMA,
    KIND_ABLATION_BOOKED,
    KIND_CIRCUIT_REGISTERED,
    KIND_REJECTED,
    MECHANISTIC_SCHEMA,
    MECHANISTIC_VERSION,
    AblationRecord,
    AuditKindError,
    BadAblationError,
    BadCircuitError,
    BadEdgeError,
    BadNodeError,
    CircuitRecord,
    DuplicateAblationError,
    DuplicateCircuitError,
    Mechanistic,
    MechanisticError,
    SeqOrderError,
    TraceReport,
    UnknownAblationError,
    UnknownCircuitError,
    _VERDICTS,
    mechanistic_audit_event,
)

RUNTIME = Path(__file__).resolve().parents[1]


def _spec(nodes=None, edges=None, task="indirect-object-identification"):
    return {
        "task": task,
        "nodes": nodes
        if nodes is not None
        else [
            {"node_id": "emb", "layer": 0, "kind": "embedding"},
            {"node_id": "h3.5", "layer": 3, "kind": "attention-head"},
            {"node_id": "mlp4", "layer": 4, "kind": "mlp"},
            {"node_id": "logits", "layer": 12, "kind": "logit"},
        ],
        "edges": edges
        if edges is not None
        else [
            {"from": "emb", "to": "h3.5"},
            {"from": "h3.5", "to": "mlp4"},
            {"from": "mlp4", "to": "logits"},
        ],
    }


def _declared(ledger, cid="ioi", seq=1):
    return ledger.circuit(cid, _spec(), seq)


# ---------------------------------------------------------------------------
# pins
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert MECHANISTIC_VERSION == "mechanistic.v1"
    assert MECHANISTIC_SCHEMA == "northstar.mechanistic.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse((RUNTIME / "mechanistic.py").read_text(encoding="utf-8"))
    allowed = {
        "hashlib", "math", "threading", "dataclasses", "typing",
        "__future__", "canonical_json", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# circuit
# ---------------------------------------------------------------------------


def test_circuit_roundtrip_and_verify():
    m = Mechanistic()
    rec = _declared(m)
    assert isinstance(rec, CircuitRecord)
    assert rec.circuit_id == "ioi"
    assert rec.task == "indirect-object-identification"
    assert rec.node_count == 4
    assert rec.edge_count == 3
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    nodes = [("emb", 0, "embedding"), ("h3.5", 3, "attention-head"),
             ("mlp4", 4, "mlp"), ("logits", 12, "logit")]
    edges = [("emb", "h3.5"), ("h3.5", "mlp4"), ("mlp4", "logits")]
    assert rec.verify("indirect-object-identification", nodes, edges)
    assert not rec.verify("other-task", nodes, edges)


def test_circuit_duplicate_and_bad_inputs():
    m = Mechanistic()
    _declared(m)
    rejected = 0

    with pytest.raises(DuplicateCircuitError):
        _declared(m, seq=2)
    rejected += 1

    bad_specs = [
        ("no-spec", "not-a-mapping", 3),
        ("no-task", {"nodes": [], "edges": []}, 4),
        ("empty-nodes", {"task": "t", "nodes": [], "edges": []}, 5),
        ("edges-not-list", {"task": "t", "nodes": [
            {"node_id": "a", "layer": 0, "kind": "custom"}], "edges": {}}, 6),
    ]
    for cid, spec, seq in bad_specs:
        with pytest.raises(BadCircuitError):
            m.circuit(cid, spec, seq)
        rejected += 1

    dup_nodes = [
        {"node_id": "a", "layer": 0, "kind": "custom"},
        {"node_id": "a", "layer": 1, "kind": "custom"},
    ]
    with pytest.raises(BadNodeError):
        m.circuit("dup-nodes", _spec(nodes=dup_nodes, edges=[]), 7)
    rejected += 1

    for bad_node, seq in [
        ({"node_id": "a", "layer": 0}, 8),                    # missing kind
        ({"node_id": "a", "layer": -1, "kind": "mlp"}, 9),     # neg layer
        ({"node_id": "a", "layer": 0, "kind": "neuron"}, 10),  # bad kind
        ("not-a-mapping", 11),
    ]:
        with pytest.raises(BadNodeError):
            m.circuit(f"badnode-{seq}", _spec(nodes=[bad_node], edges=[]),
                      seq)
        rejected += 1

    base_nodes = [
        {"node_id": "a", "layer": 0, "kind": "custom"},
        {"node_id": "b", "layer": 1, "kind": "custom"},
    ]
    bad_edge_cases = [
        ([{"from": "a", "to": "zzz"}], BadEdgeError, 12),   # unknown dst
        ([{"from": "a", "to": "a"}], BadEdgeError, 13),      # self-loop
        ([{"from": "a", "to": "b"}, {"from": "a", "to": "b"}],
         BadEdgeError, 14),                                  # duplicate
        ([{"from": "a", "to": "b"}, {"from": "b", "to": "a"}],
         BadEdgeError, 15),                                  # cycle
        ("not-a-list", BadCircuitError, 16),
    ]
    for edges, exc, seq in bad_edge_cases:
        with pytest.raises(exc):
            m.circuit(f"badedge-{seq}", _spec(nodes=base_nodes, edges=edges),
                      seq)
        rejected += 1

    with pytest.raises(BadCircuitError):
        m.circuit("", _spec(), 17)
    rejected += 1

    rows = [r for r in m.audit_log(18) if r["kind"] == KIND_REJECTED]
    assert len(rows) == rejected
    assert all(r["detail"]["error"].endswith("Error") for r in rows)
    # every failed mutation consumed its seq: next valid seq is 18
    rec = m.circuit("fresh", _spec(), 18)
    assert rec.seq == 18


# ---------------------------------------------------------------------------
# trace (pure read)
# ---------------------------------------------------------------------------


def test_trace_order_and_purity():
    m = Mechanistic()
    _declared(m)
    rows_before = len(m.audit_log(2))
    t1 = m.trace("ioi", 2)
    t2 = m.trace("ioi", 2)  # same seq twice: pure read
    assert isinstance(t1, TraceReport)
    assert t1.order == ("emb", "h3.5", "mlp4", "logits")
    assert t1.verify("ioi")
    assert t1.digest == t2.digest
    # no seq consumed, no audit rows written by the read
    assert len(m.audit_log(2)) == rows_before
    assert m.stats(2)["last_seq"] == 1


def test_trace_unknown_circuit():
    m = Mechanistic()
    with pytest.raises(UnknownCircuitError):
        m.trace("ghost", 1)
    with pytest.raises(UnknownCircuitError):
        m.trace(123, 2)  # malformed id: bare raise, no seq burn


# ---------------------------------------------------------------------------
# ablate
# ---------------------------------------------------------------------------


def test_ablate_roundtrip_and_verify():
    m = Mechanistic()
    _declared(m)
    rec = m.ablate("ioi", "abl-1", ["h3.5"], 2,
                   effect_score=0.9, verdict="task-broken")
    assert isinstance(rec, AblationRecord)
    assert rec.ablation_id == "abl-1"
    assert rec.circuit_id == "ioi"
    assert rec.node_count == 1
    assert rec.verdict == "task-broken"
    assert rec.seq == 2
    assert rec.digest.startswith("sha256:")
    assert rec.verify("ioi", ["h3.5"])
    assert not rec.verify("ioi", ["mlp4"])
    # effect score / verdict are booked as host-reported data only
    rec2 = m.ablate("ioi", "abl-2", ["h3.5", "mlp4"], 3)
    assert rec2.verdict == "declared"
    assert rec2.verify("ioi", ["mlp4", "h3.5"])  # order-insensitive pin


def test_ablate_bad_inputs():
    m = Mechanistic()
    _declared(m)
    rejected = 0

    with pytest.raises(UnknownCircuitError):
        m.ablate("ghost", "a", ["h3.5"], 2)
    rejected += 1

    m.ablate("ioi", "dup", ["h3.5"], 3)
    with pytest.raises(DuplicateAblationError):
        m.ablate("ioi", "dup", ["h3.5"], 4)
    rejected += 1

    with pytest.raises(BadAblationError):
        m.ablate("ioi", "e1", [], 5)                       # empty nodes
    rejected += 1
    with pytest.raises(BadAblationError):
        m.ablate("ioi", "e2", ["h3.5", "h3.5"], 6)          # dup nodes
    rejected += 1
    with pytest.raises(BadAblationError):
        m.ablate("ioi", "e3", ["nope"], 7)                 # not in circuit
    rejected += 1
    with pytest.raises(BadAblationError):
        m.ablate("ioi", "e4", [123], 8)                    # non-str node
    rejected += 1
    for bad_score, seq in [(True, 9), (float("nan"), 10), (-0.5, 11),
                           (1.5, 12), ("high", 13)]:
        with pytest.raises(BadAblationError):
            m.ablate("ioi", f"bad-{seq}", ["h3.5"], seq,
                     effect_score=bad_score)
        rejected += 1
    for good_score, seq in [(0, 14), (1, 15), (0.25, 16)]:
        rec = m.ablate("ioi", f"ok-{seq}", ["h3.5"], seq,
                       effect_score=good_score)
        assert rec.seq == seq
    with pytest.raises(BadAblationError):
        m.ablate("ioi", "badverdict", ["h3.5"], 17, verdict="causal-proof")
    rejected += 1
    for v in sorted(_VERDICTS):
        m.ablate("ioi", f"v-{v}", ["h3.5"], 18 + sorted(_VERDICTS).index(v),
                 verdict=v)

    rows = [r for r in m.audit_log(100) if r["kind"] == KIND_REJECTED]
    assert len(rows) == rejected
    assert m.stats(100)["last_seq"] == 18 + len(_VERDICTS) - 1


# ---------------------------------------------------------------------------
# seq discipline
# ---------------------------------------------------------------------------


def test_seq_ordering():
    m = Mechanistic()
    _declared(m)  # seq 1
    with pytest.raises(SeqOrderError):
        m.circuit("rewind", _spec(), 1)   # rewind: bare, no consumption
    with pytest.raises(SeqOrderError):
        m.circuit("zero", _spec(), 0)
    for bad in (True, "2", 1.5, None, -1):
        with pytest.raises(SeqOrderError):
            m.circuit("bad", _spec(), bad)
    assert m.stats(99)["last_seq"] == 1
    assert not [r for r in m.audit_log(99) if r["kind"] == KIND_REJECTED]
    rec = m.circuit("next", _spec(), 2)
    assert rec.seq == 2


# ---------------------------------------------------------------------------
# audit boundary
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban():
    m = Mechanistic()
    _declared(m)
    m.ablate("ioi", "abl-1", ["h3.5"], 2, effect_score=0.9,
             verdict="task-broken")
    rows = m.audit_log(3)
    kinds = [r["kind"] for r in rows]
    assert kinds == [KIND_CIRCUIT_REGISTERED, KIND_ABLATION_BOOKED]
    for r in rows:
        assert r["schema"] == AUDIT_SCHEMA
        assert r["module"] == MECHANISTIC_VERSION
        assert r["seq"] in (1, 2)
    banned_keys = {"effect_score", "score", "spec", "nodes", "edges",
                 "payload", "raw", "value", "data"}
    for r in rows:
        assert not banned_keys.intersection(r["detail"].keys()), \
            r["detail"].keys()
    # builder accepts the three kinds, rejects unknown + banned keys
    ok = mechanistic_audit_event(KIND_REJECTED, {"error": "X"}, 9)
    assert ok["kind"] == KIND_REJECTED
    with pytest.raises(AuditKindError):
        mechanistic_audit_event("nope", {}, 9)
    with pytest.raises(AuditKindError):
        mechanistic_audit_event(KIND_REJECTED, {"score": 1.0}, 9)


# ---------------------------------------------------------------------------
# determinism / frozen / views
# ---------------------------------------------------------------------------


def test_cross_instance_digest_determinism():
    a, b = Mechanistic(), Mechanistic()
    ra = a.circuit("ioi", _spec(), 1)
    rb = b.circuit("ioi", _spec(), 1)
    assert ra.digest == rb.digest
    ta = a.trace("ioi", 2)
    tb = b.trace("ioi", 2)
    assert ta.digest == tb.digest
    aa = a.ablate("ioi", "x", ["h3.5"], 3, verdict="task-intact")
    ab = b.ablate("ioi", "x", ["h3.5"], 3, verdict="task-intact")
    assert aa.digest == ab.digest


def test_frozen_records():
    m = Mechanistic()
    rec = _declared(m)
    with pytest.raises(FrozenInstanceError):
        rec.circuit_id = "mutated"  # type: ignore[misc]
    ab = m.ablate("ioi", "a1", ["h3.5"], 2)
    with pytest.raises(FrozenInstanceError):
        ab.verdict = "x"  # type: ignore[misc]


def test_views():
    m = Mechanistic()
    _declared(m, cid="b")
    _declared(m, cid="a", seq=2)
    m.ablate("a", "abl", ["emb"], 3)
    assert m.circuit_ids(4) == ("a", "b")
    assert m.circuit_record("a", 4).node_count == 4
    assert m.ablation_record("abl", 4).circuit_id == "a"
    with pytest.raises(UnknownCircuitError):
        m.circuit_record("ghost", 4)
    with pytest.raises(UnknownAblationError):
        m.ablation_record("ghost", 4)
    st = m.stats(4)
    assert st == {"circuits": 2, "ablations": 1,
                  "audit_rows": 3, "last_seq": 3}
    assert len(m.audit_log(4)) == 3


def test_concurrent_access_smoke():
    m = Mechanistic()
    errs = []

    def worker(i):
        try:
            m.circuit(f"c{i}", _spec(), 1 + i)
        except MechanisticError as e:  # noqa: BLE001 - collected
            errs.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs
    assert m.stats(100)["circuits"] == 8


def test_main_subprocess():
    out = subprocess.run(
        [sys.executable, str(RUNTIME / "mechanistic.py")],
        capture_output=True, text=True, cwd="/tmp", check=False)
    assert out.returncode == 0, out.stderr
    assert "mechanistic OK: circuit, trace, ablate, pins, audit" in out.stdout
