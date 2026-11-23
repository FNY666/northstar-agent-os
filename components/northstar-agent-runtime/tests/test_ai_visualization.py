"""Tests for the ai_visualization decision ledger (Simulated).

House contract: frozen records, caller int seqs strictly increasing
with claim-then-burn, no wall-clock, RLock-guarded, fail-closed
taxonomy, stdlib-only AST-verified, sha256: digest pins, audit.ndjson/1.
"""
from __future__ import annotations

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_visualization
from ai_visualization import (
    AI_VISUALIZATION_VERSION,
    SCHEMA_PIN,
    AIVisualization,
    AIVisualizationError,
    AuditKindError,
    BadDigestError,
    BadOutcomeError,
    BadReasonError,
    BadSubjectError,
    BadVisualizationKindError,
    POSTURES,
    RETIRE_REASONS,
    RetiredSubjectError,
    SeqOrderError,
    UnknownSubjectError,
    UnknownVisualizationError,
    VISUALIZATION_KINDS,
    VISUALIZATION_OUTCOMES,
    ai_visualization_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_VISUALIZATION_VERSION == "ai-visualization.v1"
    assert SCHEMA_PIN == "northstar.ai-visualization.v1"
    assert VISUALIZATION_KINDS == (
        "saliency-map",
        "activation-map",
        "attention-heatmap",
        "feature-visualization",
        "concept-visualization",
        "decision-boundary-plot",
        "embedding-projection",
        "circuit-diagram",
    )
    assert VISUALIZATION_OUTCOMES == ("visualized", "partial", "failed", "inconclusive")
    assert POSTURES == (
        "unexamined",
        "failed",
        "contested",
        "partially-visualized",
        "visualized",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")


def test_stdlib_only():
    """AST self-check: only stdlib (plus canonical_json fallback) is imported."""
    assert stdlib_only()
    path = Path(ai_visualization.__file__)
    tree = ast.parse(path.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed, node.module


def test_visualize_roundtrip():
    """visualize() mints viz-N ids; records are frozen and digest-verified."""
    ledger = AIVisualization()
    rec = ledger.visualize(
        "subject-1",
        1,
        visualization_kind="attention-heatmap",
        outcome="visualized",
        visualization_digest=GOOD_DIGEST,
    )
    assert rec.visualization_id == "viz-1"
    assert rec.subject_id == "subject-1"
    assert rec.seq == 1
    assert rec.visualization_kind == "attention-heatmap"
    assert rec.outcome == "visualized"
    assert rec.visualization_digest == GOOD_DIGEST
    assert rec.verify()
    # frozen dataclass
    with pytest.raises(Exception):
        rec.outcome = "failed"  # type: ignore
    rec2 = ledger.visualize("subject-1", 2)
    assert rec2.visualization_id == "viz-2"
    # defaults
    assert rec2.visualization_kind == "saliency-map"
    assert rec2.outcome == "visualized"


def test_visualize_bad_inputs():
    """Bad inputs fail closed: seq burned, rejected row booked, rewinds bare."""
    ledger = AIVisualization()
    # bad kind
    with pytest.raises(BadVisualizationKindError):
        ledger.visualize("s1", 1, visualization_kind="not-a-kind")
    # bad outcome
    with pytest.raises(BadOutcomeError):
        ledger.visualize("s1", 2, outcome="not-an-outcome")
    # bad subject id (empty)
    with pytest.raises(BadSubjectError):
        ledger.visualize("", 3)
    # bad digest
    with pytest.raises(BadDigestError):
        ledger.visualize("s1", 4, visualization_digest="nope")
    n_rows = len(ledger.audit_log(9))
    assert n_rows == 4
    assert all(r["kind"] == "rejected" for r in ledger.audit_log(9))
    # rewind raises bare (no new row, seq unconsumed)
    with pytest.raises(SeqOrderError):
        ledger.visualize("s1", 2)
    assert len(ledger.audit_log(9)) == 4
    # after burns, a good call claims the next seq and books the row
    rec = ledger.visualize("s1", 5)
    assert rec.verify()
    kinds = [r["kind"] for r in ledger.audit_log(9)]
    assert kinds == ["rejected"] * 4 + ["visualized"]


def test_visualize_full_kind_vocabulary():
    """All 8 pinned visualization kinds are bookable."""
    ledger = AIVisualization()
    seq = 0
    for i, kind in enumerate(VISUALIZATION_KINDS):
        seq += 1
        rec = ledger.visualize(
            f"subject-{kind}", seq, visualization_kind=kind, outcome="visualized"
        )
        assert rec.verify()
        assert rec.visualization_id == f"viz-{i + 1}"


def test_verify_semantics():
    """verify() is a pure read: verified/tampered as data, unknown refused."""
    ledger = AIVisualization()
    rec = ledger.visualize("s1", 1)
    rep = ledger.verify(rec.visualization_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    # seq shape-validated only: never consumed, no audit row
    n_before = len(ledger.audit_log(2))
    rep2 = ledger.verify(rec.visualization_id, 2)  # same seq again
    assert rep2.verdict == "verified"
    assert len(ledger.audit_log(2)) == n_before
    # tamper is reported as data, never raised
    tampered = ledger._visualizations[rec.visualization_id]
    object.__setattr__(tampered, "outcome", "failed")
    rep3 = ledger.verify(rec.visualization_id, 3)
    assert rep3.verdict == "tampered"
    assert rep3.integrity_ok is False
    assert rep3.verify()
    # unknown id refused
    with pytest.raises(UnknownVisualizationError):
        ledger.verify("viz-999", 4)
    with pytest.raises(SeqOrderError):
        ledger.verify(rec.visualization_id, True)


def test_evaluate_posture_math():
    """Posture ladder: failed > contested > partially-visualized > visualized."""
    ledger = AIVisualization()
    # all visualized -> visualized
    ledger.visualize("a", 1, outcome="visualized")
    ledger.visualize("a", 2, outcome="visualized")
    assert ledger.evaluate("a", 3).posture == "visualized"
    # partial demotes -> partially-visualized
    ledger.visualize("b", 4, outcome="visualized")
    ledger.visualize("b", 5, outcome="partial")
    assert ledger.evaluate("b", 6).posture == "partially-visualized"
    # inconclusive demotes -> contested
    ledger.visualize("c", 7, outcome="visualized")
    ledger.visualize("c", 8, outcome="inconclusive")
    assert ledger.evaluate("c", 9).posture == "contested"
    # failed outranks everything
    ledger.visualize("d", 10, outcome="visualized")
    ledger.visualize("d", 11, outcome="inconclusive")
    ledger.visualize("d", 12, outcome="failed")
    assert ledger.evaluate("d", 13).posture == "failed"
    # tallies
    ev = ledger.evaluate("d", 14)
    assert ev.n_visualizations == 3
    assert ev.n_visualized == 1
    assert ev.n_inconclusive == 1
    assert ev.n_failed == 1
    assert ev.n_partial == 0
    assert ev.verify()
    # unknown subject refused
    with pytest.raises(UnknownSubjectError):
        ledger.evaluate("nope", 15)


def test_evaluate_purity_and_integrity():
    """evaluate() is pure: no seq consumption, no audit row; tamper flips flag."""
    ledger = AIVisualization()
    ledger.visualize("s1", 1, outcome="visualized")
    n_before = len(ledger.audit_log(5))
    ev1 = ledger.evaluate("s1", 5)
    ev2 = ledger.evaluate("s1", 5)  # same seq again: fine
    assert ev1.posture == "visualized" == ev2.posture
    assert ev1.integrity_ok is True
    assert len(ledger.audit_log(5)) == n_before
    # tamper flips integrity_ok as data
    tampered = ledger._visualizations["viz-1"]
    object.__setattr__(tampered, "outcome", "failed")
    ev3 = ledger.evaluate("s1", 6)
    assert ev3.posture == "failed"
    assert ev3.integrity_ok is False
    assert ev3.verify()


def test_retire_terminality():
    """retire() is terminal: ids never recycled, reads still work."""
    ledger = AIVisualization()
    ledger.visualize("s1", 1)
    ret = ledger.retire("s1", 2, reason="manual")
    assert ret.subject_id == "s1"
    assert ret.reason == "manual"
    assert ret.verify()
    # post-retire mutations refused
    with pytest.raises(RetiredSubjectError):
        ledger.visualize("s1", 3)
    # post-retire reads still work
    assert ledger.visualize("s2", 4).verify()
    assert ledger.evaluate("s2", 5).posture == "visualized"
    # bad reason, double-retire, unknown subject
    with pytest.raises(BadReasonError):
        ledger.retire("s2", 6, reason="bogus")
    with pytest.raises(RetiredSubjectError):
        ledger.retire("s1", 7)
    with pytest.raises(UnknownSubjectError):
        ledger.retire("ghost", 8)
    # ids never recycled: minting continues
    rec = ledger.visualize("s3", 9)
    assert rec.visualization_id == "viz-3"


def test_seq_discipline():
    """Genesis rewind raises bare; malformed seqs rejected; burns consume."""
    ledger = AIVisualization()
    # genesis rewind (seq 0) raises bare with zero rows
    with pytest.raises(SeqOrderError):
        ledger.visualize("s1", 0)
    assert len(ledger.audit_log(9)) == 0
    # malformed seqs
    for bad in (True, "1", None, 1.5):
        with pytest.raises(SeqOrderError):
            ledger.visualize("s1", bad)  # type: ignore
    # failed mutation consumes its seq
    with pytest.raises(BadOutcomeError):
        ledger.visualize("s1", 1, outcome="bad")
    with pytest.raises(SeqOrderError):
        ledger.visualize("s1", 1)
    rec = ledger.visualize("s1", 2)
    assert rec.verify()


def test_audit_shapes_and_leak_ban():
    """Audit rows carry module/version/kind/seq/details; raw keys banned."""
    ledger = AIVisualization()
    rec = ledger.visualize("s1", 1, visualization_digest=GOOD_DIGEST)
    row = ledger.audit_log(1)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-visualization"
    assert row["version"] == "ai-visualization.v1"
    assert row["kind"] == "visualized"
    assert row["seq"] == 1
    assert row["details"]["visualization_id"] == rec.visualization_id
    # pinned vocab + digest pins emittable, raw material banned
    with pytest.raises(AIVisualizationError):
        ai_visualization_audit_event("visualized", 2, image=b"raw")
    with pytest.raises(AIVisualizationError):
        ai_visualization_audit_event("visualized", 2, heatmap="raw")
    with pytest.raises(AIVisualizationError):
        ai_visualization_audit_event("visualized", 2, embeddings="raw")
    with pytest.raises(AIVisualizationError):
        ai_visualization_audit_event("visualized", 2, attention_weights="raw")
    ok = ai_visualization_audit_event(
        "visualized", 2, visualization_kind="saliency-map", visualization_digest=GOOD_DIGEST
    )
    assert ok["kind"] == "visualized"
    with pytest.raises(AuditKindError):
        ai_visualization_audit_event("bogus", 2)


def test_views_stats_unknown_lookups():
    """Pure-read views, stats, and unknown lookups behave."""
    ledger = AIVisualization()
    ledger.visualize("s1", 1, visualization_kind="activation-map")
    ledger.visualize("s1", 2, visualization_kind="circuit-diagram")
    ledger.visualize("s2", 3)
    assert ledger.subject_ids(4) == ("s1", "s2")
    assert ledger.visualization_ids(4) == ("viz-1", "viz-2", "viz-3")
    assert len(ledger.visualizations_for("s1", 4)) == 2
    rec = ledger.visualization_record("viz-2", 4)
    assert rec.visualization_kind == "circuit-diagram"
    st = ledger.stats(4)
    assert st["n_subjects"] == 2
    assert st["n_visualizations"] == 3
    assert st["n_retired"] == 0
    assert st["seq"] == 3
    assert st["version"] == "ai-visualization.v1"
    with pytest.raises(UnknownVisualizationError):
        ledger.visualization_record("viz-9", 4)
    with pytest.raises(UnknownSubjectError):
        ledger.retire_record("s1", 4)
    assert ledger.retired_ids(4) == ()


def test_cross_instance_digest_determinism():
    """Same inputs on fresh ledgers produce identical digest pins."""
    a = AIVisualization()
    b = AIVisualization()
    ra = a.visualize(
        "s1", 1, visualization_kind="embedding-projection", visualization_digest=GOOD_DIGEST
    )
    rb = b.visualize(
        "s1", 1, visualization_kind="embedding-projection", visualization_digest=GOOD_DIGEST
    )
    assert ra.digest == rb.digest
    ea = a.evaluate("s1", 2)
    eb = b.evaluate("s1", 2)
    assert ea.digest == eb.digest


def test_thread_read_smoke():
    """Concurrent reads on one ledger are race-free."""
    ledger = AIVisualization()
    ledger.visualize("s1", 1)
    errors = []

    def work():
        try:
            for _ in range(50):
                ledger.verify("viz-1", 9)
                ledger.evaluate("s1", 9)
                ledger.stats(9)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_main_subprocess():
    """module main() self-check passes via subprocess."""
    path = Path(ai_visualization.__file__)
    proc = subprocess.run(
        [sys.executable, str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-visualization OK" in proc.stdout
