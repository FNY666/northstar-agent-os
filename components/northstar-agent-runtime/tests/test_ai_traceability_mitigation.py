"""Tests for the ai_traceability_mitigation decision ledger (Simulated).

House contract: frozen records, caller int seqs strictly increasing
with claim-then-burn, no wall-clock, RLock-guarded, fail-closed
taxonomy, stdlib-only AST-verified, sha256: digest pins, audit.ndjson/1.
"""
from __future__ import annotations

import ast
import dataclasses
import subprocess
import sys
from pathlib import Path

import pytest

import ai_traceability_mitigation
from ai_traceability_mitigation import (
    AI_TRACEABILITY_MITIGATION_VERSION,
    SCHEMA_PIN,
    AITraceabilityMitigation,
    AITraceabilityMitigationError,
    ALLOWED_TRANSITIONS,
    EFFECTIVENESS,
    MITIGATION_STATUSES,
    POSTURES,
    RETIRE_REASONS,
    TRACEABILITY_STRATEGIES,
    TERMINAL_STATUSES,
    AuditKindError,
    BadDigestError,
    BadEffectivenessError,
    BadHazardError,
    BadReasonError,
    BadStatusError,
    BadStrategyError,
    BadTransitionError,
    RetiredHazardError,
    SeqOrderError,
    UnknownHazardError,
    UnknownMitigationError,
    ai_traceability_mitigation_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_TRACEABILITY_MITIGATION_VERSION == "ai-traceability-mitigation.v1"
    assert SCHEMA_PIN == "northstar.ai-traceability-mitigation.v1"
    assert TRACEABILITY_STRATEGIES == (
        "traceability-assignment",
        "lineage-restoration",
        "provenance-reconstruction",
        "audit-trail-completion",
        "decision-record-backfill",
        "data-lineage-mapping",
        "trace-gap-closure",
        "no-action",
    )
    assert MITIGATION_STATUSES == (
        "proposed",
        "approved",
        "in-progress",
        "implemented",
        "abandoned",
    )
    assert EFFECTIVENESS == ("unrated", "none", "partial", "full")
    assert POSTURES == (
        "unmitigated",
        "under-mitigation",
        "ineffective",
        "mitigated",
        "partially-mitigated",
        "abandoned",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert TERMINAL_STATUSES == frozenset({"implemented", "abandoned"})
    assert ALLOWED_TRANSITIONS["proposed"] == frozenset({"approved", "abandoned"})
    assert ALLOWED_TRANSITIONS["implemented"] == frozenset()


def test_stdlib_only():
    """AST self-check: only stdlib (plus canonical_json fallback) is imported."""
    assert stdlib_only()
    path = Path(ai_traceability_mitigation.__file__)
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
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed


def test_mitigate_roundtrip():
    """mitigate() mints tmm-N ids; records are frozen and digest-verified."""
    ledger = AITraceabilityMitigation()
    rec = ledger.mitigate(
        "hazard-1",
        1,
        strategy="traceability-assignment",
        hazard_digest=GOOD_DIGEST,
    )
    assert rec.mitigation_id == "tmm-1"
    assert rec.hazard_id == "hazard-1"
    assert rec.seq == 1
    assert rec.strategy == "traceability-assignment"
    assert rec.status == "proposed"
    assert rec.effectiveness == "unrated"
    assert rec.hazard_digest == GOOD_DIGEST
    assert rec.verify()
    # frozen dataclass
    with pytest.raises(Exception):
        rec.status = "implemented"  # type: ignore
    rec2 = ledger.mitigate("hazard-1", 2)
    assert rec2.mitigation_id == "tmm-2"


def test_mitigate_bad_inputs():
    """Bad inputs fail closed: seq burned, rejected row booked, rewinds bare."""
    ledger = AITraceabilityMitigation()
    before = len(ledger.audit_log(0))
    # rewind on genesis (seq 0 <= seq 0) raises bare with zero rows
    with pytest.raises(SeqOrderError):
        ledger.mitigate("hazard-1", 0)
    assert len(ledger.audit_log(0)) == before
    bad_calls = [
        ("", 1, "traceability-assignment"),
        (True, 2, "traceability-assignment"),
        ("hazard-1", 3, "not-a-strategy"),
        ("hazard-1", 4, "traceability-assignment"),
    ]
    for hazard_id, seq, strategy in bad_calls[:3]:
        with pytest.raises(AITraceabilityMitigationError):
            ledger.mitigate(hazard_id, seq, strategy=strategy)
    with pytest.raises(AITraceabilityMitigationError):
        ledger.mitigate("hazard-1", 4, hazard_digest="bad-digest")
    rows = ledger.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 4
    for r in rejected:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-traceability-mitigation"


def test_full_strategy_vocabulary():
    """All 8 traceability-mitigation strategies are accepted."""
    ledger = AITraceabilityMitigation()
    seq = 1
    for strategy in TRACEABILITY_STRATEGIES:
        rec = ledger.mitigate(f"hazard-{strategy}", seq, strategy=strategy)
        assert rec.strategy == strategy
        assert rec.verify()
        seq += 1


def test_update_transition_ladder():
    """update() follows the fail-closed transition ladder."""
    ledger = AITraceabilityMitigation()
    rec = ledger.mitigate("hazard-1", 1, strategy="traceability-assignment")
    rec = ledger.update(rec.mitigation_id, 2, "approved")
    assert rec.status == "approved"
    assert rec.verify()
    rec = ledger.update(rec.mitigation_id, 3, "in-progress")
    assert rec.status == "in-progress"
    rec = ledger.update(rec.mitigation_id, 4, "implemented", effectiveness="full")
    assert rec.status == "implemented"
    assert rec.effectiveness == "full"
    assert rec.verify()


def test_update_bad_transitions():
    """Bad transitions fail closed: seq burned, rejected row booked."""
    ledger = AITraceabilityMitigation()
    rec = ledger.mitigate("hazard-1", 1)
    # skip approved -> in-progress
    with pytest.raises(BadTransitionError):
        ledger.update(rec.mitigation_id, 2, "in-progress")
    # premature effectiveness rating
    with pytest.raises(BadEffectivenessError):
        ledger.update(rec.mitigation_id, 3, "approved", effectiveness="full")
    # unknown mitigation id
    with pytest.raises(UnknownMitigationError):
        ledger.update("tmm-999", 4, "approved")
    # bad status
    with pytest.raises(BadStatusError):
        ledger.update(rec.mitigation_id, 5, "not-a-status")
    # bad effectiveness
    with pytest.raises(BadEffectivenessError):
        ledger.update(rec.mitigation_id, 6, "approved", effectiveness="bogus")
    rows = ledger.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 5
    # terminal escape: drive to implemented, then try another transition
    rec = ledger.update(rec.mitigation_id, 7, "approved")
    rec = ledger.update(rec.mitigation_id, 8, "in-progress")
    rec = ledger.update(rec.mitigation_id, 9, "implemented", effectiveness="full")
    with pytest.raises(BadTransitionError):
        ledger.update(rec.mitigation_id, 10, "abandoned")
    rows = ledger.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 6


def test_verify_semantics():
    """verify() is a pure read: seq shape-validated only, no audit row."""
    ledger = AITraceabilityMitigation()
    rec = ledger.mitigate("hazard-1", 1, strategy="lineage-restoration")
    before = len(ledger.audit_log(0))
    rep = ledger.verify(rec.mitigation_id, 2)
    assert rep.record_id == rec.mitigation_id
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    assert rep.seq == 2
    # seq is not consumed: no audit rows
    assert len(ledger.audit_log(0)) == before
    # unknown mitigation id
    with pytest.raises(UnknownMitigationError):
        ledger.verify("tmm-999", 3)
    # bad read seq
    with pytest.raises(SeqOrderError):
        ledger.verify(rec.mitigation_id, True)


def test_verify_tamper_as_data():
    """Tampered records verify() as 'tampered' as data, never raised."""
    ledger = AITraceabilityMitigation()
    rec = ledger.mitigate("hazard-1", 1)
    tampered = dataclasses.replace(rec, strategy="provenance-reconstruction")
    assert tampered.verify() is False
    ledger._mitigations[rec.mitigation_id] = tampered
    rep = ledger.verify(rec.mitigation_id, 2)
    assert rep.verdict == "tampered"
    assert rep.integrity_ok is False
    assert rep.verify()
    # evaluate() integrity flips as data too
    ev = ledger.evaluate("hazard-1", 3)
    assert ev.integrity_ok is False


def test_evaluate_posture_math():
    """evaluate() derives the residual-traceability posture by ledger rule."""
    # under-mitigation: any non-terminal status
    ledger = AITraceabilityMitigation()
    rec = ledger.mitigate("hazard-1", 1, strategy="traceability-assignment")
    ev = ledger.evaluate("hazard-1", 2)
    assert ev.posture == "under-mitigation"
    assert ev.n_mitigations == 1
    assert ev.n_terminal == 0
    assert ev.integrity_ok is True
    assert ev.verify()
    # unknown hazard
    with pytest.raises(UnknownHazardError):
        ledger.evaluate("nope", 3)

    # ineffective: implemented with effectiveness none
    ledger2 = AITraceabilityMitigation()
    rec2 = ledger2.mitigate("hazard-2", 1, strategy="audit-trail-completion")
    rec2 = ledger2.update(rec2.mitigation_id, 2, "approved")
    rec2 = ledger2.update(rec2.mitigation_id, 3, "in-progress")
    rec2 = ledger2.update(
        rec2.mitigation_id, 4, "implemented", effectiveness="none"
    )
    ev2 = ledger2.evaluate("hazard-2", 5)
    assert ev2.posture == "ineffective"
    assert ev2.n_implemented == 1
    assert ev2.n_none == 1

    # mitigated: all implemented, at least one full, none none
    ledger3 = AITraceabilityMitigation()
    rec3 = ledger3.mitigate("hazard-3", 1, strategy="data-lineage-mapping")
    rec3 = ledger3.update(rec3.mitigation_id, 2, "approved")
    rec3 = ledger3.update(rec3.mitigation_id, 3, "in-progress")
    rec3 = ledger3.update(
        rec3.mitigation_id, 4, "implemented", effectiveness="full"
    )
    ev3 = ledger3.evaluate("hazard-3", 5)
    assert ev3.posture == "mitigated"
    assert ev3.n_full == 1
    assert ev3.n_terminal == 1

    # partially-mitigated: implemented with partial effectiveness
    ledger4 = AITraceabilityMitigation()
    rec4 = ledger4.mitigate("hazard-4", 1, strategy="no-action")
    rec4 = ledger4.update(rec4.mitigation_id, 2, "approved")
    rec4 = ledger4.update(rec4.mitigation_id, 3, "in-progress")
    rec4 = ledger4.update(
        rec4.mitigation_id, 4, "implemented", effectiveness="partial"
    )
    ev4 = ledger4.evaluate("hazard-4", 5)
    assert ev4.posture == "partially-mitigated"
    assert ev4.n_partial == 1

    # abandoned: all abandoned
    ledger5 = AITraceabilityMitigation()
    rec5 = ledger5.mitigate("hazard-5", 1)
    rec5 = ledger5.update(rec5.mitigation_id, 2, "abandoned")
    ev5 = ledger5.evaluate("hazard-5", 3)
    assert ev5.posture == "abandoned"
    assert ev5.n_terminal == 1


def test_retire_terminality():
    """retire() is terminal: ids never recycled, post-retire mutations refused."""
    ledger = AITraceabilityMitigation()
    rec = ledger.mitigate("hazard-1", 1)
    ret = ledger.retire("hazard-1", 2, reason="superseded")
    assert ret.hazard_id == "hazard-1"
    assert ret.reason == "superseded"
    assert ret.verify()
    # double retire fails
    with pytest.raises(RetiredHazardError):
        ledger.retire("hazard-1", 3)
    # unknown hazard
    with pytest.raises(UnknownHazardError):
        ledger.retire("nope", 4)
    # bad reason
    with pytest.raises(BadReasonError):
        ledger.retire("hazard-1", 5, reason="bogus")
    # post-retire mutation refused
    with pytest.raises(RetiredHazardError):
        ledger.mitigate("hazard-1", 6)
    with pytest.raises(RetiredHazardError):
        ledger.update(rec.mitigation_id, 7, "approved")
    # reads still work
    assert ledger.mitigation_record(rec.mitigation_id, 8) is not None
    assert ledger.retire_record("hazard-1", 9) is not None
    rows = ledger.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 5


def test_seq_discipline():
    """Caller seqs strictly increase; rewinds raise bare; failed mutations burn."""
    ledger = AITraceabilityMitigation()
    # malformed seqs raise bare SeqOrderError
    for bad in (0, -1, True, 1.5, "2"):
        with pytest.raises(SeqOrderError):
            ledger.mitigate("hazard-1", bad)
    assert len(ledger.audit_log(0)) == 0
    rec = ledger.mitigate("hazard-1", 1)
    # rewind raises bare, no rejected row
    with pytest.raises(SeqOrderError):
        ledger.mitigate("hazard-2", 1)
    assert len(ledger.audit_log(0)) == 1  # only the mitigated row
    # failed mutation consumes seq (burn) and books rejected
    with pytest.raises(BadStrategyError):
        ledger.mitigate("hazard-2", 2, strategy="bogus")
    rows = ledger.audit_log(0)
    assert [r["kind"] for r in rows] == ["mitigated", "rejected"]
    # seq 2 was consumed; next must be 3
    with pytest.raises(SeqOrderError):
        ledger.mitigate("hazard-2", 2)
    rec2 = ledger.mitigate("hazard-2", 3, strategy="trace-gap-closure")
    assert rec2.mitigation_id == "tmm-2"


def test_audit_shapes_and_leak_ban():
    """Audit rows carry schema/module/version; raw keys are banned."""
    ledger = AITraceabilityMitigation()
    rec = ledger.mitigate("hazard-1", 1, strategy="lineage-restoration")
    rows = ledger.audit_log(0)
    assert len(rows) == 1
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-traceability-mitigation"
    assert row["version"] == "ai-traceability-mitigation.v1"
    assert row["kind"] == "mitigated"
    assert row["seq"] == 1
    assert row["details"]["mitigation_id"] == "tmm-1"
    # raw keys banned at the audit boundary
    with pytest.raises(AITraceabilityMitigationError):
        ai_traceability_mitigation_audit_event("mitigated", 2, hazard="raw text")
    with pytest.raises(AITraceabilityMitigationError):
        ai_traceability_mitigation_audit_event("mitigated", 2, mitigation_evidence="x")
    with pytest.raises(AITraceabilityMitigationError):
        ai_traceability_mitigation_audit_event("mitigated", 2, ethics_review="x")
    with pytest.raises(AITraceabilityMitigationError):
        ai_traceability_mitigation_audit_event("mitigated", 2, fairness_report="x")
    with pytest.raises(AITraceabilityMitigationError):
        ai_traceability_mitigation_audit_event("mitigated", 2, weights="x")
    with pytest.raises(AITraceabilityMitigationError):
        ai_traceability_mitigation_audit_event(
            "mitigated", 2, disclosure_record="x"
        )
    with pytest.raises(AITraceabilityMitigationError):
        ai_traceability_mitigation_audit_event(
            "mitigated", 2, explanation_text="x"
        )
    with pytest.raises(AITraceabilityMitigationError):
        ai_traceability_mitigation_audit_event(
            "mitigated", 2, trade_secret="x"
        )
    with pytest.raises(AITraceabilityMitigationError):
        ai_traceability_mitigation_audit_event(
            "mitigated", 2, traceability_assignment="x"
        )
    with pytest.raises(AITraceabilityMitigationError):
        ai_traceability_mitigation_audit_event(
            "mitigated", 2, lineage_record="x"
        )
    with pytest.raises(AITraceabilityMitigationError):
        ai_traceability_mitigation_audit_event(
            "mitigated", 2, provenance_log="x"
        )
    with pytest.raises(AITraceabilityMitigationError):
        ai_traceability_mitigation_audit_event(
            "mitigated", 2, decision_trace="x"
        )
    with pytest.raises(AITraceabilityMitigationError):
        ai_traceability_mitigation_audit_event(
            "mitigated", 2, traceability_gap="x"
        )
    # unknown kind
    with pytest.raises(AuditKindError):
        ai_traceability_mitigation_audit_event("bogus", 2)
    # pinned vocab values remain emittable
    row2 = ai_traceability_mitigation_audit_event(
        "mitigated", 2, strategy="traceability-assignment", status="proposed"
    )
    assert row2["details"]["strategy"] == "traceability-assignment"
    # bad digest shape
    with pytest.raises(BadDigestError):
        ledger.mitigate("hazard-9", 2, hazard_digest="not-a-digest")


def test_views_and_stats():
    """Pure-read views: records, ids, stats, audit log."""
    ledger = AITraceabilityMitigation()
    r1 = ledger.mitigate("hazard-a", 1, strategy="traceability-assignment")
    r2 = ledger.mitigate("hazard-a", 2, strategy="no-action")
    r3 = ledger.mitigate("hazard-b", 3, strategy="trace-gap-closure")
    assert ledger.mitigation_record("tmm-1", 0) == r1
    with pytest.raises(UnknownMitigationError):
        ledger.mitigation_record("tmm-999", 0)
    assert ledger.mitigations_for("hazard-a", 0) == (r1, r2)
    assert ledger.hazard_ids(0) == ("hazard-a", "hazard-b")
    assert ledger.mitigation_ids(0) == ("tmm-1", "tmm-2", "tmm-3")
    assert ledger.retired_ids(0) == ()
    stats = ledger.stats(0)
    assert stats == {
        "n_hazards": 2,
        "n_mitigations": 3,
        "n_retired": 0,
        "seq": 3,
        "version": "ai-traceability-mitigation.v1",
    }
    ledger.retire("hazard-a", 4)
    assert ledger.retired_ids(0) == ("hazard-a",)
    assert ledger.stats(0)["n_retired"] == 1
    kinds = [r["kind"] for r in ledger.audit_log(0)]
    assert kinds == ["mitigated", "mitigated", "mitigated", "retired"]


def test_main_subprocess():
    """main() self-check runs green in a subprocess."""
    proc = subprocess.run(
        [sys.executable, "-m", "ai_traceability_mitigation"],
        capture_output=True,
        text=True,
        cwd=str(Path(ai_traceability_mitigation.__file__).parent),
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-traceability-mitigation OK" in proc.stdout
