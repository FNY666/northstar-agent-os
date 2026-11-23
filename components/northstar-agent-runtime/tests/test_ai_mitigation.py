"""Tests for the ai_mitigation decision ledger (Simulated).

House contract: frozen records, caller int seqs strictly increasing
with claim-then-burn, no wall-clock, RLock-guarded, fail-closed
taxonomy, stdlib-only AST-verified, sha256: digest pins, audit.ndjson/1.
"""
from __future__ import annotations

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_mitigation
from ai_mitigation import (
    AI_MITIGATION_VERSION,
    SCHEMA_PIN,
    AIMitigation,
    AIMitigationError,
    ALLOWED_TRANSITIONS,
    EFFECTIVENESS,
    MITIGATION_STATUSES,
    MITIGATION_STRATEGIES,
    POSTURES,
    RETIRE_REASONS,
    TERMINAL_STATUSES,
    AuditKindError,
    BadDigestError,
    BadEffectivenessError,
    BadRiskError,
    BadStatusError,
    BadStrategyError,
    BadTransitionError,
    RetiredRiskError,
    SeqOrderError,
    UnknownMitigationError,
    UnknownRiskError,
    ai_mitigation_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_MITIGATION_VERSION == "ai-mitigation.v1"
    assert SCHEMA_PIN == "northstar.ai-mitigation.v1"
    assert MITIGATION_STRATEGIES == (
        "avoid",
        "reduce",
        "transfer",
        "accept",
        "contain",
        "monitor",
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
        "residual-risk-accepted",
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
    path = Path(ai_mitigation.__file__)
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
            assert node.module is None or node.module.split(".")[0] in allowed


def test_mitigate_roundtrip():
    """mitigate() mints mgt-N ids; records are frozen and digest-verified."""
    ledger = AIMitigation()
    rec = ledger.mitigate(
        "risk-1",
        1,
        strategy="reduce",
        risk_digest=GOOD_DIGEST,
    )
    assert rec.mitigation_id == "mgt-1"
    assert rec.risk_id == "risk-1"
    assert rec.seq == 1
    assert rec.strategy == "reduce"
    assert rec.status == "proposed"
    assert rec.effectiveness == "unrated"
    assert rec.risk_digest == GOOD_DIGEST
    assert rec.verify()
    # frozen dataclass
    with pytest.raises(Exception):
        rec.status = "implemented"  # type: ignore
    rec2 = ledger.mitigate("risk-1", 2)
    assert rec2.mitigation_id == "mgt-2"


def test_mitigate_bad_inputs():
    """Bad inputs fail closed: seq burned, rejected row booked, rewinds bare."""
    ledger = AIMitigation()
    before = len(ledger.audit_log(0))
    # rewind on genesis (seq 0 <= seq 0) raises bare with zero rows
    with pytest.raises(SeqOrderError):
        ledger.mitigate("risk-1", 0)
    assert len(ledger.audit_log(0)) == before
    bad_calls = [
        ("", 1, "reduce"),
        (True, 2, "reduce"),
        ("risk-1", 3, "not-a-strategy"),
        ("risk-1", 4, "reduce"),
    ]
    for risk_id, seq, strategy in bad_calls[:3]:
        with pytest.raises(AIMitigationError):
            ledger.mitigate(risk_id, seq, strategy=strategy)
    with pytest.raises(AIMitigationError):
        ledger.mitigate("risk-1", 4, risk_digest="bad-digest")
    rows = ledger.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 4
    for r in rejected:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-mitigation"


def test_full_strategy_vocabulary():
    """All 6 risk-treatment strategies are accepted."""
    ledger = AIMitigation()
    seq = 1
    for strategy in MITIGATION_STRATEGIES:
        rec = ledger.mitigate(f"risk-{strategy}", seq, strategy=strategy)
        assert rec.strategy == strategy
        assert rec.verify()
        seq += 1


def test_update_transition_ladder():
    """Status transitions follow the fail-closed ladder; records re-pin."""
    ledger = AIMitigation()
    rec = ledger.mitigate("risk-u", 1, strategy="contain")
    rec = ledger.update(rec.mitigation_id, 2, "approved")
    assert rec.status == "approved"
    assert rec.effectiveness == "unrated"
    assert rec.verify()
    rec = ledger.update(rec.mitigation_id, 3, "in-progress")
    assert rec.status == "in-progress"
    assert rec.verify()
    rec = ledger.update(rec.mitigation_id, 4, "implemented", effectiveness="full")
    assert rec.status == "implemented"
    assert rec.effectiveness == "full"
    assert rec.verify()
    # seq of the record is the update's seq
    assert rec.seq == 4
    # abandon path from proposed
    rec2 = ledger.mitigate("risk-u2", 5, strategy="avoid")
    rec2 = ledger.update(rec2.mitigation_id, 6, "abandoned")
    assert rec2.status == "abandoned"
    assert rec2.verify()


def test_update_bad_transitions():
    """Skips, terminal escapes, and premature ratings fail closed."""
    ledger = AIMitigation()
    rec = ledger.mitigate("risk-b", 1)
    # unknown mitigation id: burned + rejected
    with pytest.raises(UnknownMitigationError):
        ledger.update("mgt-999", 2, "approved")
    # skip ladder rung: proposed -> implemented not allowed
    with pytest.raises(BadTransitionError):
        ledger.update(rec.mitigation_id, 3, "implemented")
    # bad status value
    with pytest.raises(BadStatusError):
        ledger.update(rec.mitigation_id, 4, "deployed")
    # rating before implemented is refused
    ledger.update(rec.mitigation_id, 5, "approved")
    with pytest.raises(BadEffectivenessError):
        ledger.update(rec.mitigation_id, 6, "in-progress", effectiveness="full")
    ledger.update(rec.mitigation_id, 7, "in-progress")
    rec = ledger.update(rec.mitigation_id, 8, "implemented", effectiveness="partial")
    assert rec.effectiveness == "partial"
    # terminal statuses allow no further transitions
    with pytest.raises(BadTransitionError):
        ledger.update(rec.mitigation_id, 9, "abandoned")
    rows = ledger.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 5
    assert {r["details"]["rejected_kind"] for r in rejected} == {
        "UnknownMitigationError",
        "BadTransitionError",
        "BadStatusError",
        "BadEffectivenessError",
    }
    # retired risk refuses updates too
    ledger.retire("risk-b", 10)
    with pytest.raises(RetiredRiskError):
        ledger.update(rec.mitigation_id, 11, "abandoned")


def test_verify_semantics():
    """verify() is a pure read: verified verdict, read purity, unknown refusal."""
    ledger = AIMitigation()
    rec = ledger.mitigate("risk-v", 1)
    before = len(ledger.audit_log(0))
    rep = ledger.verify(rec.mitigation_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.record_id == rec.mitigation_id
    assert rep.verify()
    # pure read: seq not consumed, no audit row
    assert ledger.stats(0)["seq"] == 1
    assert len(ledger.audit_log(0)) == before
    with pytest.raises(UnknownMitigationError):
        ledger.verify("mgt-999", 3)
    with pytest.raises(SeqOrderError):
        ledger.verify(rec.mitigation_id, True)


def test_verify_tamper_as_data():
    """A swapped digest pin flips the verdict to tampered - booked as data."""
    ledger = AIMitigation()
    rec = ledger.mitigate("risk-t", 1)
    orig = ledger.mitigation_record(rec.mitigation_id, 0)
    ledger._mitigations[rec.mitigation_id] = dataclasses.replace(
        orig, digest="sha256:" + "00" * 32
    )
    rep = ledger.verify(rec.mitigation_id, 2)
    assert rep.verdict == "tampered"
    assert rep.integrity_ok is False
    assert rep.verify()


def test_evaluate_posture_math():
    """All reachable postures, with under-mitigation > ineffective >
    residual-risk-accepted > mitigated > partially-mitigated > abandoned."""
    ledger = AIMitigation()

    def push(risk, strategy, effectiveness=None):
        nonlocal_seq = getattr(push, "seq", 0) + 1
        push.seq = nonlocal_seq
        rec = ledger.mitigate(risk, nonlocal_seq, strategy=strategy)
        push.seq += 1
        ledger.update(rec.mitigation_id, push.seq, "approved")
        push.seq += 1
        ledger.update(rec.mitigation_id, push.seq, "in-progress")
        push.seq += 1
        ledger.update(rec.mitigation_id, push.seq, "implemented",
                      effectiveness=effectiveness)
        return rec

    # mitigated: all implemented, at least one full, none none
    push("risk-a", "reduce", "full")
    assert ledger.evaluate("risk-a", push.seq + 1).posture == "mitigated"
    # partially-mitigated: all terminal, no full, some partial
    push("risk-b", "contain", "partial")
    assert ledger.evaluate("risk-b", push.seq + 1).posture == "partially-mitigated"
    # ineffective: any implemented with effectiveness none
    push("risk-c", "monitor", "none")
    ev = ledger.evaluate("risk-c", push.seq + 1)
    assert ev.posture == "ineffective"
    assert ev.n_none == 1
    assert ev.verify()
    # residual-risk-accepted: implemented accept with full
    push("risk-d", "accept", "full")
    assert ledger.evaluate("risk-d", push.seq + 1).posture == "residual-risk-accepted"
    # under-mitigation outranks ineffective: one proposed alongside a none
    rec = ledger.mitigate("risk-e", push.seq + 1, strategy="reduce")
    ev = ledger.evaluate("risk-e", push.seq + 2)
    assert ev.posture == "under-mitigation"
    assert ev.n_terminal == 0
    assert ev.integrity_ok is True
    push.seq = ev.seq
    # abandoned: all abandoned
    rec2 = ledger.mitigate("risk-f", push.seq + 1, strategy="avoid")
    ledger.update(rec2.mitigation_id, push.seq + 2, "abandoned")
    push.seq += 2
    assert ledger.evaluate("risk-f", push.seq + 1).posture == "abandoned"
    # unknown risk refused
    with pytest.raises(UnknownRiskError):
        ledger.evaluate("no-such-risk", push.seq + 2)


def test_retire_terminality():
    """Retired risk ids refuse mutations; ids never recycled; reads still work."""
    ledger = AIMitigation()
    rec = ledger.mitigate("risk-r", 1)
    ret = ledger.retire("risk-r", 2, reason="superseded")
    assert ret.verify()
    assert ret.reason == "superseded"
    # post-retire mutation refused (fail-closed), seq burned
    before = len(ledger.audit_log(0))
    with pytest.raises(RetiredRiskError):
        ledger.mitigate("risk-r", 3)
    with pytest.raises(RetiredRiskError):
        ledger.update(rec.mitigation_id, 4, "approved")
    assert len(ledger.audit_log(0)) == before + 2
    # re-retire refused
    with pytest.raises(RetiredRiskError):
        ledger.retire("risk-r", 5)
    # reads still work
    assert ledger.evaluate("risk-r", 6).posture == "under-mitigation"
    assert ledger.retire_record("risk-r", 7).reason == "superseded"
    # unknown risk retire refused
    with pytest.raises(UnknownRiskError):
        ledger.retire("no-such-risk", 8)


def test_seq_discipline():
    """Claim-then-burn: rewinds raise bare, failures burn seq, ids never gap-widen."""
    ledger = AIMitigation()
    with pytest.raises(SeqOrderError):
        ledger.mitigate("risk-s", True)
    rec = ledger.mitigate("risk-s", 1)
    # duplicate seq is a rewind: raises bare, no audit row
    before = len(ledger.audit_log(0))
    with pytest.raises(SeqOrderError):
        ledger.mitigate("risk-s", 1)
    assert len(ledger.audit_log(0)) == before
    # failed mutation burns the seq: next valid call must exceed it
    with pytest.raises(BadStrategyError):
        ledger.mitigate("risk-s", 2, strategy="nope")
    with pytest.raises(SeqOrderError):
        ledger.mitigate("risk-s", 2)
    rec2 = ledger.mitigate("risk-s", 3)
    assert rec2.mitigation_id == "mgt-2"
    # record seq equals the claimed caller seq
    assert rec.seq == 1
    assert rec2.seq == 3


def test_audit_shapes_and_leak_ban():
    """Audit rows carry audit.ndjson/1 shape; raw risk material is banned."""
    ledger = AIMitigation()
    rec = ledger.mitigate("risk-a", 1, risk_digest=GOOD_DIGEST)
    ledger.update(rec.mitigation_id, 2, "approved")
    rows = ledger.audit_log(0)
    assert len(rows) == 2
    first = rows[0]
    assert first["schema"] == "audit.ndjson/1"
    assert first["module"] == "ai-mitigation"
    assert first["version"] == AI_MITIGATION_VERSION
    assert first["kind"] == "mitigated"
    assert first["seq"] == 1
    assert first["details"]["risk_digest"] == GOOD_DIGEST
    assert rows[1]["kind"] == "updated"
    assert rows[1]["details"]["old_status"] == "proposed"
    # banned raw keys raise fail-closed on audit construction
    with pytest.raises(AIMitigationError):
        ai_mitigation_audit_event("mitigated", 3, risk_description="raw text")
    with pytest.raises(AIMitigationError):
        ai_mitigation_audit_event("mitigated", 3, mitigation_evidence="raw")
    with pytest.raises(AIMitigationError):
        ai_mitigation_audit_event("mitigated", 3, weights="w")
    # pinned vocab values remain emittable as declared data
    row = ai_mitigation_audit_event("mitigated", 3, strategy="reduce", status="proposed")
    assert row["details"]["strategy"] == "reduce"
    with pytest.raises(AuditKindError):
        ai_mitigation_audit_event("no-such-kind", 3)


def test_views_and_stats():
    """Views are pure reads with seq shape-validation; stats tally ledger state."""
    ledger = AIMitigation()
    ledger.mitigate("risk-v1", 1, strategy="reduce")
    ledger.mitigate("risk-v1", 2, strategy="avoid")
    ledger.mitigate("risk-v2", 3, strategy="monitor")
    assert ledger.risk_ids(0) == ("risk-v1", "risk-v2")
    assert ledger.mitigation_ids(0) == ("mgt-1", "mgt-2", "mgt-3")
    assert len(ledger.mitigations_for("risk-v1", 0)) == 2
    assert ledger.mitigations_for("no-such-risk", 0) == ()
    st = ledger.stats(0)
    assert st["n_risks"] == 2
    assert st["n_mitigations"] == 3
    assert st["n_retired"] == 0
    assert st["version"] == AI_MITIGATION_VERSION
    ledger.retire("risk-v1", 4)
    assert ledger.retired_ids(0) == ("risk-v1",)
    assert ledger.stats(0)["n_retired"] == 1
    with pytest.raises(SeqOrderError):
        ledger.stats(True)
    with pytest.raises(UnknownMitigationError):
        ledger.mitigation_record("mgt-999", 0)


def test_main_subprocess():
    """main() self-check runs green in a subprocess."""
    proc = subprocess.run(
        [sys.executable, "-c", "import ai_mitigation; ai_mitigation.main()"],
        cwd=str(Path(ai_mitigation.__file__).parent),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-mitigation OK" in proc.stdout
