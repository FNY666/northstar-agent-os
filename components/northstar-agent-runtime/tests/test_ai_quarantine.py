"""Tests for the ai_quarantine decision ledger (Simulated).

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

import ai_quarantine
from ai_quarantine import (
    AI_QUARANTINE_VERSION,
    SCHEMA_PIN,
    CRITICAL_RISK,
    AIQuarantine,
    AIQuarantineError,
    AuditKindError,
    BadAssetError,
    BadDigestError,
    BadDispositionError,
    BadReasonError,
    BadRiskError,
    NoActiveHoldError,
    POSTURES,
    QUARANTINE_REASONS,
    RELEASE_DISPOSITIONS,
    SeqOrderError,
    UnknownAssetError,
    UnknownRecordError,
    ai_quarantine_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_QUARANTINE_VERSION == "ai-quarantine.v1"
    assert SCHEMA_PIN == "northstar.ai-quarantine.v1"
    assert CRITICAL_RISK == 75
    assert QUARANTINE_REASONS == (
        "suspected-misalignment",
        "data-contamination",
        "policy-violation",
        "tool-misuse",
        "unverified-dependency",
        "harm-indicator",
        "deceptive-behavior",
        "specification-gaming",
    )
    assert RELEASE_DISPOSITIONS == ("cleared", "condemned")
    assert POSTURES == ("held-critical", "held", "condemned", "cleared")


def test_stdlib_only():
    """AST self-check: only stdlib (plus canonical_json fallback) is imported."""
    assert stdlib_only()
    path = Path(ai_quarantine.__file__)
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


def test_quarantine_roundtrip_verify_and_frozenness():
    """quarantine -> minted id, digest verifies, record is frozen."""
    ledger = AIQuarantine()
    rec = ledger.quarantine(
        "asset-1", 1, reason="data-contamination", risk=42,
        asset_digest=GOOD_DIGEST,
    )
    assert rec.quarantine_id == "qtn-1"
    assert rec.asset_id == "asset-1"
    assert rec.reason == "data-contamination"
    assert rec.risk == 42
    assert rec.asset_digest == GOOD_DIGEST
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    with pytest.raises(Exception):
        rec.risk = 99  # frozen dataclass
    audit = ledger.audit_log(0)
    assert len(audit) == 1
    assert audit[0]["kind"] == "quarantined"
    assert audit[0]["details"]["reason"] == "data-contamination"
    assert ledger.holds_for("asset-1", 0) == (rec,)


def test_quarantine_bad_inputs_burn_seq_and_book_rejected():
    """Bad inputs fail closed: seq consumed, rejected row booked."""
    ledger = AIQuarantine()
    cases = [
        ("", 1, {}, BadAssetError),                        # empty asset_id
        ("a1", 1, {"reason": "nope"}, BadReasonError),
        ("a1", 1, {"risk": -1}, BadRiskError),
        ("a1", 1, {"risk": 101}, BadRiskError),
        ("a1", 1, {"risk": True}, BadRiskError),            # bool refused
        ("a1", 1, {"risk": 3.5}, BadRiskError),
        ("a1", 1, {"asset_digest": "bad"}, BadDigestError),
    ]
    seq = 1
    for asset_id, _, kwargs, exc in cases:
        with pytest.raises(exc):
            ledger.quarantine(asset_id, seq, **kwargs)
        seq += 1
    # risk boundaries 0 and 100 are accepted
    r0 = ledger.quarantine("a0", seq, risk=0)
    assert r0.risk == 0
    r100 = ledger.quarantine("a100", seq + 1, risk=100)
    assert r100.risk == 100
    audit = ledger.audit_log(0)
    rejected = [r for r in audit if r["kind"] == "rejected"]
    assert len(rejected) == len(cases)
    assert all(r["details"]["rejected_kind"].endswith("Error") for r in rejected)


def test_full_quarantine_reason_vocabulary_accepted():
    """Every pinned quarantine reason books cleanly."""
    ledger = AIQuarantine()
    seq = 1
    for i, reason in enumerate(QUARANTINE_REASONS):
        rec = ledger.quarantine(f"asset-{i}", seq, reason=reason, risk=5)
        assert rec.reason == reason
        assert rec.verify()
        seq += 1
    assert ledger.stats(0)["n_holds"] == len(QUARANTINE_REASONS)


def test_release_roundtrip_and_disposition_vocabulary():
    """release disposes all active holds; full disposition vocabulary."""
    ledger = AIQuarantine()
    ledger.quarantine("a1", 1, reason="tool-misuse", risk=10)
    ledger.quarantine("a1", 2, reason="policy-violation", risk=20)
    assert len(ledger.holds_for("a1", 0)) == 2
    for i, disposition in enumerate(RELEASE_DISPOSITIONS):
        # re-quarantine so each release disposes an active hold
        ledger.quarantine("a1", 3 + 2 * i, risk=5)
        rel = ledger.release("a1", 4 + 2 * i, disposition=disposition)
        assert rel.release_id == f"rel-{i + 1}"
        assert rel.disposition == disposition
        assert rel.verify()
        assert ledger.holds_for("a1", 0) == ()
        assert rel.n_holds_disposed >= 1
    assert ledger.stats(0)["n_releases"] == len(RELEASE_DISPOSITIONS)
    with pytest.raises(Exception):
        rel.disposition = "cleared"  # frozen dataclass


def test_release_refusals_unknown_empty_bad_disposition():
    """release is fail-closed: unknown/empty holds/bad dispositions refused."""
    ledger = AIQuarantine()
    with pytest.raises(UnknownAssetError):
        ledger.release("nope", 1, disposition="cleared")
    ledger.quarantine("a1", 2, risk=10)
    with pytest.raises(BadDispositionError):
        ledger.release("a1", 3, disposition="guilty")
    ledger.release("a1", 4, disposition="cleared")
    # no active holds left -> refused, seq burned
    with pytest.raises(NoActiveHoldError):
        ledger.release("a1", 5, disposition="cleared")
    audit = ledger.audit_log(0)
    rejected = [r for r in audit if r["kind"] == "rejected"]
    # unknown(1) + bad disposition(1) + no active hold(1) = 3
    assert len(rejected) == 3


def test_verify_semantics_tamper_and_read_purity():
    """verify is a pure read; tamper reported as data; unknown refused."""
    import dataclasses

    ledger = AIQuarantine()
    rec = ledger.quarantine("a1", 1, risk=10)
    rel = ledger.release("a1", 2, disposition="cleared")
    for rid in (rec.quarantine_id, rel.release_id):
        rep = ledger.verify(rid, 3)
        assert rep.verdict == "verified"
        assert rep.integrity_ok
        assert rep.verify()
    # tamper reported as data, never raised
    tampered = dataclasses.replace(rec, risk=99)
    ledger._quarantines[rec.quarantine_id] = tampered
    rep = ledger.verify(rec.quarantine_id, 4)
    assert rep.verdict == "tampered"
    assert not rep.integrity_ok
    ev = ledger.evaluate("a1", 5)
    assert not ev.integrity_ok  # tamper flips evaluate's integrity too
    with pytest.raises(UnknownRecordError):
        ledger.verify("qtn-999", 6)
    # read purity: same seq twice, no audit rows, no seq consumption
    a = ledger.verify(rel.release_id, 7)
    b = ledger.verify(rel.release_id, 7)
    assert a.digest == b.digest
    assert all(r["kind"] != "verified" for r in ledger.audit_log(0))


def test_evaluate_posture_math_and_precedence():
    """Posture math follows the documented precedence."""
    # held-critical: active hold + risk >= 75
    l1 = AIQuarantine()
    l1.quarantine("c1", 1, risk=90)
    assert l1.evaluate("c1", 2).posture == "held-critical"
    # held: active hold + low risk
    l2 = AIQuarantine()
    l2.quarantine("c2", 1, risk=10)
    assert l2.evaluate("c2", 2).posture == "held"
    # held-critical wins over held when several holds are active
    l3 = AIQuarantine()
    l3.quarantine("c3", 1, risk=10)
    l3.quarantine("c3", 2, risk=80)
    ev3 = l3.evaluate("c3", 3)
    assert ev3.posture == "held-critical"
    assert ev3.n_active == 2
    assert ev3.n_critical == 1
    # cleared: no active holds, all releases cleared
    l4 = AIQuarantine()
    l4.quarantine("c4", 1, risk=90)
    l4.release("c4", 2, disposition="cleared")
    ev4 = l4.evaluate("c4", 3)
    assert ev4.posture == "cleared"
    assert ev4.n_holds == 1
    assert ev4.n_releases == 1
    assert ev4.n_active == 0
    # condemned: no active holds, any condemned release
    l5 = AIQuarantine()
    l5.quarantine("c5", 1, risk=10)
    l5.release("c5", 2, disposition="cleared")
    l5.quarantine("c5", 3, risk=10)
    l5.release("c5", 4, disposition="condemned")
    assert l5.evaluate("c5", 5).posture == "condemned"
    # active hold outranks any prior condemned release
    l6 = AIQuarantine()
    l6.quarantine("c6", 1, risk=10)
    l6.release("c6", 2, disposition="condemned")
    l6.quarantine("c6", 3, risk=5)
    assert l6.evaluate("c6", 4).posture == "held"


def test_evaluate_read_purity_and_unknown_asset():
    """evaluate is a pure read; unknown assets raise."""
    ledger = AIQuarantine()
    ledger.quarantine("a1", 1, risk=10)
    a = ledger.evaluate("a1", 2)
    b = ledger.evaluate("a1", 2)
    assert a.digest == b.digest
    assert a.posture == "held"
    assert a.integrity_ok
    assert all(r["kind"] != "evaluated" for r in ledger.audit_log(0))
    # read seq is shape-validated but never consumed
    with pytest.raises(SeqOrderError):
        ledger.evaluate("a1", True)
    with pytest.raises(UnknownAssetError):
        ledger.evaluate("nope", 3)


def test_release_then_requarantine_starts_new_hold_chain():
    """release ends a hold chain; re-quarantine starts a new one."""
    ledger = AIQuarantine()
    h1 = ledger.quarantine("a1", 1, risk=90)
    assert ledger.evaluate("a1", 2).posture == "held-critical"
    rel1 = ledger.release("a1", 3, disposition="condemned")
    assert rel1.n_holds_disposed == 1
    assert ledger.evaluate("a1", 4).posture == "condemned"
    h2 = ledger.quarantine("a1", 5, reason="unverified-dependency", risk=5)
    assert h2.quarantine_id == "qtn-2"
    assert ledger.evaluate("a1", 6).posture == "held"
    assert ledger.quarantine_history("a1", 0) == (h1, h2)
    rel2 = ledger.release("a1", 7, disposition="cleared")
    assert rel2.release_id == "rel-2"
    # condemned outranks cleared across hold chains: no active holds,
    # but a condemned release exists -> condemned (documented precedence)
    assert ledger.evaluate("a1", 8).posture == "condemned"
    audit = ledger.audit_log(0)
    assert [r["kind"] for r in audit] == [
        "quarantined", "released", "quarantined", "released",
    ]


def test_seq_discipline_rewind_malformed_and_burn():
    """Rewinds raise bare; malformed seqs raise; burns consume seq."""
    ledger = AIQuarantine()
    ledger.quarantine("a1", 1, risk=10)
    with pytest.raises(SeqOrderError):
        ledger.quarantine("a2", 1)  # rewind: bare, zero rows
    assert len([r for r in ledger.audit_log(0) if r["kind"] == "rejected"]) == 0
    for bad in (True, "2", 2.0, None):
        with pytest.raises(SeqOrderError):
            ledger.quarantine("a2", bad)
    assert len([r for r in ledger.audit_log(0) if r["kind"] == "rejected"]) == 0
    # failed mutation consumes its seq
    with pytest.raises(BadReasonError):
        ledger.quarantine("a2", 2, reason="nope")
    # seq 2 is now burned; seq 3 works
    rec = ledger.quarantine("a2", 3, risk=1)
    assert rec.quarantine_id == "qtn-2"
    assert len([r for r in ledger.audit_log(0) if r["kind"] == "rejected"]) == 1


def test_audit_shapes_leak_ban_and_bad_kind():
    """Audit rows have the fixed shape; banned keys raise; bad kinds raise."""
    ledger = AIQuarantine()
    rec = ledger.quarantine("a1", 1, risk=10)
    row = ledger.audit_log(0)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-quarantine"
    assert row["version"] == "ai-quarantine.v1"
    assert row["kind"] == "quarantined"
    assert row["seq"] == 1
    assert row["details"]["quarantine_id"] == rec.quarantine_id
    assert row["details"]["risk"] == 10
    for banned in ("model_weights", "trajectories", "forensic_data",
                   "prompts", "telemetry", "training_data"):
        with pytest.raises(AIQuarantineError):
            ai_quarantine_audit_event("quarantined", 9, **{banned: "raw"})
    with pytest.raises(AuditKindError):
        ai_quarantine_audit_event("bogus", 9)
    with pytest.raises(SeqOrderError):
        ai_quarantine_audit_event("quarantined", True)
    # pinned vocab values cross the boundary fine
    ok = ai_quarantine_audit_event("quarantined", 9, reason="near-miss-reason",
                                   risk=10, asset_digest=GOOD_DIGEST)
    assert ok["details"]["reason"] == "near-miss-reason"


def test_digest_determinism_views_and_unknown_lookups():
    """Cross-instance digest determinism; views; unknown lookups fail closed."""
    a = AIQuarantine()
    b = AIQuarantine()
    ra = a.quarantine("a1", 1, reason="policy-violation", risk=3,
                      asset_digest=GOOD_DIGEST)
    rb = b.quarantine("a1", 1, reason="policy-violation", risk=3,
                      asset_digest=GOOD_DIGEST)
    assert ra.digest == rb.digest
    ia = a.release("a1", 2, disposition="cleared")
    ib = b.release("a1", 2, disposition="cleared")
    assert ia.digest == ib.digest
    ea = a.evaluate("a1", 3)
    eb = b.evaluate("a1", 3)
    assert ea.digest == eb.digest
    assert a.quarantine_record("qtn-1", 0) == ra
    assert a.release_record("rel-1", 0) == ia
    assert [r.quarantine_id for r in a.quarantine_history("a1", 0)] == ["qtn-1"]
    assert [r.release_id for r in a.release_history("a1", 0)] == ["rel-1"]
    assert a.holds_for("a1", 0) == ()
    assert a.asset_ids(0) == ("a1",)
    assert a.quarantine_ids(0) == ("qtn-1",)
    assert a.release_ids(0) == ("rel-1",)
    with pytest.raises(UnknownRecordError):
        a.quarantine_record("qtn-999", 0)
    with pytest.raises(UnknownRecordError):
        a.release_record("rel-999", 0)


def test_thread_safety_frozen_records_and_main_via_subprocess():
    """8-thread read smoke; records frozen; main() subprocess self-check."""
    ledger = AIQuarantine()
    ledger.quarantine("a1", 1, risk=10)
    ledger.release("a1", 2, disposition="cleared")
    errors = []

    def reader():
        try:
            for _ in range(50):
                assert ledger.evaluate("a1", 0).posture == "cleared"
                assert ledger.stats(0)["n_holds"] == 1
                assert len(ledger.audit_log(0)) == 2
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    proc = subprocess.run(
        [sys.executable, "ai_quarantine.py"],
        cwd=Path(ai_quarantine.__file__).parent,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-quarantine OK" in proc.stdout
