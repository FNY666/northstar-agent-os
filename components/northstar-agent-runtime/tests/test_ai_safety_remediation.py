"""Tests for the ai-safety-remediation decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_safety_remediation.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_safety_remediation", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_safety_remediation"] = module
    spec.loader.exec_module(module)
    return module


asr = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert asr.AI_SAFETY_REMEDIATION_VERSION == "ai-safety-remediation.v1"
    assert asr.SCHEMA_PIN == "northstar.ai-safety-remediation.v1"
    assert asr.SAFETY_REMEDIATION_KINDS == (
        "hazard-mitigation",
        "safety-interlock",
        "output-filter",
        "capability-revocation",
        "deployment-hold",
        "model-rollback",
        "safety-retraining",
        "no-action",
    )
    assert asr.REMEDIATION_OUTCOMES == ("remediated", "partial", "failed", "inconclusive")
    assert asr.VERIFY_VERDICTS == ("verified", "tampered")
    assert asr.POSTURES == (
        "unevaluated",
        "contested",
        "partially-remediated",
        "failed",
        "remediated",
    )
    assert asr.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert asr.AUDIT_KINDS == ("remediated", "retired", "rejected")


# 2. stdlib-only AST check + stdlib_only()
def test_stdlib_only_ast():
    assert asr.stdlib_only() is True
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib", "json", "threading", "dataclasses", "typing",
        "__future__", "ast", "pathlib", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed


# 3. remediate roundtrip + srf-N minting + verify() + frozen-ness
def test_remediate_roundtrip():
    ledger = asr.AISafetyRemediation()
    rec = ledger.remediate(
        "hazard-1", 1, safety_remediation_kind="hazard-mitigation",
        outcome="remediated", safety_digest=PIN,
    )
    assert rec.remediation_id == "srf-1"
    assert rec.hazard_id == "hazard-1"
    assert rec.seq == 1
    assert rec.verify() is True
    rec2 = ledger.remediate("hazard-2", 2)
    assert rec2.remediation_id == "srf-2"
    assert rec2.safety_remediation_kind == "no-action"
    assert rec2.outcome == "inconclusive"
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.outcome = "failed"  # type: ignore[misc]


# 4. remediate bad-input table + seq-burn + rejected-row accounting + rewind bare
def test_remediate_bad_inputs():
    ledger = asr.AISafetyRemediation()
    bads = [
        ("", 1, {}, asr.BadHazardError),
        ("   ", 1, {}, asr.BadHazardError),
        (123, 1, {}, asr.BadHazardError),
        (True, 1, {}, asr.BadHazardError),
        ("h", 1, {"safety_remediation_kind": "nonsense"}, asr.BadKindError),
        ("h", 1, {"outcome": "fixed"}, asr.BadOutcomeError),
        ("h", 1, {"safety_digest": "sha256:zzz"}, asr.BadDigestError),
        ("h", 1, {"safety_digest": "sha256:" + "gg" * 32}, asr.BadDigestError),
        ("h", 1, {"safety_digest": True}, asr.BadDigestError),
    ]
    seq = 1
    for hazard, _s, kw, exc in bads:
        with pytest.raises(exc):
            ledger.remediate(hazard, seq, **kw)
        seq += 1
    rows = ledger.audit_log(0)
    assert len(rows) == len(bads)
    assert all(r["kind"] == "rejected" for r in rows)
    assert all(r["module"] == "ai-safety-remediation" for r in rows)
    assert all(r["schema"] == "audit.ndjson/1" for r in rows)
    assert [r["seq"] for r in rows] == list(range(1, len(bads) + 1))
    # every seq consumed: next mutation must use the following seq
    rec = ledger.remediate("h-ok", seq, outcome="remediated")
    assert rec.seq == seq
    assert rec.remediation_id == "srf-1"  # counters only advance on success
    # rewind raises bare: no seq consumed, no audit row
    n_rows = len(ledger.audit_log(0))
    with pytest.raises(asr.SeqOrderError):
        ledger.remediate("h-ok", seq)
    assert len(ledger.audit_log(0)) == n_rows


# 5. full safety-remediation-kind vocabulary acceptance
def test_full_kind_vocabulary():
    ledger = asr.AISafetyRemediation()
    for i, kind in enumerate(asr.SAFETY_REMEDIATION_KINDS, start=1):
        rec = ledger.remediate("h", i, safety_remediation_kind=kind, outcome="remediated")
        assert rec.safety_remediation_kind == kind
        assert rec.verify() is True


# 6. full outcome vocabulary + digest pin handling
def test_full_outcome_vocabulary():
    ledger = asr.AISafetyRemediation()
    for i, outcome in enumerate(asr.REMEDIATION_OUTCOMES, start=1):
        rec = ledger.remediate(
            "h", i, safety_remediation_kind="output-filter",
            outcome=outcome, safety_digest=PIN2,
        )
        assert rec.outcome == outcome
        assert rec.safety_digest == PIN2
        assert rec.verify() is True
    ev = ledger.evaluate("h", 5)
    assert ev.n_remediations == 4
    assert ev.n_remediated == 1 and ev.n_partial == 1
    assert ev.n_failed == 1 and ev.n_inconclusive == 1


# 7. verify semantics + tamper-as-data + read purity + unknown refusal
def test_verify_semantics():
    ledger = asr.AISafetyRemediation()
    rec = ledger.remediate("h", 1, outcome="remediated", safety_digest=PIN)
    n_rows = len(ledger.audit_log(0))
    rep = ledger.verify(rec.remediation_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # pure read: no audit rows, seq shape only validated
    assert len(ledger.audit_log(0)) == n_rows
    rep2 = ledger.verify(rec.remediation_id, 2)  # same seq twice is fine
    assert rep2.verdict == "verified"
    # tamper reported as data, never raised
    object.__setattr__(rec, "outcome", "failed")
    rep3 = ledger.verify(rec.remediation_id, 3)
    assert rep3.verdict == "tampered"
    assert rep3.integrity_ok is False
    with pytest.raises(asr.UnknownRecordError):
        ledger.verify("srf-999", 4)
    with pytest.raises(asr.SeqOrderError):
        ledger.verify(rec.remediation_id, "x")


# 8. evaluate posture math (all 5 postures + precedence)
def test_evaluate_postures():
    ledger = asr.AISafetyRemediation()
    # remediated: all remediated
    ledger.remediate("h-rem", 1, outcome="remediated")
    ledger.remediate("h-rem", 2, outcome="remediated")
    assert ledger.evaluate("h-rem", 3).posture == "remediated"
    # partially-remediated: partial only
    ledger.remediate("h-part", 4, outcome="partial")
    assert ledger.evaluate("h-part", 5).posture == "partially-remediated"
    # contested: inconclusive present
    ledger.remediate("h-cont", 6, outcome="partial")
    ledger.remediate("h-cont", 7, outcome="inconclusive")
    assert ledger.evaluate("h-cont", 8).posture == "contested"
    # failed outranks contested and partial
    ledger.remediate("h-fail", 9, outcome="remediated")
    ledger.remediate("h-fail", 10, outcome="inconclusive")
    ledger.remediate("h-fail", 11, outcome="failed")
    ev = ledger.evaluate("h-fail", 12)
    assert ev.posture == "failed"
    assert ev.n_remediations == 3
    assert ev.integrity_ok is True
    with pytest.raises(asr.UnknownHazardError):
        ledger.evaluate("h-missing", 13)


# 9. evaluate read purity + integrity flip on tamper
def test_evaluate_purity_and_integrity_flip():
    ledger = asr.AISafetyRemediation()
    rec = ledger.remediate("h", 1, outcome="remediated", safety_digest=PIN)
    n_rows = len(ledger.audit_log(0))
    ev = ledger.evaluate("h", 2)
    assert ev.posture == "remediated"
    assert ev.integrity_ok is True
    assert ev.verify() is True
    assert len(ledger.audit_log(0)) == n_rows  # pure read
    ev2 = ledger.evaluate("h", 2)  # same seq twice is fine
    assert ev2.posture == "remediated"
    object.__setattr__(rec, "outcome", "failed")
    ev3 = ledger.evaluate("h", 3)
    assert ev3.posture == "failed"
    assert ev3.integrity_ok is False


# 10. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    ledger = asr.AISafetyRemediation()
    ledger.remediate("h", 1, outcome="partial")
    ret = ledger.retire("h", 2, reason="manual")
    assert ret.hazard_id == "h"
    assert ret.verify() is True
    assert ledger.retired_ids(3) == ("h",)
    # ids never recycled: mutations refused after retire
    with pytest.raises(asr.RetiredHazardError):
        ledger.remediate("h", 3, outcome="remediated")
    with pytest.raises(asr.RetiredHazardError):
        ledger.retire("h", 4)
    # post-retire reads still work
    assert ledger.evaluate("h", 5).posture == "partially-remediated"
    assert len(ledger.remediations_for("h", 6)) == 1
    # bad reason burns seq and books a rejected row
    ledger.remediate("h2", 7, outcome="remediated")
    with pytest.raises(asr.BadReasonError):
        ledger.retire("h2", 8, reason="nope")
    rows = ledger.audit_log(0)
    assert rows[-1]["kind"] == "rejected"
    # all four reasons accepted
    for i, reason in enumerate(asr.RETIRE_REASONS):
        ledger.remediate(f"hr-{reason}", 9 + 2 * i, outcome="remediated")
        r = ledger.retire(f"hr-{reason}", 10 + 2 * i, reason=reason)
        assert r.reason == reason
        assert r.verify() is True


# 11. seq discipline: genesis rewind bare, malformed seqs, failed-mutation burns
def test_seq_discipline():
    ledger = asr.AISafetyRemediation()
    n0 = len(ledger.audit_log(0))
    with pytest.raises(asr.SeqOrderError):
        ledger.remediate("h", 0)  # genesis rewind: bare, nothing consumed
    assert len(ledger.audit_log(0)) == n0
    ledger.remediate("h", 1, outcome="remediated")
    for bad_seq in ("2", 2.0, True, None, -1):
        with pytest.raises(asr.SeqOrderError):
            ledger.remediate("h", bad_seq)  # malformed: bare, no burn
    assert len(ledger.audit_log(0)) == n0 + 1
    # failed mutation burns seq
    with pytest.raises(asr.BadKindError):
        ledger.remediate("h", 2, safety_remediation_kind="bad")
    rows = ledger.audit_log(0)
    assert rows[-1]["kind"] == "rejected" and rows[-1]["seq"] == 2
    rec = ledger.remediate("h", 3, outcome="remediated")
    assert rec.seq == 3


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = asr.AISafetyRemediation()
    rec = ledger.remediate(
        "h", 1, safety_remediation_kind="safety-interlock", outcome="partial"
    )
    rows = ledger.audit_log(0)
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-safety-remediation"
    assert row["version"] == "ai-safety-remediation.v1"
    assert row["kind"] == "remediated"
    assert row["details"]["remediation_id"] == rec.remediation_id
    assert row["details"]["safety_remediation_kind"] == "safety-interlock"
    assert row["details"]["outcome"] == "partial"
    # raw material keys banned from the audit boundary
    for banned in ("safety_case", "hazard_log", "fault_tree", "red_team_trace", "script", "weights"):
        with pytest.raises(asr.AISafetyRemediationError):
            asr.ai_safety_remediation_audit_event("remediated", 2, **{banned: "x"})
    with pytest.raises(asr.AuditKindError):
        asr.ai_safety_remediation_audit_event("nonsense", 2)
    # pinned vocab values remain emittable as declared data
    ok = asr.ai_safety_remediation_audit_event(
        "remediated", 2, safety_remediation_kind="output-filter", outcome="remediated"
    )
    assert ok["details"]["outcome"] == "remediated"


# 13. views/stats + unknown lookups
def test_views_and_stats():
    ledger = asr.AISafetyRemediation()
    ledger.remediate("h-b", 1, outcome="remediated")
    ledger.remediate("h-a", 2, outcome="failed")
    assert ledger.hazard_ids(3) == ("h-a", "h-b")
    assert ledger.remediation_ids(4) == ("srf-1", "srf-2")
    assert ledger.remediation_record("srf-1", 5).hazard_id == "h-b"
    assert len(ledger.remediations_for("h-a", 6)) == 1
    assert ledger.remediations_for("h-none", 7) == ()
    with pytest.raises(asr.UnknownRemediationError):
        ledger.remediation_record("srf-999", 8)
    st = ledger.stats(9)
    assert st["n_hazards"] == 2 and st["n_remediations"] == 2
    assert st["n_retired"] == 0 and st["n_audit_rows"] == 2


# 14. cross-instance digest determinism + 8-thread read smoke
def test_determinism_and_threads():
    ledgers = [asr.AISafetyRemediation() for _ in range(3)]
    recs = [
        led.remediate(
            "h", i + 1, safety_remediation_kind="deployment-hold",
            outcome="remediated", safety_digest=PIN,
        )
        for i, led in enumerate(ledgers)
    ]
    digests = {r.digest for r in recs}
    # 3 ledgers x identical (hazard, seq, kind, outcome, digest) inputs ->
    # only 3 distinct digests: cross-instance determinism
    assert len(digests) == 3
    led2 = asr.AISafetyRemediation()
    r1 = led2.remediate("h", 1, outcome="remediated", safety_digest=PIN)
    led3 = asr.AISafetyRemediation()
    r2 = led3.remediate("h", 1, outcome="remediated", safety_digest=PIN)
    assert r1.digest == r2.digest
    assert r1.verify() and r2.verify()

    ledger = asr.AISafetyRemediation()
    for i in range(1, 9):
        ledger.remediate("h", i, outcome="remediated", safety_digest=PIN)
    errors = []

    def reader():
        try:
            for _ in range(50):
                ledger.evaluate("h", 9)
                ledger.verify("srf-1", 9)
                ledger.remediations_for("h", 9)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    ev = ledger.evaluate("h", 10)
    assert ev.posture == "remediated"


# 15. main() subprocess self-check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-safety-remediation OK: remediate, verify, evaluate, retire, pins, audit" in proc.stdout
