"""Tests for the ai-remediation action decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_remediation.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_remediation", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_remediation"] = module
    spec.loader.exec_module(module)
    return module


ar = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ar.AI_REMEDIATION_VERSION == "ai-remediation.v1"
    assert ar.SCHEMA_PIN == "northstar.ai-remediation.v1"
    assert ar.REMEDIATION_KINDS == (
        "rollback",
        "patch",
        "containment",
        "access-revocation",
        "configuration-restore",
        "model-retraining",
        "monitoring-escalation",
        "no-action",
    )
    assert ar.REMEDIATION_OUTCOMES == ("remediated", "partial", "failed", "inconclusive")
    assert ar.VERIFY_VERDICTS == ("verified", "tampered")
    assert ar.POSTURES == ("unevaluated", "partially-remediated", "failed", "remediated")
    assert ar.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert ar.AUDIT_KINDS == ("remediated", "retired", "rejected")


# 2. stdlib-only AST check + stdlib_only()
def test_stdlib_only_ast():
    assert ar.stdlib_only() is True
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


# 3. remediate roundtrip + rmd-N minting + verify() + frozen-ness
def test_remediate_roundtrip():
    ledger = ar.AIRemediation()
    rec = ledger.remediate(
        "target-1", 1, remediation_kind="rollback", outcome="remediated",
        remediation_digest=PIN,
    )
    assert rec.remediation_id == "rmd-1"
    assert rec.target_id == "target-1"
    assert rec.seq == 1
    assert rec.verify() is True
    rec2 = ledger.remediate("target-2", 2)
    assert rec2.remediation_id == "rmd-2"
    assert rec2.remediation_kind == "no-action"
    assert rec2.outcome == "inconclusive"
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.outcome = "failed"  # type: ignore[misc]


# 4. remediate bad-input table + seq-burn + rejected-row accounting + rewind bare
def test_remediate_bad_inputs():
    ledger = ar.AIRemediation()
    bads = [
        ("", 1, {}, ar.BadTargetError),
        ("   ", 1, {}, ar.BadTargetError),
        (123, 1, {}, ar.BadTargetError),
        ("t", 1, {"remediation_kind": "nonsense"}, ar.BadKindError),
        ("t", 1, {"outcome": "fixed"}, ar.BadOutcomeError),
        ("t", 1, {"remediation_digest": "sha256:zzz"}, ar.BadDigestError),
        ("t", 1, {"remediation_digest": "sha256:" + "gg" * 32}, ar.BadDigestError),
        ("t", 1, {"remediation_digest": True}, ar.BadDigestError),
    ]
    seq = 1
    for target, _s, kw, exc in bads:
        with pytest.raises(exc):
            ledger.remediate(target, seq, **kw)
        seq += 1
    rows = ledger.audit_log(0)
    assert len(rows) == len(bads)
    assert all(r["kind"] == "rejected" for r in rows)
    assert all(r["module"] == "ai-remediation" for r in rows)
    assert [r["seq"] for r in rows] == list(range(1, len(bads) + 1))
    # every seq consumed: next mutation must use the following seq
    rec = ledger.remediate("t-ok", seq, outcome="remediated")
    assert rec.seq == seq
    assert rec.remediation_id == "rmd-1"  # counters only advance on success
    # rewind raises bare: no seq consumed, no audit row
    n_rows = len(ledger.audit_log(0))
    with pytest.raises(ar.SeqOrderError):
        ledger.remediate("t-ok", seq)
    assert len(ledger.audit_log(0)) == n_rows


# 5. full remediation-kind vocabulary acceptance
def test_full_remediation_kind_vocabulary():
    ledger = ar.AIRemediation()
    for i, kind in enumerate(ar.REMEDIATION_KINDS, start=1):
        rec = ledger.remediate("t", i, remediation_kind=kind, outcome="remediated")
        assert rec.remediation_kind == kind
        assert rec.verify() is True


# 6. full outcome vocabulary + digest pin handling
def test_full_outcome_vocabulary_and_digest():
    ledger = ar.AIRemediation()
    for i, outcome in enumerate(ar.REMEDIATION_OUTCOMES, start=1):
        rec = ledger.remediate("t", i, outcome=outcome, remediation_digest=PIN2)
        assert rec.outcome == outcome
        assert rec.remediation_digest == PIN2
        assert rec.verify() is True
    rec_empty = ledger.remediate("t", 5)
    assert rec_empty.remediation_digest == ""


# 7. remediate repeatable on same target + views
def test_remediate_chain_and_views():
    ledger = ar.AIRemediation()
    r1 = ledger.remediate("t-1", 1, remediation_kind="rollback", outcome="failed")
    r2 = ledger.remediate("t-1", 2, remediation_kind="patch", outcome="remediated")
    r3 = ledger.remediate("t-2", 3, remediation_kind="containment", outcome="partial")
    assert (r1.remediation_id, r2.remediation_id, r3.remediation_id) == ("rmd-1", "rmd-2", "rmd-3")
    assert ledger.target_ids(0) == ("t-1", "t-2")
    assert ledger.remediation_ids(0) == ("rmd-1", "rmd-2", "rmd-3")
    assert ledger.remediations_for("t-1", 0) == (r1, r2)
    assert ledger.remediations_for("t-2", 0) == (r3,)
    assert ledger.remediations_for("t-missing", 0) == ()
    got = ledger.remediation_record("rmd-2", 0)
    assert got == r2
    with pytest.raises(ar.UnknownRemediationError):
        ledger.remediation_record("rmd-99", 0)
    stats = ledger.stats(0)
    assert stats["n_targets"] == 2
    assert stats["n_remediations"] == 3
    assert stats["n_retired"] == 0
    assert stats["seq"] == 3
    assert stats["n_audit_rows"] == 3


# 8. remediate refusals: retired target, retired-then-burn accounting
def test_remediate_refusals_retired():
    ledger = ar.AIRemediation()
    ledger.remediate("t-1", 1, outcome="remediated")
    ledger.retire("t-1", 2)
    n_rows = len(ledger.audit_log(0))
    with pytest.raises(ar.RetiredTargetError):
        ledger.remediate("t-1", 3, outcome="remediated")
    assert len(ledger.audit_log(0)) == n_rows + 1
    assert ledger.audit_log(0)[-1]["kind"] == "rejected"


# 9. verify semantics: roundtrip, tamper-as-data, unknown, read purity
def test_verify_semantics():
    ledger = ar.AIRemediation()
    rec = ledger.remediate("t-1", 1, remediation_kind="patch", outcome="remediated")
    rep = ledger.verify(rec.remediation_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # tamper surfaces as data, never raised
    tampered = dataclasses.replace(rec, outcome="failed")
    assert tampered.verify() is False
    # unknown record fails closed
    with pytest.raises(ar.UnknownRecordError):
        ledger.verify("rmd-404", 3)
    # pure read: no audit row, seq not consumed
    rows_before = len(ledger.audit_log(0))
    seq_before = ledger.stats(0)["seq"]
    ledger.verify(rec.remediation_id, 999)
    ledger.verify(rec.remediation_id, 0)
    assert len(ledger.audit_log(0)) == rows_before
    assert ledger.stats(0)["seq"] == seq_before
    # retire records are verifiable digests but not verify() targets
    ret = ledger.retire("t-1", 4)
    assert ret.verify() is True
    with pytest.raises(ar.UnknownRecordError):
        ledger.verify("t-1", 5)


# 10. evaluate posture math (all postures + precedence) + read purity
def test_evaluate_posture_math():
    ledger = ar.AIRemediation()
    # all-remediated -> remediated
    ledger.remediate("a", 1, outcome="remediated")
    ledger.remediate("a", 2, outcome="remediated")
    ev = ledger.evaluate("a", 100)
    assert ev.posture == "remediated"
    assert (ev.n_remediations, ev.n_remediated, ev.n_failed) == (2, 2, 0)
    assert ev.integrity_ok is True
    assert ev.verify() is True
    # failed beats everything -> failed
    ledger.remediate("b", 3, outcome="remediated")
    ledger.remediate("b", 4, outcome="failed")
    evb = ledger.evaluate("b", 100)
    assert evb.posture == "failed"
    assert evb.n_failed == 1
    # partial / inconclusive -> partially-remediated
    ledger.remediate("c", 5, outcome="remediated")
    ledger.remediate("c", 6, outcome="partial")
    assert ledger.evaluate("c", 100).posture == "partially-remediated"
    ledger.remediate("d", 7, outcome="inconclusive")
    evd = ledger.evaluate("d", 100)
    assert evd.posture == "partially-remediated"
    assert evd.n_inconclusive == 1
    # read purity: seq not consumed, no audit row
    rows_before = len(ledger.audit_log(0))
    seq_before = ledger.stats(0)["seq"]
    ledger.evaluate("a", 0)
    ledger.evaluate("a", 10**9)
    assert len(ledger.audit_log(0)) == rows_before
    assert ledger.stats(0)["seq"] == seq_before
    # unknown target fails closed
    with pytest.raises(ar.UnknownTargetError):
        ledger.evaluate("nope", 0)


# 11. evaluate is unevaluated-gated: reads need seq shape only
def test_evaluate_read_seq_shape():
    ledger = ar.AIRemediation()
    ledger.remediate("t", 1)
    with pytest.raises(ar.SeqOrderError):
        ledger.evaluate("t", -1)
    with pytest.raises(ar.SeqOrderError):
        ledger.evaluate("t", "1")
    with pytest.raises(ar.SeqOrderError):
        ledger.evaluate("t", True)


# 12. retire terminality + id non-recycling + post-retire reads
def test_retire_terminality():
    ledger = ar.AIRemediation()
    ledger.remediate("t-1", 1, outcome="remediated")
    ret = ledger.retire("t-1", 2, reason="superseded")
    assert ret.verify() is True
    assert ret.reason == "superseded"
    assert ledger.retired_ids(0) == ("t-1",)
    # ids never recycled: retiring again burns seq and fails
    with pytest.raises(ar.RetiredTargetError):
        ledger.retire("t-1", 3)
    # post-retire mutations refused, reads still work
    with pytest.raises(ar.RetiredTargetError):
        ledger.remediate("t-1", 4)
    ev = ledger.evaluate("t-1", 5)
    assert ev.posture == "remediated"
    rep = ledger.verify("rmd-1", 6)
    assert rep.verdict == "verified"
    assert ledger.remediation_record("rmd-1", 7).outcome == "remediated"
    # unknown target retire fails closed with burn
    with pytest.raises(ar.UnknownTargetError):
        ledger.retire("t-ghost", 8)
    # bad reason burns too
    with pytest.raises(ar.BadReasonError):
        ledger.retire("t-ghost", 9, reason="oops")
    stats = ledger.stats(0)
    assert stats["seq"] == 9
    assert stats["n_audit_rows"] == 6  # remediated, retired, +4 rejected


# 13. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    ledger = ar.AIRemediation()
    ledger.remediate("t", 10, outcome="remediated")
    for bad in (10, 0, -5):
        n = len(ledger.audit_log(0))
        with pytest.raises(ar.SeqOrderError):
            ledger.remediate("t", bad)
        assert len(ledger.audit_log(0)) == n  # rewind: bare, no row
    for bad in ("10", 10.0, True, None):
        with pytest.raises(ar.SeqOrderError):
            ledger.remediate("t", bad)
    # failed mutation consumes seq: next valid mutation continues
    with pytest.raises(ar.BadKindError):
        ledger.remediate("t", 11, remediation_kind="bogus")
    rec = ledger.remediate("t", 12, outcome="remediated")
    assert rec.seq == 12
    assert ledger.stats(0)["seq"] == 12


# 14. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    ledger = ar.AIRemediation()
    rec = ledger.remediate(
        "t-1", 1, remediation_kind="rollback", outcome="remediated"
    )
    rows = ledger.audit_log(0)
    assert len(rows) == 1
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-remediation"
    assert row["version"] == "ai-remediation.v1"
    assert row["kind"] == "remediated"
    assert row["seq"] == 1
    assert row["details"]["remediation_id"] == rec.remediation_id
    assert row["details"]["target_id"] == "t-1"
    ledger.retire("t-1", 2)
    assert ledger.audit_log(0)[1]["kind"] == "retired"
    # banned raw-material keys never cross the audit boundary
    for banned in ("script", "runbook", "patch_diff", "rollback_plan", "transcript"):
        with pytest.raises(ar.AIRemediationError):
            ar.ai_remediation_audit_event("remediated", 3, **{banned: "x"})
    # digest pins of those values are fine (key ban applies to raw material)
    ok = ar.ai_remediation_audit_event("remediated", 3, script_digest=PIN)
    assert ok["details"]["script_digest"] == PIN
    # bad audit kind fails closed
    with pytest.raises(ar.AuditKindError):
        ar.ai_remediation_audit_event("hacked", 3)
    with pytest.raises(ar.SeqOrderError):
        ar.ai_remediation_audit_event("remediated", "3")


# 15. cross-instance determinism + tamper + 8-thread reads + main() subprocess
def test_determinism_threads_and_main():
    a = ar.AIRemediation()
    b = ar.AIRemediation()
    ra = a.remediate("t", 1, remediation_kind="patch", outcome="remediated", remediation_digest=PIN)
    rb = b.remediate("t", 1, remediation_kind="patch", outcome="remediated", remediation_digest=PIN)
    assert ra.digest == rb.digest  # cross-instance determinism
    tampered = dataclasses.replace(ra, outcome="failed")
    assert tampered.verify() is False
    assert a.verify("rmd-1", 2).verdict == "verified"
    # 8-thread read smoke: evaluate + verify + views concurrently
    errors = []

    def reader(_i):
        try:
            for _ in range(50):
                a.evaluate("t", 3)
                a.verify("rmd-1", 3)
                a.remediations_for("t", 3)
                a.target_ids(3)
                a.stats(3)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # main() subprocess self-check
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-remediation OK" in proc.stdout
