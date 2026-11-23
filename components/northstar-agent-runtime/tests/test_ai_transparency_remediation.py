"""Tests for the ai-transparency-remediation decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_transparency_remediation.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_transparency_remediation", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_transparency_remediation"] = module
    spec.loader.exec_module(module)
    return module


atr = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert atr.AI_TRANSPARENCY_REMEDIATION_VERSION == "ai-transparency-remediation.v1"
    assert atr.SCHEMA_PIN == "northstar.ai-transparency-remediation.v1"
    assert atr.TRANSPARENCY_REMEDIATION_KINDS == (
        "disclosure-remediation",
        "documentation-remediation",
        "explanation-remediation",
        "model-card-remediation",
        "datasheet-remediation",
        "provenance-restoration",
        "audit-trail-restoration",
        "no-action",
    )
    assert atr.REMEDIATION_OUTCOMES == ("remediated", "partial", "failed", "inconclusive")
    assert atr.VERIFY_VERDICTS == ("verified", "tampered")
    assert atr.POSTURES == (
        "unevaluated",
        "contested",
        "partially-remediated",
        "failed",
        "remediated",
    )
    assert atr.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert atr.AUDIT_KINDS == ("remediated", "retired", "rejected")


# 2. stdlib-only AST check + stdlib_only()
def test_stdlib_only_ast():
    assert atr.stdlib_only() is True
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


# 3. remediate roundtrip + trm-N minting + verify() + frozen-ness
def test_remediate_roundtrip():
    ledger = atr.AITransparencyRemediation()
    rec = ledger.remediate(
        "issue-1", 1, transparency_remediation_kind="disclosure-remediation",
        outcome="remediated", transparency_digest=PIN,
    )
    assert rec.remediation_id == "trm-1"
    assert rec.issue_id == "issue-1"
    assert rec.seq == 1
    assert rec.verify() is True
    rec2 = ledger.remediate("issue-2", 2)
    assert rec2.remediation_id == "trm-2"
    assert rec2.transparency_remediation_kind == "no-action"
    assert rec2.outcome == "inconclusive"
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.outcome = "failed"  # type: ignore[misc]


# 4. remediate bad-input table + seq-burn + rejected-row accounting + rewind bare
def test_remediate_bad_inputs():
    ledger = atr.AITransparencyRemediation()
    bads = [
        ("", 1, {}, atr.BadIssueError),
        ("   ", 1, {}, atr.BadIssueError),
        (123, 1, {}, atr.BadIssueError),
        (True, 1, {}, atr.BadIssueError),
        ("i", 1, {"transparency_remediation_kind": "nonsense"}, atr.BadKindError),
        ("i", 1, {"outcome": "fixed"}, atr.BadOutcomeError),
        ("i", 1, {"transparency_digest": "sha256:zzz"}, atr.BadDigestError),
        ("i", 1, {"transparency_digest": "sha256:" + "gg" * 32}, atr.BadDigestError),
        ("i", 1, {"transparency_digest": True}, atr.BadDigestError),
    ]
    seq = 1
    for issue, _s, kw, exc in bads:
        with pytest.raises(exc):
            ledger.remediate(issue, seq, **kw)
        seq += 1
    rows = ledger.audit_log(0)
    assert len(rows) == len(bads)
    assert all(r["kind"] == "rejected" for r in rows)
    assert all(r["module"] == "ai-transparency-remediation" for r in rows)
    assert all(r["schema"] == "audit.ndjson/1" for r in rows)
    assert [r["seq"] for r in rows] == list(range(1, len(bads) + 1))
    # every seq consumed: next mutation must use the following seq
    rec = ledger.remediate("i-ok", seq, outcome="remediated")
    assert rec.seq == seq


# 5. full kind vocabulary sweep
def test_full_kind_vocabulary():
    ledger = atr.AITransparencyRemediation()
    seq = 1
    for kind in atr.TRANSPARENCY_REMEDIATION_KINDS:
        rec = ledger.remediate(
            f"i-{kind}", seq, transparency_remediation_kind=kind, outcome="remediated"
        )
        assert rec.transparency_remediation_kind == kind
        assert rec.verify() is True
        seq += 1
    assert ledger.stats(0)["n_issues"] == len(atr.TRANSPARENCY_REMEDIATION_KINDS)


# 6. full outcome vocabulary + tallies
def test_full_outcome_vocabulary():
    ledger = atr.AITransparencyRemediation()
    seq = 1
    for outcome in atr.REMEDIATION_OUTCOMES:
        rec = ledger.remediate("i", seq, outcome=outcome)
        assert rec.outcome == outcome
        seq += 1
    ev = ledger.evaluate("i", seq)
    assert ev.n_remediations == 4
    assert ev.n_remediated == 1
    assert ev.n_partial == 1
    assert ev.n_failed == 1
    assert ev.n_inconclusive == 1
    assert ev.posture == "failed"  # failed outranks


# 7. verify semantics: verified / tampered-as-data / unknown refusal / read purity
def test_verify_semantics():
    ledger = atr.AITransparencyRemediation()
    rec = ledger.remediate("i", 1, outcome="remediated")
    rep = ledger.verify(rec.remediation_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # tamper is reported as data, never raised
    object.__setattr__(rec, "outcome", "failed")
    rep2 = ledger.verify(rec.remediation_id, 3)
    assert rep2.verdict == "tampered"
    assert rep2.integrity_ok is False
    with pytest.raises(atr.UnknownRecordError):
        ledger.verify("trm-999", 4)
    # pure read: seq not consumed, no audit row
    rows_before = len(ledger.audit_log(0))
    ledger.verify(rec.remediation_id, 4)
    ledger.verify(rec.remediation_id, 4)
    assert len(ledger.audit_log(0)) == rows_before


# 8. evaluate posture math: all 5 postures + precedence
def test_evaluate_posture_math():
    ledger = atr.AITransparencyRemediation()
    # remediated: all remediated
    ledger.remediate("i-ok", 1, outcome="remediated")
    ledger.remediate("i-ok", 2, outcome="remediated")
    assert ledger.evaluate("i-ok", 3).posture == "remediated"
    # partially-remediated: remediated + partial
    ledger.remediate("i-part", 4, outcome="remediated")
    ledger.remediate("i-part", 5, outcome="partial")
    assert ledger.evaluate("i-part", 6).posture == "partially-remediated"
    # contested: partial + inconclusive
    ledger.remediate("i-cont", 7, outcome="partial")
    ledger.remediate("i-cont", 8, outcome="inconclusive")
    assert ledger.evaluate("i-cont", 9).posture == "contested"
    # failed outranks everything
    ledger.remediate("i-fail", 10, outcome="remediated")
    ledger.remediate("i-fail", 11, outcome="failed")
    assert ledger.evaluate("i-fail", 12).posture == "failed"
    with pytest.raises(atr.UnknownIssueError):
        ledger.evaluate("nope", 13)


# 9. evaluate read purity + tamper flips integrity_ok
def test_evaluate_purity_and_integrity():
    ledger = atr.AITransparencyRemediation()
    rec = ledger.remediate("i", 1, outcome="remediated")
    ev1 = ledger.evaluate("i", 2)
    ev2 = ledger.evaluate("i", 2)
    assert ev1.digest == ev2.digest  # deterministic, pure read
    assert ev1.integrity_ok is True
    assert len(ledger.audit_log(0)) == 1  # remediate only; reads add no rows
    object.__setattr__(rec, "transparency_digest", PIN)
    ev3 = ledger.evaluate("i", 3)
    assert ev3.integrity_ok is False


# 10. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    ledger = atr.AITransparencyRemediation()
    ledger.remediate("i", 1, outcome="remediated")
    ret = ledger.retire("i", 2, reason="superseded")
    assert ret.verify() is True
    assert ret.reason == "superseded"
    # double-retire refused
    with pytest.raises(atr.RetiredIssueError):
        ledger.retire("i", 3)
    # ids never recycled: post-retire mutations refused
    with pytest.raises(atr.RetiredIssueError):
        ledger.remediate("i", 4, outcome="remediated")
    # post-retire reads still work
    recs = ledger.remediations_for("i", 5)
    assert len(recs) == 1
    ev = ledger.evaluate("i", 6)
    assert ev.posture == "remediated"
    with pytest.raises(atr.BadReasonError):
        ledger.retire("i", 7, reason="nonsense")
    with pytest.raises(atr.UnknownIssueError):
        ledger.retire("ghost", 8)


# 11. seq discipline: malformed seqs / genesis rewind bare / failed-mutation-consumes-seq
def test_seq_discipline():
    ledger = atr.AITransparencyRemediation()
    for bad in (-1, True, 1.5, "1", None):
        with pytest.raises(atr.SeqOrderError):
            ledger.remediate("i", bad)
    # failed validation burns the seq
    with pytest.raises(atr.BadKindError):
        ledger.remediate("i", 1, transparency_remediation_kind="nope")
    rec = ledger.remediate("i", 2, outcome="remediated")
    assert rec.seq == 2
    # rewind raises bare SeqOrderError, consumes nothing, books nothing
    n_rows = len(ledger.audit_log(0))
    with pytest.raises(atr.SeqOrderError):
        ledger.remediate("i", 2)
    assert len(ledger.audit_log(0)) == n_rows
    # read seqs: shape-validated only
    with pytest.raises(atr.SeqOrderError):
        ledger.stats(-1)


# 12. audit shapes + leak ban + bad audit kind
def test_audit_shapes_and_leak_ban():
    ledger = atr.AITransparencyRemediation()
    rec = ledger.remediate("i", 1, outcome="remediated", transparency_digest=PIN)
    rows = ledger.audit_log(0)
    assert rows[0]["kind"] == "remediated"
    assert rows[0]["version"] == "ai-transparency-remediation.v1"
    assert rows[0]["details"]["remediation_id"] == rec.remediation_id
    assert rows[0]["details"]["transparency_remediation_kind"] == "no-action"
    assert rows[0]["details"]["outcome"] == "remediated"
    # banned raw keys may not cross the audit boundary
    for banned in ("complaint_text", "harm_narrative", "transparency_report", "proprietary_document"):
        with pytest.raises(atr.AITransparencyRemediationError):
            atr.ai_transparency_remediation_audit_event("remediated", 2, **{banned: "x"})
    # pinned vocab values are still emittable as declared data
    row = atr.ai_transparency_remediation_audit_event(
        "remediated", 2, transparency_remediation_kind="documentation-remediation", outcome="partial"
    )
    assert row["details"]["transparency_remediation_kind"] == "documentation-remediation"
    with pytest.raises(atr.AuditKindError):
        atr.ai_transparency_remediation_audit_event("nonsense", 2)
    ledger.retire("i", 2)
    assert ledger.audit_log(0)[1]["kind"] == "retired"


# 13. views/stats + unknown lookups
def test_views_stats_unknown_lookups():
    ledger = atr.AITransparencyRemediation()
    r1 = ledger.remediate("i-a", 1, outcome="remediated")
    r2 = ledger.remediate("i-b", 2, outcome="partial")
    assert ledger.remediation_record(r1.remediation_id, 3) == r1
    assert [r.remediation_id for r in ledger.remediations_for("i-a", 3)] == ["trm-1"]
    assert ledger.issue_ids(3) == ("i-a", "i-b")
    assert ledger.remediation_ids(3) == ("trm-1", "trm-2")
    st = ledger.stats(3)
    assert st["n_issues"] == 2
    assert st["n_remediations"] == 2
    assert st["n_retired"] == 0
    assert st["n_audit_rows"] == 2
    ledger.retire("i-a", 4)
    assert ledger.retired_ids(5) == ("i-a",)
    assert ledger.stats(5)["n_retired"] == 1
    with pytest.raises(atr.UnknownRemediationError):
        ledger.remediation_record("trm-999", 5)
    assert ledger.remediations_for("ghost", 5) == ()


# 14. cross-instance digest determinism + 8-thread read smoke
def test_determinism_and_thread_smoke():
    a = atr.AITransparencyRemediation()
    b = atr.AITransparencyRemediation()
    ra = a.remediate("i", 1, transparency_remediation_kind="documentation-remediation", outcome="partial", transparency_digest=PIN)
    rb = b.remediate("i", 1, transparency_remediation_kind="documentation-remediation", outcome="partial", transparency_digest=PIN)
    assert ra.digest == rb.digest
    assert a.evaluate("i", 2).digest == b.evaluate("i", 2).digest

    errors = []

    def worker():
        try:
            for _ in range(50):
                a.verify(ra.remediation_id, 3)
                a.evaluate("i", 3)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# 15. main() subprocess self-check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-transparency-remediation OK: remediate, verify, evaluate, retire, pins, audit" in proc.stdout
