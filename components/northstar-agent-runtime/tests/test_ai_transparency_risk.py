"""Tests for the ai-transparency-risk register decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_transparency_risk.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_transparency_risk", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_transparency_risk"] = module
    spec.loader.exec_module(module)
    return module


tr = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert tr.AI_TRANSPARENCY_RISK_VERSION == "ai-transparency-risk.v1"
    assert tr.SCHEMA_PIN == "northstar.ai-transparency-risk.v1"
    assert tr.TRANSPARENCY_RISK_KINDS == (
        "disclosure-gap",
        "explanation-deficit",
        "documentation-gap",
        "decision-opacity",
        "traceability-gap",
        "communication-failure",
        "auditability-gap",
        "transparency-regression",
    )
    assert tr.VERDICTS == (
        "unacceptable",
        "concerning",
        "tolerable",
        "acceptable",
        "not-assessed",
    )
    assert tr.MITIGATION_STRATEGIES == (
        "disclosure-release",
        "explanation-provision",
        "documentation-completion",
        "transparency-audit",
        "traceability-improvement",
        "communication-plan",
        "human-oversight",
        "no-action",
    )
    assert tr.RETIRE_REASONS == ("manual", "withdrawn", "duplicate", "superseded")
    assert tr.POSTURES == (
        "unassessed",
        "unacceptable-open",
        "concerning-open",
        "tolerable-managed",
        "mitigated",
        "acceptable",
    )
    assert tr.AUDIT_KINDS == ("assessed", "mitigated", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    assert tr.stdlib_only() is True
    tree = ast.parse(MOD.read_text(encoding="utf-8"))
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "threading",
        "typing",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed


# 3. assess roundtrip / minted id / verify / frozen-ness
def test_assess_roundtrip():
    ledger = tr.AITransparencyRisk()
    rec = ledger.assess(
        "sys-1", 1, transparency_risk_kind="explanation-deficit", verdict="unacceptable",
        severity=95, assessment_digest=PIN,
    )
    assert rec.assessment_id == "trk-1"
    assert rec.system_id == "sys-1"
    assert rec.seq == 1
    assert rec.transparency_risk_kind == "explanation-deficit"
    assert rec.verdict == "unacceptable"
    assert rec.severity == 95
    assert rec.assessment_digest == PIN
    assert rec.digest.startswith("sha256:")
    assert rec.verify() is True
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.severity = 0  # type: ignore[misc]


# 4. assess bad-input table + seq-burn + rejected-row accounting
def test_assess_bad_inputs():
    ledger = tr.AITransparencyRisk()
    cases = [
        (lambda: ledger.assess("", 1), tr.BadIdError),
        (lambda: ledger.assess("s", 2, transparency_risk_kind="nope"),
         tr.BadTransparencyRiskKindError),
        (lambda: ledger.assess("s", 3, verdict="nope"), tr.BadVerdictError),
        (lambda: ledger.assess("s", 4, severity=-1), tr.BadSeverityError),
        (lambda: ledger.assess("s", 5, severity=101), tr.BadSeverityError),
        (lambda: ledger.assess("s", 6, severity=True), tr.BadSeverityError),
        (lambda: ledger.assess("s", 7, assessment_digest="bad"), tr.BadDigestError),
        (lambda: ledger.assess("s", 8, assessment_digest="sha256:zz"),
         tr.BadDigestError),
    ]
    for i, (fn, exc) in enumerate(cases):
        with pytest.raises(exc):
            fn()
        assert ledger._seq == i + 1, i
    rejected = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert len(rejected) == len(cases)
    # failed mutations consumed their seqs: next valid assess needs the next seq
    rec = ledger.assess("s", len(cases) + 1)
    assert rec.assessment_id == "trk-1"
    # rewind raises bare: no burn, no new rejected row
    before = len(ledger.audit_log(0))
    with pytest.raises(tr.SeqOrderError):
        ledger.assess("s", 1)
    assert len(ledger.audit_log(0)) == before
    assert ledger._seq == len(cases) + 1
    # malformed seqs raise bare (no burn)
    for bad in ("1", 1.5, None, True):
        with pytest.raises(tr.SeqOrderError):
            ledger.assess("s", bad)  # type: ignore[arg-type]


# 5. full transparency-risk-kind vocabulary
def test_full_transparency_risk_kind_vocabulary():
    ledger = tr.AITransparencyRisk()
    for i, kind in enumerate(tr.TRANSPARENCY_RISK_KINDS):
        rec = ledger.assess(f"sys-{i}", i + 1, transparency_risk_kind=kind)
        assert rec.transparency_risk_kind == kind


# 6. mitigate roundtrip / chainable / frozen-ness
def test_mitigate_roundtrip():
    ledger = tr.AITransparencyRisk()
    asm = ledger.assess("sys-1", 1, verdict="concerning")
    mit = ledger.mitigate(
        asm.assessment_id, 2, strategy="human-oversight", mitigation_digest=PIN2
    )
    assert mit.mitigation_id == "mit-1"
    assert mit.assessment_id == asm.assessment_id
    assert mit.system_id == "sys-1"
    assert mit.strategy == "human-oversight"
    assert mit.mitigation_digest == PIN2
    assert mit.verify() is True
    with pytest.raises(dataclasses.FrozenInstanceError):
        mit.strategy = "disclosure-release"  # type: ignore[misc]
    # chainable: a second declared mitigation books cleanly
    mit2 = ledger.mitigate(asm.assessment_id, 3, strategy="transparency-audit")
    assert mit2.mitigation_id == "mit-2"
    assert len(ledger.mitigations_for(asm.assessment_id, 3)) == 2


# 7. mitigate refusals: unknown / bad strategy / bad digest / retired
def test_mitigate_refusals():
    ledger = tr.AITransparencyRisk()
    asm = ledger.assess("sys-1", 1, verdict="tolerable")
    before = len(ledger.audit_log(0))
    with pytest.raises(tr.UnknownAssessmentError):
        ledger.mitigate("trk-999", 2)
    with pytest.raises(tr.BadStrategyError):
        ledger.mitigate(asm.assessment_id, 3, strategy="nope")
    with pytest.raises(tr.BadDigestError):
        ledger.mitigate(asm.assessment_id, 4, mitigation_digest="bad")
    assert len([r for r in ledger.audit_log(0) if r["kind"] == "rejected"]) == 3
    # retire, then mitigation refused for the retired system
    ledger.retire("sys-1", 5)
    with pytest.raises(tr.RetiredSystemError):
        ledger.mitigate(asm.assessment_id, 6)
    assert len(ledger.audit_log(0)) == before + 5


# 8. full mitigation-strategy vocabulary
def test_full_strategy_vocabulary():
    ledger = tr.AITransparencyRisk()
    asm = ledger.assess("sys-1", 1, verdict="acceptable")
    for i, strategy in enumerate(tr.MITIGATION_STRATEGIES):
        mit = ledger.mitigate(asm.assessment_id, i + 2, strategy=strategy)
        assert mit.strategy == strategy


# 9. verify semantics: verified/tampered-as-data, read purity, unknown refusal
def test_verify_semantics():
    ledger = tr.AITransparencyRisk()
    asm = ledger.assess("sys-1", 1, verdict="unacceptable")
    mit = ledger.mitigate(asm.assessment_id, 2)
    seq_before = ledger._seq
    audit_before = len(ledger.audit_log(0))
    v1 = ledger.verify(asm.assessment_id, 3)
    v2 = ledger.verify(asm.assessment_id, 3)  # same seq twice: pure read
    assert v1.verdict == "verified"
    assert v1.integrity_ok is True
    assert v1.verify() is True
    assert v2.digest == v1.digest
    vm = ledger.verify(mit.mitigation_id, 3)
    assert vm.verdict == "verified"
    assert ledger._seq == seq_before
    assert len(ledger.audit_log(0)) == audit_before
    with pytest.raises(tr.UnknownAssessmentError):
        ledger.verify("nope", 3)
    with pytest.raises(tr.SeqOrderError):
        ledger.verify(asm.assessment_id, -1)
    # tamper is reported as data, never raised
    object.__setattr__(asm, "severity", 99)
    vt = ledger.verify(asm.assessment_id, 3)
    assert vt.verdict == "tampered"
    assert vt.integrity_ok is False


# 10. evaluate posture math
def test_evaluate_posture_math():
    # unacceptable-open outranks everything
    ledger = tr.AITransparencyRisk()
    ledger.assess(
        "s1", 1, transparency_risk_kind="disclosure-gap", verdict="unacceptable", severity=99
    )
    rep = ledger.evaluate("s1", 2)
    assert rep.posture == "unacceptable-open"
    assert rep.n_unacceptable == 1 and rep.n_assessments == 1
    assert rep.verify() is True
    # concerning-open: unmitigated concerning
    ledger2 = tr.AITransparencyRisk()
    ledger2.assess("s2", 1, verdict="concerning")
    assert ledger2.evaluate("s2", 2).posture == "concerning-open"
    # tolerable-managed: unmitigated tolerable / not-assessed
    ledger3 = tr.AITransparencyRisk()
    ledger3.assess("s3", 1, verdict="tolerable")
    ledger3.assess("s3", 2, verdict="not-assessed")
    rep3 = ledger3.evaluate("s3", 3)
    assert rep3.posture == "tolerable-managed"
    assert rep3.n_tolerable == 1 and rep3.n_not_assessed == 1
    # mitigated: all covered
    ledger4 = tr.AITransparencyRisk()
    a4 = ledger4.assess("s4", 1, verdict="unacceptable")
    ledger4.mitigate(a4.assessment_id, 2, strategy="transparency-audit")
    rep4 = ledger4.evaluate("s4", 3)
    assert rep4.posture == "mitigated"
    assert rep4.n_mitigated == 1
    # acceptable: only unmitigated acceptable risks
    ledger5 = tr.AITransparencyRisk()
    ledger5.assess("s5", 1, verdict="acceptable")
    assert ledger5.evaluate("s5", 2).posture == "acceptable"
    # precedence: concerning + unacceptable -> unacceptable-open
    ledger6 = tr.AITransparencyRisk()
    ledger6.assess("s6", 1, verdict="concerning")
    ledger6.assess("s6", 2, verdict="unacceptable")
    assert ledger6.evaluate("s6", 3).posture == "unacceptable-open"


# 11. evaluate read purity + unknown system
def test_evaluate_read_purity():
    ledger = tr.AITransparencyRisk()
    ledger.assess("s1", 1, verdict="acceptable")
    seq_before = ledger._seq
    audit_before = len(ledger.audit_log(0))
    r1 = ledger.evaluate("s1", 2)
    r2 = ledger.evaluate("s1", 2)
    assert r1.digest == r2.digest
    assert ledger._seq == seq_before
    assert len(ledger.audit_log(0)) == audit_before
    with pytest.raises(tr.UnknownSystemError):
        ledger.evaluate("unknown", 2)


# 12. retire terminality
def test_retire_terminality():
    ledger = tr.AITransparencyRisk()
    asm = ledger.assess("s1", 1, verdict="tolerable")
    with pytest.raises(tr.BadReasonError):
        ledger.retire("s1", 2, reason="nope")
    with pytest.raises(tr.UnknownSystemError):
        ledger.retire("unknown", 3)
    rec = ledger.retire("s1", 4, reason="withdrawn")
    assert rec.reason == "withdrawn"
    assert rec.verify() is True
    assert ledger.retired_ids(0) == ["s1"]
    # id non-recycling: the retired system id can never be reused
    with pytest.raises(tr.RetiredSystemError):
        ledger.assess("s1", 5)
    with pytest.raises(tr.RetiredSystemError):
        ledger.retire("s1", 6)
    # reads still work post-retire
    assert ledger.assessment_record(asm.assessment_id, 6) is asm
    assert ledger.evaluate("s1", 6).posture == "tolerable-managed"
    assert ledger.stats(6)["n_retired"] == 1


# 13. seq discipline: genesis rewind bare, malformed seqs, failed mutation burns
def test_seq_discipline():
    ledger = tr.AITransparencyRisk()
    # genesis rewind (seq 0 before anything): raises bare, zero audit rows
    with pytest.raises(tr.SeqOrderError):
        ledger.assess("s1", 0)
    assert ledger.audit_log(0) == []
    assert ledger._seq == 0
    # failed mutation consumes seq but books the rejected row
    with pytest.raises(tr.BadVerdictError):
        ledger.assess("s1", 1, verdict="nope")
    assert ledger._seq == 1
    assert len([r for r in ledger.audit_log(0) if r["kind"] == "rejected"]) == 1
    # valid claim lands on the next seq
    rec = ledger.assess("s1", 2)
    assert rec.assessment_id == "trk-1"
    # gap seqs allowed
    rec2 = ledger.assess("s1", 100)
    assert rec2.assessment_id == "trk-2"
    # mitigate with a non-int seq raises bare
    with pytest.raises(tr.SeqOrderError):
        ledger.mitigate(rec.assessment_id, True)  # type: ignore[arg-type]


# 14. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    ledger = tr.AITransparencyRisk()
    asm = ledger.assess("s1", 1, transparency_risk_kind="explanation-deficit", verdict="concerning")
    rows = ledger.audit_log(0)
    row = rows[-1]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-transparency-risk"
    assert row["version"] == "ai-transparency-risk.v1"
    assert row["kind"] == "assessed"
    assert row["seq"] == 1
    assert row["details"]["assessment_id"] == asm.assessment_id
    assert row["details"]["transparency_risk_kind"] == "explanation-deficit"
    assert row["details"]["verdict"] == "concerning"
    # banned raw keys refused at the audit boundary
    for banned in ("transparency", "disclosure", "disclosure_text", "model_card",
                    "explanation", "explanation_text", "traceability", "data_lineage"):
        with pytest.raises(tr.AITransparencyRiskError):
            tr.ai_transparency_risk_audit_event("assessed", 2, **{banned: "raw"})
    # pinned vocab values and digest pins stay emittable
    ok = tr.ai_transparency_risk_audit_event(
        "mitigated", 2, strategy="transparency-audit", transparency_risk_kind="traceability-gap"
    )
    assert ok["kind"] == "mitigated"
    with pytest.raises(tr.AuditKindError):
        tr.ai_transparency_risk_audit_event("nope", 2)
    with pytest.raises(tr.SeqOrderError):
        tr.ai_transparency_risk_audit_event("assessed", True)


# 15. cross-instance determinism + threads + main()
def test_determinism_threads_main():
    a = tr.AITransparencyRisk()
    b = tr.AITransparencyRisk()
    for i, ledger in enumerate((a, b)):
        asm = ledger.assess(
            f"sys-{i}", 1, transparency_risk_kind="disclosure-gap",
            verdict="unacceptable", severity=90,
        )
        ledger.mitigate(asm.assessment_id, 2, strategy="transparency-audit")
    ra = a.evaluate("sys-0", 3)
    rb = b.evaluate("sys-1", 3)
    assert ra.posture == rb.posture == "mitigated"
    assert ra.verify() is True and rb.verify() is True
    # tamper breaks verify() and flips integrity_ok as data
    ledger = tr.AITransparencyRisk()
    asm = ledger.assess("s1", 1, verdict="tolerable")
    assert asm.verify() is True
    object.__setattr__(asm, "verdict", "acceptable")
    assert asm.verify() is False
    rep = ledger.evaluate("s1", 2)
    assert rep.integrity_ok is False
    # views and unknown lookups
    assert ledger.assessment_ids(2) == [asm.assessment_id]
    assert ledger.system_ids(2) == ["s1"]
    assert ledger.stats(2)["n_assessments"] == 1
    with pytest.raises(tr.UnknownAssessmentError):
        ledger.assessment_record("trk-999", 2)
    # 8-thread read smoke
    ledger2 = tr.AITransparencyRisk()
    asm2 = ledger2.assess("t", 1, verdict="concerning")
    errors = []

    def _read():
        try:
            for _ in range(50):
                ledger2.verify(asm2.assessment_id, 1)
                ledger2.evaluate("t", 1)
                ledger2.stats(1)
        except Exception as exc:  # pragma: no cover - smoke test
            errors.append(exc)

    threads = [threading.Thread(target=_read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    # main() self-check via subprocess
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-transparency-risk OK" in proc.stdout
