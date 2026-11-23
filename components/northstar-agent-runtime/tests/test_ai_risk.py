"""Tests for the ai-risk assessment/mitigation decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_risk.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_risk", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_risk"] = module
    spec.loader.exec_module(module)
    return module


ar = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ar.AI_RISK_VERSION == "ai-risk.v1"
    assert ar.SCHEMA_PIN == "northstar.ai-risk.v1"
    assert ar.RISK_KINDS == (
        "misalignment",
        "misuse",
        "loss-of-control",
        "deceptive-behavior",
        "power-seeking",
        "cyber-uplift",
        "bio-risk",
        "societal-harm",
    )
    assert ar.VERDICTS == ("critical", "high", "medium", "low", "not-assessed")
    assert ar.MITIGATION_STRATEGIES == (
        "avoid",
        "reduce",
        "transfer",
        "accept",
        "monitor",
        "red-team",
        "capability-restriction",
        "deployment-hold",
    )
    assert ar.RETIRE_REASONS == ("manual", "withdrawn", "duplicate", "superseded")
    assert ar.POSTURES == (
        "unassessed",
        "critical-open",
        "at-risk",
        "monitored",
        "mitigated",
        "acceptable",
    )
    assert ar.AUDIT_KINDS == ("assessed", "mitigated", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    assert ar.stdlib_only() is True
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
    ledger = ar.AIRisk()
    rec = ledger.assess(
        "sys-1", 1, risk_kind="misuse", verdict="high", severity=60,
        assessment_digest=PIN,
    )
    assert rec.assessment_id == "asm-1"
    assert rec.system_id == "sys-1"
    assert rec.seq == 1
    assert rec.risk_kind == "misuse"
    assert rec.verdict == "high"
    assert rec.severity == 60
    assert rec.assessment_digest == PIN
    assert rec.digest.startswith("sha256:")
    assert rec.verify() is True
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.severity = 0  # type: ignore[misc]


# 4. assess bad-input table + seq-burn + rejected-row accounting
def test_assess_bad_inputs():
    ledger = ar.AIRisk()
    cases = [
        (lambda: ledger.assess("", 1), ar.BadIdError),
        (lambda: ledger.assess("s", 2, risk_kind="nope"), ar.BadRiskKindError),
        (lambda: ledger.assess("s", 3, verdict="nope"), ar.BadVerdictError),
        (lambda: ledger.assess("s", 4, severity=-1), ar.BadSeverityError),
        (lambda: ledger.assess("s", 5, severity=101), ar.BadSeverityError),
        (lambda: ledger.assess("s", 6, severity=True), ar.BadSeverityError),
        (lambda: ledger.assess("s", 7, assessment_digest="bad"), ar.BadDigestError),
        (lambda: ledger.assess("s", 8, assessment_digest="sha256:zz"), ar.BadDigestError),
    ]
    for i, (fn, exc) in enumerate(cases):
        with pytest.raises(exc):
            fn()
        assert ledger._seq == i + 1, i
    rejected = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert len(rejected) == len(cases)
    # failed mutations consumed their seqs: next valid assess needs the next seq
    rec = ledger.assess("s", len(cases) + 1)
    assert rec.assessment_id == "asm-1"
    # rewind raises bare: no burn, no new rejected row
    before = len(ledger.audit_log(0))
    with pytest.raises(ar.SeqOrderError):
        ledger.assess("s", 1)
    assert len(ledger.audit_log(0)) == before
    assert ledger._seq == len(cases) + 1
    # malformed seqs raise bare (no burn)
    for bad in ("1", 1.5, None, True):
        with pytest.raises(ar.SeqOrderError):
            ledger.assess("s", bad)  # type: ignore[arg-type]


# 5. full risk-kind vocabulary
def test_full_risk_kind_vocabulary():
    ledger = ar.AIRisk()
    for i, kind in enumerate(ar.RISK_KINDS):
        rec = ledger.assess(f"sys-{i}", i + 1, risk_kind=kind)
        assert rec.risk_kind == kind
        assert rec.verify() is True


# 6. mitigate roundtrip
def test_mitigate_roundtrip():
    ledger = ar.AIRisk()
    asm = ledger.assess("sys-1", 1, risk_kind="misalignment", verdict="critical")
    mit = ledger.mitigate(asm.assessment_id, 2, strategy="reduce",
                          mitigation_digest=PIN2)
    assert mit.mitigation_id == "mit-1"
    assert mit.assessment_id == asm.assessment_id
    assert mit.system_id == "sys-1"
    assert mit.strategy == "reduce"
    assert mit.mitigation_digest == PIN2
    assert mit.verify() is True
    with pytest.raises(dataclasses.FrozenInstanceError):
        mit.strategy = "avoid"  # type: ignore[misc]
    # chainable: a second mitigation books against the same assessment
    mit2 = ledger.mitigate(asm.assessment_id, 3, strategy="monitor")
    assert mit2.mitigation_id == "mit-2"


# 7. mitigate refusals
def test_mitigate_refusals():
    ledger = ar.AIRisk()
    asm = ledger.assess("sys-1", 1, verdict="high")
    with pytest.raises(ar.UnknownAssessmentError):
        ledger.mitigate("asm-999", 2)
    with pytest.raises(ar.BadStrategyError):
        ledger.mitigate(asm.assessment_id, 3, strategy="nope")
    with pytest.raises(ar.BadDigestError):
        ledger.mitigate(asm.assessment_id, 4, mitigation_digest="bad")
    rejected = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert len(rejected) == 3
    # retired systems refuse mitigations
    ledger.retire("sys-1", 5)
    with pytest.raises(ar.RetiredSystemError):
        ledger.mitigate(asm.assessment_id, 6)


# 8. full mitigation-strategy vocabulary
def test_full_strategy_vocabulary():
    ledger = ar.AIRisk()
    for i, strategy in enumerate(ar.MITIGATION_STRATEGIES):
        asm = ledger.assess(f"sys-{i}", 2 * i + 1, verdict="medium")
        mit = ledger.mitigate(asm.assessment_id, 2 * i + 2, strategy=strategy)
        assert mit.strategy == strategy
        assert mit.verify() is True


# 9. verify semantics + read purity
def test_verify_semantics():
    ledger = ar.AIRisk()
    asm = ledger.assess("sys-1", 1, verdict="high")
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
    with pytest.raises(ar.UnknownAssessmentError):
        ledger.verify("nope", 3)
    with pytest.raises(ar.SeqOrderError):
        ledger.verify(asm.assessment_id, -1)
    # tamper is reported as data, never raised
    object.__setattr__(asm, "severity", 99)
    vt = ledger.verify(asm.assessment_id, 3)
    assert vt.verdict == "tampered"
    assert vt.integrity_ok is False


# 10. evaluate posture math
def test_evaluate_posture_math():
    # critical-open outranks everything
    ledger = ar.AIRisk()
    ledger.assess("s1", 1, risk_kind="misuse", verdict="critical", severity=90)
    rep = ledger.evaluate("s1", 2)
    assert rep.posture == "critical-open"
    assert rep.n_critical == 1 and rep.n_assessments == 1
    assert rep.verify() is True
    # at-risk: unmitigated high
    ledger2 = ar.AIRisk()
    ledger2.assess("s2", 1, verdict="high")
    assert ledger2.evaluate("s2", 2).posture == "at-risk"
    # monitored: unmitigated medium / not-assessed
    ledger3 = ar.AIRisk()
    ledger3.assess("s3", 1, verdict="medium")
    ledger3.assess("s3", 2, verdict="not-assessed")
    rep3 = ledger3.evaluate("s3", 3)
    assert rep3.posture == "monitored"
    assert rep3.n_medium == 1 and rep3.n_not_assessed == 1
    # mitigated: all critical/high covered
    ledger4 = ar.AIRisk()
    a4 = ledger4.assess("s4", 1, verdict="critical")
    ledger4.mitigate(a4.assessment_id, 2, strategy="deployment-hold")
    rep4 = ledger4.evaluate("s4", 3)
    assert rep4.posture == "mitigated"
    assert rep4.n_mitigated == 1
    # acceptable: only unmitigated lows
    ledger5 = ar.AIRisk()
    ledger5.assess("s5", 1, verdict="low")
    assert ledger5.evaluate("s5", 2).posture == "acceptable"
    # precedence: critical + high -> critical-open
    ledger6 = ar.AIRisk()
    ledger6.assess("s6", 1, verdict="high")
    ledger6.assess("s6", 2, verdict="critical")
    assert ledger6.evaluate("s6", 3).posture == "critical-open"


# 11. evaluate read purity + unknown system
def test_evaluate_read_purity():
    ledger = ar.AIRisk()
    ledger.assess("s1", 1, verdict="low")
    seq_before = ledger._seq
    audit_before = len(ledger.audit_log(0))
    r1 = ledger.evaluate("s1", 2)
    r2 = ledger.evaluate("s1", 2)
    assert r1.digest == r2.digest
    assert ledger._seq == seq_before
    assert len(ledger.audit_log(0)) == audit_before
    with pytest.raises(ar.UnknownSystemError):
        ledger.evaluate("unknown", 2)


# 12. retire terminality
def test_retire_terminality():
    ledger = ar.AIRisk()
    asm = ledger.assess("s1", 1, verdict="medium")
    with pytest.raises(ar.BadReasonError):
        ledger.retire("s1", 2, reason="nope")
    with pytest.raises(ar.UnknownSystemError):
        ledger.retire("unknown", 3)
    rec = ledger.retire("s1", 4, reason="withdrawn")
    assert rec.reason == "withdrawn"
    assert rec.verify() is True
    assert ledger.retired_ids(0) == ["s1"]
    # id non-recycling: the retired system id can never be reused
    with pytest.raises(ar.RetiredSystemError):
        ledger.assess("s1", 5)
    with pytest.raises(ar.RetiredSystemError):
        ledger.retire("s1", 6)
    # reads still work post-retire
    assert ledger.assessment_record(asm.assessment_id, 6) is asm
    rep = ledger.evaluate("s1", 6)
    assert rep.posture == "monitored"
    # all retire reasons accepted
    for i, reason in enumerate(ar.RETIRE_REASONS):
        ledger.assess(f"s-r{i}", 7 + 2 * i, verdict="low")
        r = ledger.retire(f"s-r{i}", 8 + 2 * i, reason=reason)
        assert r.reason == reason


# 13. seq discipline
def test_seq_discipline():
    ledger = ar.AIRisk()
    # genesis rewind (seq 0) raises bare with zero rows
    with pytest.raises(ar.SeqOrderError):
        ledger.assess("s", 0)
    assert ledger.audit_log(0) == []
    ledger.assess("s", 1)
    # rewind raises bare: no burn, no row
    with pytest.raises(ar.SeqOrderError):
        ledger.assess("s", 1)
    assert ledger._seq == 1
    assert ledger.audit_log(0) != []
    assert all(r["kind"] != "rejected" for r in ledger.audit_log(0))
    # failed mutation consumes seq
    with pytest.raises(ar.BadVerdictError):
        ledger.assess("s", 2, verdict="nope")
    assert ledger._seq == 2
    rec = ledger.assess("s", 3)
    assert rec.assessment_id == "asm-2"
    # views validate read-seq shape without consuming
    assert ledger.system_ids(3) == ["s"]
    with pytest.raises(ar.SeqOrderError):
        ledger.system_ids(-1)


# 14. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    ledger = ar.AIRisk()
    asm = ledger.assess("s1", 1, risk_kind="bio-risk", verdict="high")
    mit = ledger.mitigate(asm.assessment_id, 2, strategy="reduce")
    ledger.retire("s1", 3)
    kinds = [r["kind"] for r in ledger.audit_log(0)]
    assert kinds == ["assessed", "mitigated", "retired"]
    row = ledger.audit_log(0)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-risk"
    assert row["version"] == "ai-risk.v1"
    # pinned vocab values remain emittable as declared data
    assert row["details"]["risk_kind"] == "bio-risk"
    # raw-material keys are banned from the audit boundary
    with pytest.raises(ar.AIRiskError):
        ar.ai_risk_audit_event("assessed", 4, transcript="raw text")
    with pytest.raises(ar.AIRiskError):
        ar.ai_risk_audit_event("assessed", 4, weights=[1, 2, 3])
    with pytest.raises(ar.AuditKindError):
        ar.ai_risk_audit_event("nope", 4)
    with pytest.raises(ar.SeqOrderError):
        ar.ai_risk_audit_event("assessed", "1")
    # banned keys are not leaked by ledger emissions
    for r in ledger.audit_log(0):
        assert "transcript" not in r["details"]
    _ = mit


# 15. determinism, tamper, threads, main()
def test_determinism_threads_main():
    def build():
        ledger = ar.AIRisk()
        a = ledger.assess("s", 1, risk_kind="cyber-uplift", verdict="high",
                          severity=70, assessment_digest=PIN)
        m = ledger.mitigate(a.assessment_id, 2, strategy="red-team")
        return ledger, a, m

    l1, a1, m1 = build()
    l2, a2, _ = build()
    assert a1.digest == a2.digest
    assert m1.digest == l1.mitigation_record("mit-1", 0).digest
    # tamper breaks verify() and flips integrity_ok as data
    object.__setattr__(a1, "digest", "sha256:" + "00" * 32)
    assert a1.verify() is False
    rep = l1.evaluate("s", 3)
    assert rep.integrity_ok is False
    assert rep.posture == "mitigated"  # posture still derived as data
    # 8-thread read smoke
    errors = []

    def reader():
        try:
            for _ in range(50):
                l1.evaluate("s", 3)
                l1.verify("asm-1", 3)
                l1.stats(3)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    # main() subprocess check
    out = subprocess.run(
        [sys.executable, str(MOD)],
        cwd=MOD.parent,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert "ai-risk OK" in out.stdout
