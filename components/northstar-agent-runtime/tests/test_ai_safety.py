"""Tests for the ai-safety assessment/mitigation decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_safety.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_safety", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_safety"] = module
    spec.loader.exec_module(module)
    return module


sa = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert sa.AI_SAFETY_VERSION == "ai-safety.v1"
    assert sa.SCHEMA_PIN == "northstar.ai-safety.v1"
    assert sa.HAZARD_KINDS == (
        "capability-misuse",
        "misalignment",
        "specification-gaming",
        "deceptive-behavior",
        "power-seeking",
        "eval-gaming",
        "supply-chain-risk",
        "deployment-hazard",
    )
    assert sa.ASSESS_VERDICTS == ("safe", "unsafe", "uncertain", "inconclusive", "not-assessed")
    assert sa.MITIGATION_STRATEGIES == (
        "additional-oversight",
        "capability-restriction",
        "deployment-hold",
        "monitoring-escalation",
        "retraining",
        "red-teaming",
        "containment-hardening",
        "no-action",
    )
    assert sa.VERIFY_VERDICTS == ("verified", "tampered")
    assert sa.POSTURES == ("unassessed", "unsafe", "uncertain", "mitigated", "safe")
    assert sa.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert sa.AUDIT_KINDS == ("assessed", "mitigated", "retired", "rejected")


# 2. stdlib-only AST check + stdlib_only()
def test_stdlib_only_ast():
    assert sa.stdlib_only() is True
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


# 3. assess roundtrip + asm-N minting + verify() + frozen-ness
def test_assess_roundtrip():
    ledger = sa.AISafety()
    rec = ledger.assess(
        "sys-1", 1, hazard_kind="misalignment", verdict="unsafe",
        severity=70, assessment_digest=PIN,
    )
    assert rec.assessment_id == "asm-1"
    assert rec.system_id == "sys-1"
    assert rec.seq == 1
    assert rec.verify() is True
    rec2 = ledger.assess("sys-2", 2)
    assert rec2.assessment_id == "asm-2"
    assert rec2.verdict == "not-assessed"
    assert rec2.severity == 0
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "safe"  # type: ignore[misc]


# 4. assess bad-input table + seq-burn + rejected-row accounting + rewind bare
def test_assess_bad_inputs():
    ledger = sa.AISafety()
    bads = [
        ("", 1, "capability-misuse", "safe", 0, PIN),        # empty system id
        (123, 2, "capability-misuse", "safe", 0, PIN),       # non-string id
        ("sys-1", 3, "bogus-kind", "safe", 0, PIN),          # bad hazard kind
        ("sys-1", 4, "capability-misuse", "bogus", 0, PIN),  # bad verdict
        ("sys-1", 5, "capability-misuse", "safe", -1, PIN),  # severity low
        ("sys-1", 6, "capability-misuse", "safe", 101, PIN),  # severity high
        ("sys-1", 7, "capability-misuse", "safe", True, PIN),  # bool severity
        ("sys-1", 8, "capability-misuse", "safe", 0, "nope"),  # bad digest
        ("sys-1", 9, "capability-misuse", "safe", 50, "sha256:" + "zz" * 32),  # bad hex
        (None, 10, "capability-misuse", "safe", 0, PIN),     # None id
    ]
    for system_id, seq, kind, verdict, severity, digest in bads:
        with pytest.raises(sa.AISafetyError):
            ledger.assess(
                system_id, seq, hazard_kind=kind, verdict=verdict,
                severity=severity, assessment_digest=digest,
            )
    # claim-then-burn: each failed mutation consumed its seq
    assert ledger.stats(11)["seq"] == 10
    rejected = [r for r in ledger.audit_log(11) if r["kind"] == "rejected"]
    assert len(rejected) == 10
    # rewinds raise bare: no seq consumed, no rejected row
    with pytest.raises(sa.SeqOrderError):
        ledger.assess("sys-1", 10, hazard_kind="misalignment")
    assert ledger.stats(11)["seq"] == 10
    assert len([r for r in ledger.audit_log(11) if r["kind"] == "rejected"]) == 10
    # malformed seqs raise bare
    for bad_seq in (True, 1.5, "1", None):
        with pytest.raises(sa.SeqOrderError):
            ledger.assess("sys-1", bad_seq)


# 5. full hazard-kind vocabulary acceptance
def test_full_hazard_kind_vocabulary():
    ledger = sa.AISafety()
    seq = 0
    for i, kind in enumerate(sa.HAZARD_KINDS):
        seq += 1
        rec = ledger.assess("sys-1", seq, hazard_kind=kind, verdict="not-assessed")
        assert rec.hazard_kind == kind
        assert rec.assessment_id == f"asm-{i + 1}"


# 6. full verdict vocabulary + severity boundaries
def test_full_verdict_vocabulary_and_severity_bounds():
    ledger = sa.AISafety()
    for i, verdict in enumerate(sa.ASSESS_VERDICTS):
        rec = ledger.assess("sys-1", i + 1, verdict=verdict, severity=0)
        assert rec.verdict == verdict
    assert rec.severity == 0
    rec2 = ledger.assess("sys-2", 6, severity=100)
    assert rec2.severity == 100


# 7. mitigate roundtrip + mit-N minting + verify() + frozen-ness
def test_mitigate_roundtrip():
    ledger = sa.AISafety()
    asm = ledger.assess("sys-1", 1, hazard_kind="deceptive-behavior", verdict="unsafe")
    mit = ledger.mitigate(asm.assessment_id, 2, strategy="deployment-hold", mitigation_digest=PIN)
    assert mit.mitigation_id == "mit-1"
    assert mit.assessment_id == "asm-1"
    assert mit.system_id == "sys-1"
    assert mit.seq == 2
    assert mit.verify() is True
    mit2 = ledger.mitigate(asm.assessment_id, 3)
    assert mit2.mitigation_id == "mit-2"
    assert mit2.strategy == "no-action"
    with pytest.raises(dataclasses.FrozenInstanceError):
        mit.strategy = "retraining"  # type: ignore[misc]


# 8. mitigate refusals: unknown assessment, bad strategy, bad digest, retired
def test_mitigate_refusals():
    ledger = sa.AISafety()
    asm = ledger.assess("sys-1", 1, verdict="unsafe")
    ledger.retire("sys-1", 2)
    with pytest.raises(sa.UnknownAssessmentError):
        ledger.mitigate("asm-999", 3, strategy="retraining")
    with pytest.raises(sa.BadStrategyError):
        ledger.mitigate(asm.assessment_id, 4, strategy="bogus-strategy")
    with pytest.raises(sa.BadDigestError):
        ledger.mitigate(asm.assessment_id, 5, mitigation_digest="nope")
    with pytest.raises(sa.RetiredSystemError):
        ledger.mitigate(asm.assessment_id, 6, strategy="retraining")
    # failed mitigations burned their seqs; retire + 4 rejected rows
    assert ledger.stats(7)["seq"] == 6
    rejected = [r for r in ledger.audit_log(7) if r["kind"] == "rejected"]
    assert len(rejected) == 4


# 9. full strategy vocabulary + chainable mitigations
def test_strategy_vocabulary_and_chain():
    ledger = sa.AISafety()
    asm = ledger.assess("sys-1", 1, verdict="unsafe", severity=90)
    for i, strategy in enumerate(sa.MITIGATION_STRATEGIES):
        mit = ledger.mitigate(asm.assessment_id, i + 2, strategy=strategy)
        assert mit.strategy == strategy
        assert mit.mitigation_id == f"mit-{i + 1}"
    assert len(ledger.mitigations_for(asm.assessment_id, 10)) == len(sa.MITIGATION_STRATEGIES)


# 10. verify semantics: roundtrip, tamper-as-data, unknown, read purity
def test_verify_semantics():
    ledger = sa.AISafety()
    asm = ledger.assess("sys-1", 1, hazard_kind="power-seeking", verdict="safe", assessment_digest=PIN)
    mit = ledger.mitigate(asm.assessment_id, 2, strategy="additional-oversight", mitigation_digest=PIN2)
    rep = ledger.verify(asm.assessment_id, 3)
    assert rep.record_id == "asm-1"
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    rep2 = ledger.verify(mit.mitigation_id, 4)
    assert rep2.verdict == "verified"
    # tamper is reported as data, never raised
    object.__setattr__(asm, "verdict", "unsafe")
    tampered = ledger.verify(asm.assessment_id, 5)
    assert tampered.verdict == "tampered"
    assert tampered.integrity_ok is False
    # unknown records raise bare
    with pytest.raises(sa.UnknownRecordError):
        ledger.verify("asm-999", 6)
    # read purity: same-seq twice, no audit rows, no seq consumption
    a1 = ledger.verify(mit.mitigation_id, 7)
    a2 = ledger.verify(mit.mitigation_id, 7)
    assert a1.digest == a2.digest
    assert ledger.stats(8)["seq"] == 2
    assert all(r["kind"] in ("assessed", "mitigated") for r in ledger.audit_log(8))


# 11. evaluate posture math (all postures + precedence) + read purity
def test_evaluate_posture_math():
    ledger = sa.AISafety()
    # unassessed-equivalent: unknown system refuses fail-closed
    with pytest.raises(sa.UnknownSystemError):
        ledger.evaluate("no-such-system", 1)
    # unsafe posture: unmitigated unsafe outranks everything
    a1 = ledger.assess("sys-1", 1, hazard_kind="capability-misuse", verdict="unsafe", severity=80)
    a2 = ledger.assess("sys-1", 2, hazard_kind="misalignment", verdict="uncertain")
    ev = ledger.evaluate("sys-1", 3)
    assert ev.posture == "unsafe"
    assert ev.n_assessments == 2
    assert ev.n_unsafe == 1
    assert ev.n_uncertain == 1
    assert ev.integrity_ok is True
    assert ev.verify() is True
    # uncertain posture once the unsafe is mitigated
    ledger.mitigate(a1.assessment_id, 4, strategy="capability-restriction")
    ev2 = ledger.evaluate("sys-1", 5)
    assert ev2.posture == "uncertain"
    assert ev2.n_mitigated == 1
    # mitigated posture: all unsafe covered by mitigations
    a3 = ledger.assess("sys-2", 6, verdict="unsafe", severity=60)
    ledger.mitigate(a3.assessment_id, 7, strategy="deployment-hold")
    ev3 = ledger.evaluate("sys-2", 8)
    assert ev3.posture == "mitigated"
    # safe posture: all safe
    ledger.assess("sys-3", 9, verdict="safe")
    ledger.assess("sys-3", 10, verdict="safe")
    ev4 = ledger.evaluate("sys-3", 11)
    assert ev4.posture == "safe"
    # read purity
    ev5 = ledger.evaluate("sys-3", 11)
    assert ev4.digest == ev5.digest
    assert ledger.stats(12)["seq"] == 10


# 12. retire terminality + id non-recycling + post-retire reads
def test_retire_terminality():
    ledger = sa.AISafety()
    ledger.assess("sys-1", 1, verdict="safe")
    with pytest.raises(sa.BadReasonError):
        ledger.retire("sys-1", 2, reason="bogus")
    with pytest.raises(sa.UnknownSystemError):
        ledger.retire("no-such-system", 3)
    ret = ledger.retire("sys-1", 4, reason="decommissioned")
    assert ret.verify() is True
    assert ret.reason == "decommissioned"
    assert ledger.retired_ids(5) == ("sys-1",)
    # double retire refused
    with pytest.raises(sa.RetiredSystemError):
        ledger.retire("sys-1", 6)
    # post-retire mutations refused, reads still work
    with pytest.raises(sa.RetiredSystemError):
        ledger.assess("sys-1", 7, hazard_kind="misalignment")
    ev = ledger.evaluate("sys-1", 8)
    assert ev.posture == "safe"
    assert ledger.assessments_for("sys-1", 8)[0].verify() is True
    rejected = [r for r in ledger.audit_log(9) if r["kind"] == "rejected"]
    assert len(rejected) == 4


# 13. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    ledger = sa.AISafety()
    with pytest.raises(sa.SeqOrderError):
        ledger.assess("sys-1", 0, hazard_kind="misalignment")  # rewind at genesis: bare
    assert ledger.stats(1)["seq"] == 0
    ledger.assess("sys-1", 1, hazard_kind="misalignment")
    with pytest.raises(sa.SeqOrderError):
        ledger.assess("sys-1", 1, hazard_kind="misalignment")  # rewind: bare, no burn
    assert len([r for r in ledger.audit_log(2) if r["kind"] == "rejected"]) == 0
    with pytest.raises(sa.BadHazardKindError):
        ledger.assess("sys-1", 2, hazard_kind="bogus")  # failed mutation: burn + row
    assert ledger.stats(3)["seq"] == 2
    rejected = [r for r in ledger.audit_log(3) if r["kind"] == "rejected"]
    assert len(rejected) == 1
    assert rejected[0]["details"]["rejected_kind"] == "BadHazardKindError"
    # read-seq shape: negative/malformed raise bare, no rows
    for bad in (True, 1.5, "1", None, -1):
        with pytest.raises(sa.SeqOrderError):
            ledger.evaluate("sys-1", bad)
    assert len([r for r in ledger.audit_log(4) if r["kind"] == "rejected"]) == 1


# 14. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    ledger = sa.AISafety()
    ledger.assess("sys-1", 1, hazard_kind="eval-gaming", verdict="unsafe", severity=55, assessment_digest=PIN)
    ledger.mitigate("asm-1", 2, strategy="red-teaming", mitigation_digest=PIN2)
    ledger.retire("sys-1", 3)
    rows = ledger.audit_log(4)
    by_kind = {r["kind"]: r for r in rows}
    assert set(by_kind) == {"assessed", "mitigated", "retired"}
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-safety"
        assert r["version"] == "ai-safety.v1"
    assert by_kind["assessed"]["details"]["hazard_kind"] == "eval-gaming"
    assert by_kind["mitigated"]["details"]["strategy"] == "red-teaming"
    assert by_kind["retired"]["details"]["reason"] == "manual"
    # banned raw keys may not cross the audit boundary
    for banned in ("transcript", "weights", "trajectory", "prompt", "activations", "behavior"):
        with pytest.raises(sa.AISafetyError):
            sa.ai_safety_audit_event("assessed", 4, **{banned: "raw-value"})
    # digest pins of banned names are fine; pinned vocabulary values are declared data
    row = sa.ai_safety_audit_event("assessed", 4, hazard_kind="misalignment", verdict="unsafe")
    assert row["kind"] == "assessed"
    # bad kind / bad seq
    with pytest.raises(sa.AuditKindError):
        sa.ai_safety_audit_event("bogus", 5)
    with pytest.raises(sa.SeqOrderError):
        sa.ai_safety_audit_event("assessed", True)


# 15. cross-instance determinism + tamper + 8-thread reads + main() subprocess
def test_determinism_threads_and_main():
    l1 = sa.AISafety()
    l2 = sa.AISafety()
    for ledger in (l1, l2):
        a = ledger.assess("sys-1", 1, hazard_kind="supply-chain-risk", verdict="unsafe", severity=40, assessment_digest=PIN)
        ledger.mitigate(a.assessment_id, 2, strategy="monitoring-escalation", mitigation_digest=PIN2)
    d1 = l1.assessment_record("asm-1", 3).digest
    d2 = l2.assessment_record("asm-1", 3).digest
    assert d1 == d2
    # tamper breaks verify()
    rec = l1.assessment_record("asm-1", 3)
    object.__setattr__(rec, "severity", 100)
    assert rec.verify() is False
    ev = l1.evaluate("sys-1", 4)
    assert ev.integrity_ok is False
    # frozen-ness
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.severity = 0  # type: ignore[misc]
    # 8-thread read smoke
    errors = []

    def reader():
        try:
            for _ in range(50):
                l2.evaluate("sys-1", 5)
                l2.verify("asm-1", 5)
                l2.stats(5)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # main() self-check
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0
    assert "ai-safety OK" in proc.stdout
