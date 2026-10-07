"""Tests for the ai-security assessment/mitigation decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_security.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_security", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_security"] = module
    spec.loader.exec_module(module)
    return module


sa = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert sa.AI_SECURITY_VERSION == "ai-security.v1"
    assert sa.SCHEMA_PIN == "northstar.ai-security.v1"
    assert sa.SECURITY_THREATS == (
        "prompt-injection",
        "model-extraction",
        "data-poisoning",
        "backdoor-insertion",
        "jailbreak",
        "adversarial-example",
        "supply-chain-compromise",
        "inference-abuse",
    )
    assert sa.ASSESS_VERDICTS == ("secure", "vulnerable", "uncertain", "inconclusive", "not-assessed")
    assert sa.MITIGATION_STRATEGIES == (
        "input-sanitization",
        "access-restriction",
        "model-hardening",
        "monitoring-escalation",
        "patch-deployment",
        "isolation",
        "key-rotation",
        "no-action",
    )
    assert sa.VERIFY_VERDICTS == ("verified", "tampered")
    assert sa.POSTURES == ("unassessed", "vulnerable", "uncertain", "mitigated", "secure")
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
    ledger = sa.AISecurity()
    rec = ledger.assess(
        "sys-1", 1, threat_kind="jailbreak", verdict="vulnerable",
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
        rec.verdict = "secure"  # type: ignore[misc]


# 4. assess bad-input table + seq-burn + rejected-row accounting + rewind bare
def test_assess_bad_inputs():
    ledger = sa.AISecurity()
    bads = [
        ("", 1, "prompt-injection", "secure", 0, PIN),        # empty system id
        (123, 2, "prompt-injection", "secure", 0, PIN),       # non-string id
        ("sys-1", 3, "bogus-kind", "secure", 0, PIN),         # bad threat kind
        ("sys-1", 4, "prompt-injection", "bogus", 0, PIN),    # bad verdict
        ("sys-1", 5, "prompt-injection", "secure", -1, PIN),  # severity low
        ("sys-1", 6, "prompt-injection", "secure", 101, PIN),  # severity high
        ("sys-1", 7, "prompt-injection", "secure", True, PIN),  # bool severity
        ("sys-1", 8, "prompt-injection", "secure", 0, "nope"),  # bad digest
        ("sys-1", 9, "prompt-injection", "secure", 50, "sha256:" + "zz" * 32),  # bad hex
        (None, 10, "prompt-injection", "secure", 0, PIN),     # None id
    ]
    for system_id, seq, kind, verdict, severity, digest in bads:
        with pytest.raises(sa.AISecurityError):
            ledger.assess(
                system_id, seq, threat_kind=kind, verdict=verdict,
                severity=severity, assessment_digest=digest,
            )
    # claim-then-burn: each failed mutation consumed its seq
    assert ledger.stats(11)["seq"] == 10
    rejected = [r for r in ledger.audit_log(11) if r["kind"] == "rejected"]
    assert len(rejected) == 10
    # rewind raises bare SeqOrderError with no new row
    n_before = len(ledger.audit_log(11))
    with pytest.raises(sa.SeqOrderError):
        ledger.assess("sys-1", 5, threat_kind="jailbreak")
    assert len(ledger.audit_log(11)) == n_before
    assert ledger.stats(11)["seq"] == 10


# 5. full 8-threat vocabulary acceptance
def test_full_threat_vocabulary():
    ledger = sa.AISecurity()
    for i, kind in enumerate(sa.SECURITY_THREATS):
        rec = ledger.assess("sys-1", i + 1, threat_kind=kind, verdict="secure")
        assert rec.threat_kind == kind
        assert rec.verify() is True
    assert ledger.stats(9)["n_assessments"] == 8


# 6. full 5-verdict vocabulary + severity boundaries
def test_full_verdict_vocabulary_and_severity_bounds():
    ledger = sa.AISecurity()
    for i, verdict in enumerate(sa.ASSESS_VERDICTS):
        rec = ledger.assess("sys-1", i + 1, verdict=verdict)
        assert rec.verdict == verdict
    rec_lo = ledger.assess("sys-2", 6, severity=0)
    assert rec_lo.severity == 0
    rec_hi = ledger.assess("sys-2", 7, severity=100)
    assert rec_hi.severity == 100
    ev = ledger.evaluate("sys-1", 8)
    assert ev.n_secure == 1
    assert ev.n_vulnerable == 1
    assert ev.n_uncertain == 1
    assert ev.n_inconclusive == 1
    assert ev.n_not_assessed == 1


# 7. mitigate roundtrip + mit-N minting + unknown-assessment refusal
def test_mitigate_roundtrip():
    ledger = sa.AISecurity()
    rec = ledger.assess("sys-1", 1, threat_kind="data-poisoning", verdict="vulnerable")
    mit = ledger.mitigate(rec.assessment_id, 2, strategy="patch-deployment")
    assert mit.mitigation_id == "mit-1"
    assert mit.assessment_id == rec.assessment_id
    assert mit.system_id == "sys-1"
    assert mit.verify() is True
    mit2 = ledger.mitigate(rec.assessment_id, 3, strategy="model-hardening")
    assert mit2.mitigation_id == "mit-2"
    with pytest.raises(sa.UnknownAssessmentError):
        ledger.mitigate("asm-999", 4, strategy="isolation")


# 8. mitigate bad-input table + full 8-strategy vocabulary
def test_mitigate_bad_inputs_and_strategies():
    ledger = sa.AISecurity()
    rec = ledger.assess("sys-1", 1, verdict="vulnerable")
    bads = [
        ("asm-999", 2, "isolation", PIN),     # unknown assessment
        (rec.assessment_id, 3, "bogus", PIN),  # bad strategy
        (rec.assessment_id, 4, "isolation", "nope"),  # bad digest
        ("", 5, "isolation", PIN),             # empty id
    ]
    for assessment_id, seq, strategy, digest in bads:
        with pytest.raises(sa.AISecurityError):
            ledger.mitigate(
                assessment_id, seq, strategy=strategy,
                mitigation_digest=digest,
            )
    for i, strategy in enumerate(sa.MITIGATION_STRATEGIES):
        mit = ledger.mitigate(rec.assessment_id, 6 + i, strategy=strategy)
        assert mit.strategy == strategy
        assert mit.verify() is True


# 9. verify semantics: verified/tampered-as-data + unknown refusal + read purity
def test_verify_semantics():
    ledger = sa.AISecurity()
    rec = ledger.assess("sys-1", 1, verdict="vulnerable")
    rep = ledger.verify(rec.assessment_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # read purity: same-seq twice, no audit rows, no seq consumption
    seq_before = ledger.stats(3)["seq"]
    n_before = ledger.stats(3)["n_audit_rows"]
    rep2 = ledger.verify(rec.assessment_id, 2)
    assert rep2.verdict == "verified"
    assert ledger.stats(3)["seq"] == seq_before
    assert ledger.stats(3)["n_audit_rows"] == n_before
    # tamper reported as data, never raised
    object.__setattr__(rec, "threat_kind", "jailbreak")
    rep3 = ledger.verify(rec.assessment_id, 4)
    assert rep3.verdict == "tampered"
    assert rep3.integrity_ok is False
    with pytest.raises(sa.UnknownRecordError):
        ledger.verify("asm-999", 5)


# 10. evaluate posture math (all 5 postures + precedence) + read purity + unknown
def test_evaluate_posture_math():
    ledger = sa.AISecurity()
    # vulnerable: unmitigated vulnerable outranks everything
    rec = ledger.assess("sys-1", 1, verdict="vulnerable")
    ev = ledger.evaluate("sys-1", 2)
    assert ev.posture == "vulnerable"
    assert ev.n_vulnerable == 1
    assert ev.n_mitigated == 0
    assert ev.integrity_ok is True
    assert ev.verify() is True
    # mitigated: vulnerable covered by a mitigation
    ledger.mitigate(rec.assessment_id, 3, strategy="isolation")
    ev = ledger.evaluate("sys-1", 4)
    assert ev.posture == "mitigated"
    assert ev.n_mitigated == 1
    # uncertain: uncertain/inconclusive outranks mitigated
    ledger.assess("sys-1", 5, verdict="uncertain")
    ev = ledger.evaluate("sys-1", 6)
    assert ev.posture == "uncertain"
    # secure: a system with only secure verdicts
    ledger.assess("sys-2", 7, verdict="secure")
    ev2 = ledger.evaluate("sys-2", 8)
    assert ev2.posture == "secure"
    # read purity + unknown system
    seq_before = ledger.stats(9)["seq"]
    ev_again = ledger.evaluate("sys-2", 8)
    assert ev_again.posture == "secure"
    assert ledger.stats(9)["seq"] == seq_before
    with pytest.raises(sa.UnknownSystemError):
        ledger.evaluate("sys-999", 10)


# 11. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    ledger = sa.AISecurity()
    ledger.assess("sys-1", 1, verdict="secure")
    ret = ledger.retire("sys-1", 2, reason="decommissioned")
    assert ret.system_id == "sys-1"
    assert ret.reason == "decommissioned"
    assert ret.verify() is True
    # post-retire mutations refused; reads still work
    with pytest.raises(sa.RetiredSystemError):
        ledger.assess("sys-1", 3)
    # mitigate on the retired system's assessment is refused too
    asm_id = ledger.assessment_ids(2)[0]
    with pytest.raises(sa.RetiredSystemError):
        ledger.mitigate(asm_id, 4, strategy="isolation")
    ev = ledger.evaluate("sys-1", 5)
    assert ev.posture == "secure"
    assert "sys-1" in ledger.retired_ids(5)
    # id never recycled: new assessment on retired id refused
    with pytest.raises(sa.AISecurityError):
        ledger.assess("sys-1", 6)
    # bad reason burns seq; unknown system burns seq
    with pytest.raises(sa.BadReasonError):
        ledger.retire("sys-2", 7, reason="bogus")
    with pytest.raises(sa.UnknownSystemError):
        ledger.retire("sys-999", 8)


# 12. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    ledger = sa.AISecurity()
    # genesis rewind (seq 0) raises bare with zero rows
    with pytest.raises(sa.SeqOrderError):
        ledger.assess("sys-1", 0)
    assert ledger.stats(0)["n_audit_rows"] == 0
    rec = ledger.assess("sys-1", 1)
    for bad_seq in (True, 1.5, "1", None):
        with pytest.raises(sa.SeqOrderError):
            ledger.assess("sys-2", bad_seq)  # type: ignore[arg-type]
    assert ledger.stats(2)["seq"] == 1
    # failed mutation consumes seq and books a rejected row
    with pytest.raises(sa.BadVerdictError):
        ledger.assess("sys-2", 2, verdict="bogus")
    assert ledger.stats(3)["seq"] == 2
    rejected = [r for r in ledger.audit_log(3) if r["kind"] == "rejected"]
    assert len(rejected) == 1
    assert rejected[0]["details"]["rejected_kind"] == "BadVerdictError"


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = sa.AISecurity()
    rec = ledger.assess("sys-1", 1, threat_kind="jailbreak", verdict="vulnerable", severity=60)
    mit = ledger.mitigate(rec.assessment_id, 2, strategy="input-sanitization")
    rows = ledger.audit_log(3)
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["module"] == "ai-security"
    assert rows[0]["version"] == "ai-security.v1"
    assert rows[0]["kind"] == "assessed"
    assert rows[0]["details"]["threat_kind"] == "jailbreak"
    assert rows[1]["kind"] == "mitigated"
    # pinned vocabulary values are emittable as declared data
    ev = sa.ai_security_audit_event("assessed", 4, threat_kind="jailbreak", verdict="vulnerable")
    assert ev["details"]["threat_kind"] == "jailbreak"
    # raw material keys are banned at the builder level
    for banned in ("exploit", "payload", "password", "api_key", "prompt"):
        with pytest.raises(sa.AISecurityError):
            sa.ai_security_audit_event("assessed", 5, **{banned: "raw"})
    # bad audit kind
    with pytest.raises(sa.AuditKindError):
        sa.ai_security_audit_event("bogus", 6)
    with pytest.raises(sa.AuditKindError):
        sa.ai_security_audit_event("bogus", 6, threat_kind="jailbreak")


# 14. cross-instance digest determinism + views/stats + unknown lookups
def test_determinism_views_and_stats():
    a = sa.AISecurity()
    b = sa.AISecurity()
    ra = a.assess("sys-1", 1, threat_kind="jailbreak", verdict="vulnerable", severity=60)
    rb = b.assess("sys-1", 1, threat_kind="jailbreak", verdict="vulnerable", severity=60)
    assert ra.digest == rb.digest
    assert ra.assessment_id == rb.assessment_id == "asm-1"
    # tamper breaks verify()
    object.__setattr__(ra, "severity", 99)
    assert ra.verify() is False
    assert rb.verify() is True
    # views
    assert a.assessment_record("asm-1", 2).system_id == "sys-1"
    assert a.assessments_for("sys-1", 2) == (a.assessment_record("asm-1", 2),)
    assert a.system_ids(2) == ("sys-1",)
    assert a.assessment_ids(2) == ("asm-1",)
    assert a.mitigation_ids(2) == ()
    assert a.retired_ids(2) == ()
    st = a.stats(2)
    assert st["n_systems"] == 1 and st["n_assessments"] == 1
    assert st["n_mitigations"] == 0 and st["n_retired"] == 0
    # unknown lookups
    with pytest.raises(sa.UnknownAssessmentError):
        a.assessment_record("asm-999", 2)
    with pytest.raises(sa.UnknownMitigationError):
        a.mitigation_record("mit-999", 2)


# 15. main() subprocess check + 8-thread read smoke + frozen-ness
def test_main_and_thread_smoke():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert "ai-security OK: assess, mitigate, verify, evaluate, retire, pins, audit" in proc.stdout
    ledger = sa.AISecurity()
    rec = ledger.assess("sys-1", 1, verdict="secure")
    results = []
    errors = []

    def reader():
        try:
            for _ in range(200):
                ev = ledger.evaluate("sys-1", 0)
                rep = ledger.verify(rec.assessment_id, 0)
                assert ev.posture == "secure"
                assert rep.verdict == "verified"
            results.append(True)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(results) == 8
    # frozen-ness of all record types
    mit = ledger.mitigate(rec.assessment_id, 2)
    with pytest.raises(dataclasses.FrozenInstanceError):
        mit.strategy = "isolation"  # type: ignore[misc]
