"""Tests for the ai-compliance-verification decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_compliance_verification.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_compliance_verification", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_compliance_verification"] = module
    spec.loader.exec_module(module)
    return module


cv = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert cv.AI_COMPLIANCE_VERIFICATION_VERSION == "ai-compliance-verification.v1"
    assert cv.SCHEMA_PIN == "northstar.ai-compliance-verification.v1"
    assert cv.CHECK_KINDS == (
        "regulatory-requirement-review",
        "compliance-obligation-assessment",
        "policy-conformance-verification",
        "control-effectiveness-check",
        "compliance-independence-review",
        "continuous-compliance-check",
        "compliance-record-completeness-check",
        "authority-scope-review",
    )
    assert cv.VERIFY_VERDICTS == (
        "verified",
        "partial",
        "failed",
        "inconclusive",
        "not-verified",
    )
    assert cv.CERTIFICATION_KINDS == (
        "independent-review",
        "third-party-audit",
        "regulator-approval",
        "peer-review",
        "internal-qa",
        "external-lab",
        "standards-body",
        "self-attestation",
    )
    assert cv.CERTIFICATION_OUTCOMES == (
        "endorsed",
        "qualified",
        "withheld",
        "inconclusive",
    )
    assert cv.POSTURES == (
        "unverified",
        "failed",
        "contested",
        "partially-verified",
        "verified",
        "certified",
    )
    assert cv.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert cv.AUDIT_KINDS == ("verified", "certified", "retired", "rejected")


# 2. stdlib-only AST check + stdlib_only()
def test_stdlib_only_ast():
    assert cv.stdlib_only() is True
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


# 3. verify roundtrip + ver-N minting + verify() + frozen-ness
def test_verify_roundtrip():
    ledger = cv.AIComplianceVerification()
    rec = ledger.verify(
        "sys-1", 1, check_kind="regulatory-requirement-review", verdict="verified",
        severity=5, verification_digest=PIN,
    )
    assert rec.verification_id == "ver-1"
    assert rec.subject_id == "sys-1"
    assert rec.seq == 1
    assert rec.verify() is True
    rec2 = ledger.verify("sys-2", 2)
    assert rec2.verification_id == "ver-2"
    assert rec2.verdict == "not-verified"
    assert rec2.severity == 0
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "failed"  # type: ignore[misc]


# 4. verify bad-input table + seq-burn + rejected-row accounting + rewind bare
def test_verify_bad_inputs():
    ledger = cv.AIComplianceVerification()
    bads = [
        ({"subject_id": "sys-1", "check_kind": "nope"}, cv.BadCheckKindError),
        ({"subject_id": "sys-1", "verdict": "nope"}, cv.BadVerdictError),
        ({"subject_id": "sys-1", "severity": -1}, cv.BadSeverityError),
        ({"subject_id": "sys-1", "severity": 101}, cv.BadSeverityError),
        ({"subject_id": "sys-1", "severity": True}, cv.BadSeverityError),
        ({"subject_id": "sys-1", "verification_digest": "nope"}, cv.BadDigestError),
        ({"subject_id": ""}, cv.BadSubjectError),
    ]
    n_rejected = 0
    for seq, (kw, exc) in enumerate(bads, start=1):
        subject = kw.pop("subject_id")
        with pytest.raises(exc):
            ledger.verify(subject, seq, **kw)
        n_rejected += 1
    assert ledger._seq == len(bads)
    rejected = [r for r in ledger._audit if r["kind"] == "rejected"]
    assert len(rejected) == n_rejected
    # rewind raises bare, consumes nothing
    with pytest.raises(cv.SeqOrderError):
        ledger.verify("sys-1", 1)
    assert ledger._seq == len(bads)
    assert len([r for r in ledger._audit if r["kind"] == "rejected"]) == n_rejected


# 5. full 8-check-kind vocabulary accepted
def test_full_check_kind_vocabulary():
    ledger = cv.AIComplianceVerification()
    for i, kind in enumerate(cv.CHECK_KINDS, start=1):
        rec = ledger.verify(f"sys-k{i}", i, check_kind=kind)
        assert rec.check_kind == kind
        assert rec.verify() is True


# 6. full 5-verdict vocabulary + tallies
def test_full_verdict_vocabulary():
    ledger = cv.AIComplianceVerification()
    for i, verdict in enumerate(cv.VERIFY_VERDICTS, start=1):
        rec = ledger.verify("sys-v", i, verdict=verdict)
        assert rec.verdict == verdict
    ev = ledger.evaluate("sys-v", 100)
    assert ev.n_verifications == 5
    assert ev.n_verified == 1
    assert ev.n_partial == 1
    assert ev.n_failed == 1
    assert ev.n_inconclusive == 1
    assert ev.n_not_verified == 1
    assert ev.posture == "failed"  # failed outranks


# 7. certify roundtrip + minted crt-N + chain on one verification
def test_certify_roundtrip():
    ledger = cv.AIComplianceVerification()
    rec = ledger.verify("sys-1", 1, verdict="verified")
    crt = ledger.certify(
        rec.verification_id, 2, certification_kind="independent-review",
        outcome="endorsed", certification_digest=PIN,
    )
    assert crt.certification_id == "crt-1"
    assert crt.verification_id == rec.verification_id
    assert crt.subject_id == "sys-1"
    assert crt.verify() is True
    # chain: second certification on the same verification
    crt2 = ledger.certify(rec.verification_id, 3, certification_kind="peer-review")
    assert crt2.certification_id == "crt-2"
    certs = ledger.certifications_for(rec.verification_id, 0)
    assert len(certs) == 2


# 8. certify refusal table (unknown/bad-kind/bad-outcome/bad-digest/retired)
def test_certify_refusals():
    ledger = cv.AIComplianceVerification()
    rec = ledger.verify("sys-1", 1)
    with pytest.raises(cv.UnknownVerificationError):
        ledger.certify("ver-999", 2)
    with pytest.raises(cv.BadCertificationKindError):
        ledger.certify(rec.verification_id, 3, certification_kind="nope")
    with pytest.raises(cv.BadOutcomeError):
        ledger.certify(rec.verification_id, 4, outcome="nope")
    with pytest.raises(cv.BadDigestError):
        ledger.certify(rec.verification_id, 5, certification_digest="bad")
    ledger.retire("sys-1", 6)
    with pytest.raises(cv.RetiredSubjectError):
        ledger.certify(rec.verification_id, 7)
    rejected = [r for r in ledger._audit if r["kind"] == "rejected"]
    assert len(rejected) == 5


# 9. evaluate posture math (all reachable postures + precedence)
def test_evaluate_posture_math():
    # certified: all verified + every verification endorsed
    ledger = cv.AIComplianceVerification()
    r1 = ledger.verify("s-cert", 1, verdict="verified")
    ledger.certify(r1.verification_id, 2, outcome="endorsed")
    r2 = ledger.verify("s-cert", 3, verdict="verified")
    ledger.certify(r2.verification_id, 4, outcome="endorsed")
    ev = ledger.evaluate("s-cert", 100)
    assert ev.posture == "certified"
    # verified: all verified, no endorsements needed
    ledger2 = cv.AIComplianceVerification()
    ledger2.verify("s-ver", 1, verdict="verified")
    ev2 = ledger2.evaluate("s-ver", 100)
    assert ev2.posture == "verified"
    # withheld certification fails the subject
    ledger3 = cv.AIComplianceVerification()
    r = ledger3.verify("s-w", 1, verdict="verified")
    ledger3.certify(r.verification_id, 2, outcome="withheld")
    ev3 = ledger3.evaluate("s-w", 100)
    assert ev3.posture == "failed"
    # inconclusive -> contested
    ledger4 = cv.AIComplianceVerification()
    ledger4.verify("s-c", 1, verdict="verified")
    ledger4.verify("s-c", 2, verdict="inconclusive")
    ev4 = ledger4.evaluate("s-c", 100)
    assert ev4.posture == "contested"
    # partial -> partially-verified
    ledger5 = cv.AIComplianceVerification()
    ledger5.verify("s-p", 1, verdict="verified")
    ledger5.verify("s-p", 2, verdict="partial")
    ev5 = ledger5.evaluate("s-p", 100)
    assert ev5.posture == "partially-verified"
    # unknown subject refused
    with pytest.raises(cv.UnknownSubjectError):
        ledger.evaluate("nope", 100)


# 10. verify_report semantics + tamper-as-data + read purity + unknown refusal
def test_verify_report_semantics():
    ledger = cv.AIComplianceVerification()
    rec = ledger.verify("sys-1", 1, verdict="verified")
    rep = ledger.verify_report(rec.verification_id, 0)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # read purity: same read seq twice, no audit rows
    n_audit = len(ledger._audit)
    rep2 = ledger.verify_report(rec.verification_id, 0)
    assert rep2.verdict == "verified"
    assert len(ledger._audit) == n_audit
    # tamper reported as data, never raised
    object.__setattr__(rec, "verdict", "failed")
    rep3 = ledger.verify_report(rec.verification_id, 0)
    assert rep3.verdict == "tampered"
    assert rep3.integrity_ok is False
    with pytest.raises(cv.UnknownRecordError):
        ledger.verify_report("nope", 0)


# 11. retire terminality + id non-recycling + post-retire reads
def test_retire_terminality():
    ledger = cv.AIComplianceVerification()
    rec = ledger.verify("sys-1", 1, verdict="verified")
    ret = ledger.retire("sys-1", 2, reason="decommissioned")
    assert ret.verify() is True
    assert ret.reason == "decommissioned"
    assert ledger.retired_ids(0) == ("sys-1",)
    # post-retire mutations refused, reads still work
    with pytest.raises(cv.RetiredSubjectError):
        ledger.verify("sys-1", 3)
    with pytest.raises(cv.RetiredSubjectError):
        ledger.retire("sys-1", 4)
    rec2 = ledger.verification_record(rec.verification_id, 0)
    assert rec2.verification_id == rec.verification_id
    ev = ledger.evaluate("sys-1", 0)
    assert ev.subject_id == "sys-1"
    # bad reason
    ledger.verify("sys-2", 10)
    with pytest.raises(cv.BadReasonError):
        ledger.retire("sys-2", 11, reason="nope")
    # unknown subject
    with pytest.raises(cv.UnknownSubjectError):
        ledger.retire("nope", 12)


# 12. seq discipline (genesis/malformed seqs, rewind bare, burn-on-failure)
def test_seq_discipline():
    ledger = cv.AIComplianceVerification()
    # genesis rewind (seq 0 before any claim) raises bare with zero rows
    with pytest.raises(cv.SeqOrderError):
        ledger.verify("sys-1", 0)
    assert ledger._seq == 0
    assert ledger._audit == []
    # malformed seqs raise bare
    for bad_seq in (True, 1.5, "1", None):
        with pytest.raises(cv.SeqOrderError):
            ledger.verify("sys-1", bad_seq)
        assert ledger._seq == 0
        assert ledger._audit == []
    # failed mutation consumes seq
    with pytest.raises(cv.BadCheckKindError):
        ledger.verify("sys-1", 1, check_kind="nope")
    assert ledger._seq == 1
    assert len([r for r in ledger._audit if r["kind"] == "rejected"]) == 1
    # gap seqs allowed
    rec = ledger.verify("sys-1", 50)
    assert rec.seq == 50


# 13. audit shapes + leak ban + bad-kind + pinned-data passthrough
def test_audit_shapes_and_leak_ban():
    ledger = cv.AIComplianceVerification()
    rec = ledger.verify("sys-1", 1, check_kind="regulatory-requirement-review", verdict="verified")
    rows = [r for r in ledger._audit if r["kind"] == "verified"]
    assert len(rows) == 1
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-compliance-verification"
    assert row["version"] == "ai-compliance-verification.v1"
    assert row["details"]["check_kind"] == "regulatory-requirement-review"  # pinned data passthrough
    assert row["details"]["verdict"] == "verified"
    # banned raw keys raise at builder level
    with pytest.raises(cv.AuditKindError):
        cv.ai_compliance_verification_audit_event("nope", 1)
    with pytest.raises(cv.AIComplianceVerificationError):
        cv.ai_compliance_verification_audit_event("verified", 1, weights="raw")
    with pytest.raises(cv.AIComplianceVerificationError):
        cv.ai_compliance_verification_audit_event("certified", 1, proof_script="raw")
    with pytest.raises(cv.AIComplianceVerificationError):
        cv.ai_compliance_verification_audit_event("verified", 1, compliance_report="raw")
    with pytest.raises(cv.AIComplianceVerificationError):
        cv.ai_compliance_verification_audit_event("verified", 1, permit_record="raw")
    # digest pins of banned material are fine
    ok = cv.ai_compliance_verification_audit_event(
        "verified", 1, proof_script_digest=PIN
    )
    assert ok["kind"] == "verified"


# 14. views/stats + unknown lookups + cross-instance digest determinism
def test_views_stats_and_determinism():
    ledger = cv.AIComplianceVerification()
    r1 = ledger.verify("sys-a", 1, verdict="verified")
    r2 = ledger.verify("sys-a", 2, verdict="partial")
    ledger.certify(r1.verification_id, 3, outcome="endorsed")
    assert ledger.subject_ids(0) == ("sys-a",)
    assert ledger.verification_ids(0) == ("ver-1", "ver-2")
    assert ledger.certification_ids(0) == ("crt-1",)
    assert len(ledger.verifications_for("sys-a", 0)) == 2
    stats = ledger.stats(0)
    assert stats["n_subjects"] == 1
    assert stats["n_verifications"] == 2
    assert stats["n_certifications"] == 1
    with pytest.raises(cv.UnknownVerificationError):
        ledger.verification_record("ver-999", 0)
    with pytest.raises(cv.UnknownCertificationError):
        ledger.certification_record("crt-999", 0)
    # cross-instance digest determinism: same inputs, same digest
    ledger2 = cv.AIComplianceVerification()
    r1b = ledger2.verify("sys-a", 1, verdict="verified")
    assert r1b.digest == r1.digest


# 15. 8-thread read smoke + main() subprocess check
def test_concurrency_and_main():
    ledger = cv.AIComplianceVerification()
    rec = ledger.verify("sys-1", 1, verdict="verified")
    errors = []

    def reader():
        try:
            for _ in range(50):
                assert ledger.verify_report(rec.verification_id, 0).verdict == "verified"
                assert ledger.evaluate("sys-1", 0).subject_id == "sys-1"
                assert ledger.stats(0)["n_verifications"] == 1
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # frozen-ness across instances
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "failed"  # type: ignore[misc]
    # main() self-check via subprocess
    out = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert "ai-compliance-verification OK" in out.stdout
