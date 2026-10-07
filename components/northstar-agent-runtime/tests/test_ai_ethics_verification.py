"""Tests for the ai-ethics-verification decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_ethics_verification.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_ethics_verification", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_ethics_verification"] = module
    spec.loader.exec_module(module)
    return module


ev = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ev.AI_ETHICS_VERIFICATION_VERSION == "ai-ethics-verification.v1"
    assert ev.SCHEMA_PIN == "northstar.ai-ethics-verification.v1"
    assert ev.CHECK_KINDS == (
        "fairness-review",
        "bias-screen",
        "harm-assessment",
        "transparency-review",
        "accountability-check",
        "consent-verification",
        "value-alignment-review",
        "stakeholder-impact-review",
    )
    assert ev.VERIFY_VERDICTS == (
        "verified",
        "partial",
        "failed",
        "inconclusive",
        "not-verified",
    )
    assert ev.CERTIFICATION_KINDS == (
        "independent-review",
        "third-party-audit",
        "regulator-approval",
        "peer-review",
        "internal-qa",
        "external-lab",
        "standards-body",
        "self-attestation",
    )
    assert ev.CERTIFICATION_OUTCOMES == (
        "endorsed",
        "qualified",
        "withheld",
        "inconclusive",
    )
    assert ev.POSTURES == (
        "unverified",
        "failed",
        "contested",
        "partially-verified",
        "verified",
        "certified",
    )
    assert ev.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert ev.AUDIT_KINDS == ("verified", "certified", "retired", "rejected")


# 2. stdlib-only AST check + stdlib_only()
def test_stdlib_only_ast():
    assert ev.stdlib_only() is True
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
    ledger = ev.AIEthicsVerification()
    rec = ledger.verify(
        "sys-1", 1, check_kind="fairness-review", verdict="verified",
        severity=10, verification_digest=PIN,
    )
    assert rec.verification_id == "ver-1"
    assert rec.subject_id == "sys-1"
    assert rec.check_kind == "fairness-review"
    assert rec.verdict == "verified"
    assert rec.severity == 10
    assert rec.verification_digest == PIN
    assert rec.digest.startswith("sha256:")
    assert rec.verify() is True
    assert dataclasses.is_dataclass(rec)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "failed"  # type: ignore


# 4. verify bad-input table + seq-burn + rejected-row accounting + rewind-bare
def test_verify_bad_inputs_burn_seq():
    ledger = ev.AIEthicsVerification()
    n_rejected = 0
    cases = [
        ("", 1, "fairness-review", "verified", 0, ""),
        ("sys", 2, "not-a-kind", "verified", 0, ""),
        ("sys", 3, "fairness-review", "not-a-verdict", 0, ""),
        ("sys", 4, "fairness-review", "verified", -1, ""),
        ("sys", 5, "fairness-review", "verified", 101, ""),
        ("sys", 6, "fairness-review", "verified", True, ""),
        ("sys", 7, "fairness-review", "verified", 0, "bad-digest"),
        (123, 8, "fairness-review", "verified", 0, ""),
        (True, 9, "fairness-review", "verified", 0, ""),
    ]
    seq = 1
    for subject, _, kind, verdict, severity, digest in cases:
        with pytest.raises(ev.AIEthicsVerificationError):
            ledger.verify(subject, seq, check_kind=kind, verdict=verdict,
                          severity=severity, verification_digest=digest)
        n_rejected += 1
        seq += 1
    assert n_rejected == len(cases)
    rows = ledger.audit_log(100)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == n_rejected
    # Rewind raises bare SeqOrderError with no new audit row.
    with pytest.raises(ev.SeqOrderError):
        ledger.verify("sys", 1)
    rows2 = ledger.audit_log(100)
    assert len(rows2) == len(rows)


# 5. full 8 check-kind vocabulary
def test_full_check_kind_vocabulary():
    ledger = ev.AIEthicsVerification()
    seq = 1
    for i, kind in enumerate(ev.CHECK_KINDS):
        rec = ledger.verify(f"subj-{i}", seq, check_kind=kind, verdict="verified")
        assert rec.check_kind == kind
        assert rec.verification_id == f"ver-{i + 1}"
        seq += 1
    assert len(ev.CHECK_KINDS) == 8


# 6. full 5-verdict vocabulary + severity 0/100 bounds
def test_full_verdict_vocabulary_and_severity_bounds():
    ledger = ev.AIEthicsVerification()
    seq = 1
    for i, verdict in enumerate(ev.VERIFY_VERDICTS):
        rec = ledger.verify(f"v-{i}", seq, check_kind="bias-screen", verdict=verdict)
        assert rec.verdict == verdict
        seq += 1
    rec0 = ledger.verify("s0", seq, severity=0)
    assert rec0.severity == 0
    rec100 = ledger.verify("s100", seq + 1, severity=100)
    assert rec100.severity == 100
    with pytest.raises(ev.BadSeverityError):
        ledger.verify("bad", seq + 2, severity=101)
    with pytest.raises(ev.BadSeverityError):
        ledger.verify("bad", seq + 3, severity=True)


# 7. certify roundtrip + minted crt-N + chain + verify
def test_certify_roundtrip():
    ledger = ev.AIEthicsVerification()
    rec = ledger.verify("sys-1", 1, check_kind="harm-assessment", verdict="verified")
    crt = ledger.certify(
        rec.verification_id, 2, certification_kind="third-party-audit",
        outcome="endorsed", certification_digest=PIN2,
    )
    assert crt.certification_id == "crt-1"
    assert crt.verification_id == rec.verification_id
    assert crt.subject_id == "sys-1"
    assert crt.certification_kind == "third-party-audit"
    assert crt.outcome == "endorsed"
    assert crt.certification_digest == PIN2
    assert crt.verify() is True
    crt2 = ledger.certify(
        rec.verification_id, 3, certification_kind="peer-review", outcome="qualified",
    )
    assert crt2.certification_id == "crt-2"
    assert dataclasses.is_dataclass(crt2)


# 8. certify refusal table (unknown/bad-kind/bad-outcome/bad-digest/retired) + seq-burn
def test_certify_refusals_burn_seq():
    ledger = ev.AIEthicsVerification()
    rec = ledger.verify("sys-1", 1, verdict="verified")
    n_rejected = 0
    # unknown verification
    with pytest.raises(ev.UnknownVerificationError):
        ledger.certify("ver-999", 2)
    n_rejected += 1
    # bad certification kind
    with pytest.raises(ev.BadCertificationKindError):
        ledger.certify(rec.verification_id, 3, certification_kind="bogus")
    n_rejected += 1
    # bad outcome
    with pytest.raises(ev.BadOutcomeError):
        ledger.certify(rec.verification_id, 4, outcome="bogus")
    n_rejected += 1
    # bad digest
    with pytest.raises(ev.BadDigestError):
        ledger.certify(rec.verification_id, 5, certification_digest="xx")
    n_rejected += 1
    # retire then certify -> RetiredSubjectError
    ledger.retire("sys-1", 6)
    with pytest.raises(ev.RetiredSubjectError):
        ledger.certify(rec.verification_id, 7)
    n_rejected += 1
    rows = ledger.audit_log(100)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == n_rejected


# 9. verify_report semantics (verified/tamper-as-data/read purity/unknown refusal)
def test_verify_report_semantics():
    ledger = ev.AIEthicsVerification()
    rec = ledger.verify("sys-1", 1, check_kind="consent-verification",
                        verdict="verified")
    crt = ledger.certify(rec.verification_id, 2, outcome="endorsed")
    before = len(ledger.audit_log(100))
    rep = ledger.verify_report(rec.verification_id, 50)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    rep_c = ledger.verify_report(crt.certification_id, 51)
    assert rep_c.verdict == "verified"
    # read purity: no new audit rows, seq not consumed
    assert len(ledger.audit_log(100)) == before
    # tamper is reported as data, never raised
    object.__setattr__(rec, "verdict", "failed")
    tampered = ledger.verify_report(rec.verification_id, 52)
    assert tampered.verdict == "tampered"
    assert tampered.integrity_ok is False
    assert tampered.verify() is True
    # unknown record refuses
    with pytest.raises(ev.UnknownRecordError):
        ledger.verify_report("ver-999", 53)
    # bad read seq
    with pytest.raises(ev.SeqOrderError):
        ledger.verify_report(rec.verification_id, -1)


# 10. evaluate posture math (all reachable postures + precedence + tallies)
def test_evaluate_posture_math():
    # certified: all verified + every verification endorsed
    ledger = ev.AIEthicsVerification()
    r1 = ledger.verify("s-cert", 1, check_kind="fairness-review", verdict="verified")
    r2 = ledger.verify("s-cert", 2, check_kind="bias-screen", verdict="verified")
    ledger.certify(r1.verification_id, 3, outcome="endorsed")
    ledger.certify(r2.verification_id, 4, outcome="endorsed")
    rep = ledger.evaluate("s-cert", 5)
    assert rep.posture == "certified"
    assert rep.n_verifications == 2
    assert rep.n_verified == 2
    assert rep.n_certified == 2
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # verified: all verified, no certifications at all
    ledger2 = ev.AIEthicsVerification()
    ledger2.verify("s-ver", 1, verdict="verified")
    assert ledger2.evaluate("s-ver", 2).posture == "verified"
    # failed: any failed verdict
    ledger3 = ev.AIEthicsVerification()
    ledger3.verify("s-fail", 1, verdict="verified")
    ledger3.verify("s-fail", 2, verdict="failed")
    assert ledger3.evaluate("s-fail", 3).posture == "failed"
    # failed via withheld certification
    ledger4 = ev.AIEthicsVerification()
    rw = ledger4.verify("s-wheld", 1, verdict="verified")
    ledger4.certify(rw.verification_id, 2, outcome="withheld")
    assert ledger4.evaluate("s-wheld", 3).posture == "failed"
    # contested: any inconclusive
    ledger5 = ev.AIEthicsVerification()
    ledger5.verify("s-cont", 1, verdict="verified")
    ledger5.verify("s-cont", 2, verdict="inconclusive")
    rep5 = ledger5.evaluate("s-cont", 3)
    assert rep5.posture == "contested"
    assert rep5.n_inconclusive == 1
    # partially-verified: partial or not-verified
    ledger6 = ev.AIEthicsVerification()
    ledger6.verify("s-part", 1, verdict="verified")
    ledger6.verify("s-part", 2, verdict="partial")
    assert ledger6.evaluate("s-part", 3).posture == "partially-verified"
    ledger7 = ev.AIEthicsVerification()
    ledger7.verify("s-nv", 1, verdict="verified")
    ledger7.verify("s-nv", 2, verdict="not-verified")
    rep7 = ledger7.evaluate("s-nv", 3)
    assert rep7.posture == "partially-verified"
    assert rep7.n_not_verified == 1
    # precedence: failed outranks inconclusive
    ledger8 = ev.AIEthicsVerification()
    ledger8.verify("s-prec", 1, verdict="failed")
    ledger8.verify("s-prec", 2, verdict="inconclusive")
    assert ledger8.evaluate("s-prec", 3).posture == "failed"


# 11. evaluate read purity + unknown-system refusal + tamper flips integrity_ok
def test_evaluate_purity_and_unknown():
    ledger = ev.AIEthicsVerification()
    rec = ledger.verify("sys-1", 1, verdict="verified")
    before = len(ledger.audit_log(100))
    rep = ledger.evaluate("sys-1", 50)
    assert rep.integrity_ok is True
    rep2 = ledger.evaluate("sys-1", 50)
    assert rep2.posture == rep.posture
    assert len(ledger.audit_log(100)) == before
    with pytest.raises(ev.UnknownSubjectError):
        ledger.evaluate("nope", 51)
    object.__setattr__(rec, "severity", 999)
    rep3 = ledger.evaluate("sys-1", 52)
    assert rep3.integrity_ok is False
    assert rep3.posture == "verified"  # posture itself is still derived as data
    assert rep3.verify() is True


# 12. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    ledger = ev.AIEthicsVerification()
    ledger.verify("sys-1", 1, verdict="verified")
    with pytest.raises(ev.BadReasonError):
        ledger.retire("sys-1", 2, reason="bogus")
    ret = ledger.retire("sys-1", 3, reason="superseded")
    assert ret.subject_id == "sys-1"
    assert ret.reason == "superseded"
    assert ret.verify() is True
    with pytest.raises(ev.RetiredSubjectError):
        ledger.retire("sys-1", 4)
    # ids are never recycled: new verifications refused on the retired id
    with pytest.raises(ev.RetiredSubjectError):
        ledger.verify("sys-1", 5)
    # post-retire reads still work
    recs = ledger.verifications_for("sys-1", 100)
    assert len(recs) == 1
    rep = ledger.evaluate("sys-1", 101)
    assert rep.posture == "verified"
    assert "sys-1" in ledger.retired_ids(102)
    # unknown subject retire
    with pytest.raises(ev.UnknownSubjectError):
        ledger.retire("ghost", 6)


# 13. seq discipline (genesis seq-0 claim + bare rewinds + malformed seqs)
def test_seq_discipline():
    ledger = ev.AIEthicsVerification()
    # genesis claim with seq 0 raises bare SeqOrderError (seq must be > 0)
    with pytest.raises(ev.SeqOrderError):
        ledger.verify("sys-1", 0)
    assert len(ledger.audit_log(100)) == 0  # bare rewind: no rejected row
    rec = ledger.verify("sys-1", 1)
    assert rec.verification_id == "ver-1"
    # malformed seq shapes raise bare, consuming nothing
    for bad in (True, False, 1.5, "2", None):
        with pytest.raises(ev.SeqOrderError):
            ledger.verify("sys-2", bad)
    assert len(ledger.audit_log(100)) == 1  # only the one good row
    # genuine rewind after advancing: bare raise, no burn
    with pytest.raises(ev.SeqOrderError):
        ledger.verify("sys-3", 1)
    assert len(ledger.audit_log(100)) == 1
    # failed mutation consumes seq: next good mutation must be higher
    with pytest.raises(ev.BadCheckKindError):
        ledger.verify("sys-4", 2, check_kind="nope")
    assert len([r for r in ledger.audit_log(100) if r["kind"] == "rejected"]) == 1
    rec2 = ledger.verify("sys-4", 3)
    assert rec2.verification_id == "ver-2"


# 14. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = ev.AIEthicsVerification()
    rec = ledger.verify("sys-1", 1, check_kind="stakeholder-impact-review",
                        verdict="verified", severity=42)
    rows = ledger.audit_log(100)
    assert len(rows) == 1
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-ethics-verification"
    assert row["version"] == "ai-ethics-verification.v1"
    assert row["kind"] == "verified"
    assert row["seq"] == 1
    assert row["details"]["verification_id"] == rec.verification_id
    assert row["details"]["check_kind"] == "stakeholder-impact-review"
    assert row["details"]["verdict"] == "verified"
    assert row["details"]["severity"] == 42
    crt = ledger.certify(rec.verification_id, 2, outcome="endorsed")
    rows = ledger.audit_log(100)
    assert rows[1]["kind"] == "certified"
    assert rows[1]["details"]["certification_id"] == crt.certification_id
    # banned raw keys are rejected at the audit boundary
    for banned in ("stakeholder_feedback", "harm_narrative", "survey_data",
                   "deliberation_transcript", "pii", "prompt", "weights"):
        with pytest.raises(ev.AIEthicsVerificationError):
            ev.ai_ethics_verification_audit_event("verified", 99, **{banned: "x"})
    # unknown audit kind
    with pytest.raises(ev.AuditKindError):
        ev.ai_ethics_verification_audit_event("bogus", 99)
    # pinned vocab values remain emittable
    ok = ev.ai_ethics_verification_audit_event(
        "verified", 99, check_kind="bias-screen", verdict="verified")
    assert ok["details"]["check_kind"] == "bias-screen"


# 15. cross-instance determinism + views/stats + thread smoke + main() subprocess
def test_cross_instance_determinism_views_threads_main():
    a = ev.AIEthicsVerification()
    b = ev.AIEthicsVerification()
    ra = a.verify("s", 1, check_kind="transparency-review", verdict="verified",
                  severity=7, verification_digest=PIN)
    rb = b.verify("s", 1, check_kind="transparency-review", verdict="verified",
                  severity=7, verification_digest=PIN)
    assert ra.digest == rb.digest  # digest deterministic across instances
    ca = a.certify(ra.verification_id, 2, outcome="endorsed")
    cb = b.certify(rb.verification_id, 2, outcome="endorsed")
    assert ca.digest == cb.digest
    assert a.evaluate("s", 3).digest == b.evaluate("s", 3).digest
    # views
    assert a.subject_ids(100) == ("s",)
    assert a.verification_ids(100) == ("ver-1",)
    assert a.certification_ids(100) == ("crt-1",)
    assert a.verification_record("ver-1", 100).verification_id == "ver-1"
    assert a.certification_record("crt-1", 100).certification_id == "crt-1"
    assert len(a.verifications_for("s", 100)) == 1
    assert len(a.certifications_for("ver-1", 100)) == 1
    assert a.retired_ids(100) == ()
    stats = a.stats(100)
    assert stats["n_subjects"] == 1
    assert stats["n_verifications"] == 1
    assert stats["n_certifications"] == 1
    assert stats["n_retired"] == 0
    assert stats["n_audit_rows"] == 2
    # unknown lookups
    with pytest.raises(ev.UnknownVerificationError):
        a.verification_record("ver-999", 100)
    with pytest.raises(ev.UnknownCertificationError):
        a.certification_record("crt-999", 100)
    # thread smoke: 8 concurrent pure reads
    errs = []
    def _read():
        try:
            for _ in range(50):
                a.evaluate("s", 100)
                a.subject_ids(100)
                a.stats(100)
        except Exception as exc:  # noqa: BLE001
            errs.append(exc)
    threads = [threading.Thread(target=_read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs
    # main() subprocess self-check
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0
    assert "ai-ethics-verification OK: verify, certify, evaluate, retire, pins, audit" in proc.stdout
