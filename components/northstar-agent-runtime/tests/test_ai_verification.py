"""Tests for the ai_verification decision ledger (Simulated).

House contract: frozen records, caller int seqs strictly increasing
with claim-then-burn, no wall-clock, RLock-guarded, fail-closed
taxonomy, stdlib-only AST-verified, sha256: digest pins, audit.ndjson/1.
"""
from __future__ import annotations

import dataclasses
import itertools
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_verification
from ai_verification import (
    AI_VERIFICATION_VERSION,
    SCHEMA_PIN,
    CHECK_KINDS,
    VERIFY_VERDICTS,
    CERT_KINDS,
    CERT_OUTCOMES,
    POSTURES,
    RETIRE_REASONS,
    AIVerification,
    AIVerificationError,
    AuditKindError,
    BadCertKindError,
    BadCertOutcomeError,
    BadCheckKindError,
    BadDigestError,
    BadReasonError,
    BadSeverityError,
    BadSubjectError,
    BadVerdictError,
    RetiredSubjectError,
    SeqOrderError,
    UnknownRecordError,
    UnknownSubjectError,
    UnknownVerificationError,
    ai_verification_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_VERIFICATION_VERSION == "ai-verification.v1"
    assert SCHEMA_PIN == "northstar.ai-verification.v1"
    assert CHECK_KINDS == (
        "formal-proof",
        "model-checking",
        "unit-test-suite",
        "property-test",
        "red-team-exercise",
        "static-analysis",
        "fuzzing-campaign",
        "human-audit",
    )
    assert VERIFY_VERDICTS == (
        "verified",
        "failed",
        "inconclusive",
        "not-applicable",
        "not-verified",
    )
    assert CERT_KINDS == (
        "peer-review",
        "independent-audit",
        "accreditation",
        "self-attestation",
        "third-party-lab",
        "red-team-review",
        "formal-certification",
        "continuous-monitoring",
    )
    assert CERT_OUTCOMES == ("endorsed", "qualified", "withheld", "inconclusive")
    assert POSTURES == (
        "unverified",
        "failed",
        "contested",
        "partially-verified",
        "verified",
        "certified",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "withdrawn", "false-start")


def test_stdlib_only():
    """The module imports stdlib names only (AST self-check)."""
    assert stdlib_only()
    assert ai_verification.stdlib_only()


def test_verify_books_record_with_pin():
    """verify() books a verification run, mints ver-N, digest pin verifies."""
    ledger = AIVerification()
    rec = ledger.verify(
        "subject-1",
        1,
        check_kind="formal-proof",
        verdict="verified",
        severity=10,
        artifact_digest=GOOD_DIGEST,
        verification_digest=GOOD_DIGEST,
    )
    assert rec.verification_id == "ver-1"
    assert rec.subject_id == "subject-1"
    assert rec.check_kind == "formal-proof"
    assert rec.verdict == "verified"
    assert rec.severity == 10
    assert rec.artifact_digest == GOOD_DIGEST
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    rec2 = ledger.verify("subject-1", 2)
    assert rec2.verification_id == "ver-2"
    assert rec2.check_kind == "formal-proof"
    assert rec2.verdict == "not-verified"
    assert rec2.severity == 0


def test_verify_bad_inputs():
    """Bad shapes burn seq and book rejected rows; rewinds raise bare."""
    ledger = AIVerification()
    with pytest.raises(BadSubjectError):
        ledger.verify("", 1)
    with pytest.raises(BadCheckKindError):
        ledger.verify("subject-1", 2, check_kind="vibes")
    with pytest.raises(BadVerdictError):
        ledger.verify("subject-1", 3, verdict="probably")
    with pytest.raises(BadSeverityError):
        ledger.verify("subject-1", 4, severity=True)
    with pytest.raises(BadSeverityError):
        ledger.verify("subject-1", 5, severity=101)
    with pytest.raises(BadDigestError):
        ledger.verify("subject-1", 6, artifact_digest="not-a-pin")
    rows = ledger.audit_log(7)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 6
    rec = ledger.verify("subject-1", 8)
    assert rec.verification_id == "ver-1"
    with pytest.raises(SeqOrderError):
        ledger.verify("subject-1", 8)
    assert ledger.stats(9)["seq"] == 8
    assert sum(1 for r in ledger.audit_log(9) if r["kind"] == "rejected") == 6


def test_verify_full_check_vocabulary():
    """All 8 check kinds book successfully."""
    ledger = AIVerification()
    for i, kind in enumerate(CHECK_KINDS, start=1):
        rec = ledger.verify("subject-1", i, check_kind=kind)
        assert rec.check_kind == kind
        assert rec.verify()
    assert ledger.stats(9)["n_verifications"] == 8


def test_verify_full_verdict_vocabulary():
    """All 5 verdicts book successfully; severity bounds 0/100 accepted."""
    ledger = AIVerification()
    for i, verdict in enumerate(VERIFY_VERDICTS, start=1):
        rec = ledger.verify(
            "subject-1", i, verdict=verdict, severity=100 if i == 1 else 0
        )
        assert rec.verdict == verdict
        assert rec.verify()
    rec = ledger.verify("subject-2", 6, severity=0)
    assert rec.severity == 0


def test_certify_roundtrip():
    """certify() books a certification of a verification record, mints crt-N."""
    ledger = AIVerification()
    ver = ledger.verify("subject-1", 1, verdict="verified")
    crt = ledger.certify(
        ver.verification_id,
        2,
        certification_kind="peer-review",
        outcome="endorsed",
        certification_digest=GOOD_DIGEST,
    )
    assert crt.certification_id == "crt-1"
    assert crt.verification_id == ver.verification_id
    assert crt.subject_id == "subject-1"
    assert crt.certification_kind == "peer-review"
    assert crt.outcome == "endorsed"
    assert crt.digest.startswith("sha256:")
    assert crt.verify()
    crt2 = ledger.certify(ver.verification_id, 3, certification_kind="independent-audit")
    assert crt2.certification_id == "crt-2"


def test_certify_refusal_table():
    """certify() fails closed on unknown verifications and retired subjects."""
    ledger = AIVerification()
    with pytest.raises(UnknownVerificationError):
        ledger.certify("ver-999", 1)
    with pytest.raises(BadCertKindError):
        ver = ledger.verify("subject-1", 2, verdict="verified")
        ledger.certify(ver.verification_id, 3, certification_kind="vibes")
    with pytest.raises(BadCertOutcomeError):
        ledger.certify(ver.verification_id, 4, outcome="maybe")
    with pytest.raises(BadDigestError):
        ledger.certify(ver.verification_id, 5, certification_digest="zzz")
    ledger.retire("subject-1", 6)
    with pytest.raises(RetiredSubjectError):
        ledger.certify(ver.verification_id, 7)
    rows = ledger.audit_log(8)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 5


def test_certify_full_kind_vocabulary():
    """All 8 certification kinds book successfully."""
    ledger = AIVerification()
    ver = ledger.verify("subject-1", 1, verdict="verified")
    for i, kind in enumerate(CERT_KINDS, start=2):
        crt = ledger.certify(ver.verification_id, i, certification_kind=kind)
        assert crt.certification_kind == kind
        assert crt.verify()
    assert ledger.stats(10)["n_certifications"] == 8


def test_verify_report_semantics():
    """verify_report() pure-reads a digest pin; tampering flips as data."""
    ledger = AIVerification()
    ver = ledger.verify("subject-1", 1)
    crt = ledger.certify(ver.verification_id, 2)
    rep = ledger.verify_report(ver.verification_id, 3)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    rep2 = ledger.verify_report(crt.certification_id, 4)
    assert rep2.verdict == "verified"
    tampered = crt.__class__(**{**crt.__dict__, "digest": "sha256:" + "00" * 32})
    assert tampered.verify() is False
    with pytest.raises(UnknownRecordError):
        ledger.verify_report("ver-999", 5)
    with pytest.raises(UnknownRecordError):
        ledger.verify_report("", 6)
    before = ledger.stats(7)["seq"]
    ledger.verify_report(ver.verification_id, 100)
    assert ledger.stats(101)["seq"] == before
    assert all(r["kind"] != "rejected" for r in ledger.audit_log(101))


def test_evaluate_posture_math():
    """evaluate() derives failed -> contested -> partially-verified -> verified -> certified."""
    ledger = AIVerification()
    ver_f = ledger.verify("failed-t", 1, verdict="failed")
    assert ledger.evaluate("failed-t", 2).posture == "failed"
    ver_c = ledger.verify("contested-t", 3, verdict="inconclusive")
    assert ledger.evaluate("contested-t", 4).posture == "contested"
    ledger.verify("partial-t", 5, verdict="verified")
    ledger.verify("partial-t", 6, verdict="not-verified")
    rep = ledger.evaluate("partial-t", 7)
    assert rep.posture == "partially-verified"
    assert rep.n_verifications == 2
    assert rep.n_certifications == 0
    ledger.verify("verified-t", 8, verdict="verified")
    rep2 = ledger.evaluate("verified-t", 9)
    assert rep2.posture == "verified"
    assert rep2.integrity_ok is True
    assert rep2.verify()
    ver_x = ledger.verify("certified-t", 10, verdict="verified")
    ledger.certify(ver_x.verification_id, 11, outcome="endorsed")
    rep3 = ledger.evaluate("certified-t", 12)
    assert rep3.posture == "certified"
    assert rep3.n_endorsed == 1
    ver_q = ledger.verify("qualified-t", 13, verdict="verified")
    ledger.certify(ver_q.verification_id, 14, outcome="qualified")
    assert ledger.evaluate("qualified-t", 15).posture == "verified"
    ver_w = ledger.verify("withheld-t", 16, verdict="verified")
    ledger.certify(ver_w.verification_id, 17, outcome="withheld")
    assert ledger.evaluate("withheld-t", 18).posture == "failed"
    ledger.verify("prec-t", 19, verdict="failed")
    ledger.verify("prec-t", 20, verdict="inconclusive")
    assert ledger.evaluate("prec-t", 21).posture == "failed"
    ledger.verify("tamper-t", 22)
    vid = ledger.verification_record("ver-1", 23).verification_id
    ledger._verifications[vid] = ledger._verifications[vid].__class__(
        **{**ledger._verifications[vid].__dict__, "digest": "sha256:" + "00" * 32}
    )
    assert ledger.evaluate("failed-t", 24).integrity_ok is False


def test_evaluate_read_purity():
    """evaluate() refuses unknown subjects and never consumes seq."""
    ledger = AIVerification()
    with pytest.raises(UnknownSubjectError):
        ledger.evaluate("ghost", 1)
    ledger.verify("subject-1", 2)
    before = ledger.stats(3)
    ev = ledger.evaluate("subject-1", 99)
    assert ev.posture == "partially-verified"
    assert ledger.stats(100)["seq"] == before["seq"]
    kinds = [r["kind"] for r in ledger.audit_log(101)]
    assert kinds == ["verified"]
    with pytest.raises(SeqOrderError):
        ledger.evaluate("subject-1", True)


def test_retire_terminality():
    """retire() terminates a subject id; post-retire mutations refused, reads work."""
    ledger = AIVerification()
    with pytest.raises(UnknownSubjectError):
        ledger.retire("ghost", 1)
    ver = ledger.verify("subject-1", 2)
    with pytest.raises(BadReasonError):
        ledger.retire("subject-1", 3, reason="expired")
    ret = ledger.retire("subject-1", 4, reason="withdrawn")
    assert ret.verify()
    assert ledger.retired_ids(5) == ("subject-1",)
    with pytest.raises(RetiredSubjectError):
        ledger.retire("subject-1", 6)
    with pytest.raises(RetiredSubjectError):
        ledger.verify("subject-1", 7)
    with pytest.raises(RetiredSubjectError):
        ledger.certify(ver.verification_id, 8)
    assert ledger.verification_record(ver.verification_id, 9).subject_id == "subject-1"
    ev = ledger.evaluate("subject-1", 10)
    assert ev.posture == "partially-verified"
    rows = ledger.audit_log(11)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 5


def test_seq_discipline():
    """Genesis rewind raises bare with zero rows; failed mutations consume seq."""
    ledger = AIVerification()
    with pytest.raises(SeqOrderError):
        ledger.verify("subject-1", 0)
    with pytest.raises(SeqOrderError):
        ledger.verify("subject-1", True)
    with pytest.raises(SeqOrderError):
        ledger.verify("subject-1", "1")
    assert ledger.audit_log(1) == ()
    with pytest.raises(BadCheckKindError):
        ledger.verify("subject-1", 1, check_kind="nope")
    assert ledger.stats(2)["seq"] == 1
    ledger.verify("subject-1", 2)
    with pytest.raises(SeqOrderError):
        ledger.verify("subject-1", 1)
    assert ledger.stats(3)["seq"] == 2


def test_audit_shapes_leak_ban_threads_and_main():
    """Audit rows are schema-pinned; raw keys banned; main() green; thread smoke."""
    row = ai_verification_audit_event(
        "verified", 1, verification_id="ver-1", check_kind="formal-proof"
    )
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-verification"
    assert row["version"] == AI_VERIFICATION_VERSION
    assert row["kind"] == "verified"
    with pytest.raises(AIVerificationError):
        ai_verification_audit_event("verified", 2, proof_script="Qed.")
    with pytest.raises(AIVerificationError):
        ai_verification_audit_event("certified", 2, workpaper="notes")
    row2 = ai_verification_audit_event(
        "certified", 3, outcome="endorsed", severity=10
    )
    assert row2["details"]["outcome"] == "endorsed"
    with pytest.raises(AuditKindError):
        ai_verification_audit_event("watched", 2)
    with pytest.raises(SeqOrderError):
        ai_verification_audit_event("verified", True)
    ledger = AIVerification()
    ledger.verify("subject-1", 1)
    ledger.certify("ver-1", 2)
    rows = ledger.audit_log(3)
    assert [r["kind"] for r in rows] == ["verified", "certified"]
    assert all(r["schema"] == "audit.ndjson/1" for r in rows)
    rec = ledger.verification_record("ver-1", 4)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.severity = 99  # type: ignore[misc]
    counter = itertools.count(5)
    errors = []

    def worker():
        try:
            for _ in range(10):
                ledger.verify("subject-w", next(counter))
        except SeqOrderError:
            pass
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert ledger.stats(1000)["n_verifications"] <= 41
    out = subprocess.run(
        [sys.executable, str(Path(ai_verification.__file__))],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    assert "ai-verification OK" in out.stdout
