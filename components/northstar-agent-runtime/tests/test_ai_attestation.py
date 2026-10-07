"""Targeted tests for ai_attestation.py (15 tests)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_attestation
from ai_attestation import (
    AI_ATTESTATION_SCHEMA,
    AI_ATTESTATION_VERSION,
    ATTESTATION_KINDS,
    KIND_ATTESTED,
    KIND_CAPABILITY_CLAIM,
    KIND_COMPLIANCE_CLAIM,
    KIND_FAIRNESS_CLAIM,
    KIND_PRIVACY_CLAIM,
    KIND_PROVENANCE_CLAIM,
    KIND_REJECTED,
    KIND_RETIRED,
    KIND_ROBUSTNESS_CLAIM,
    KIND_SAFETY_CLAIM,
    KIND_SECURITY_CLAIM,
    POSTURE_ATTESTED,
    POSTURE_CONTESTED,
    POSTURE_FAILED,
    POSTURE_PARTIALLY_ATTESTED,
    POSTURE_UNASSESSED,
    POSTURES,
    REASON_ATTESTATION_LOSS,
    REASON_MANUAL,
    REASONS,
    VERDICT_ATTESTED,
    VERDICT_FAILED,
    VERDICT_INCONCLUSIVE,
    VERDICT_PARTIAL,
    VERDICTS,
    AIAttestation,
    AuditKindError,
    BadAttestationKindError,
    BadDigestError,
    BadIdError,
    BadReasonError,
    BadVerdictError,
    DoubleRetireError,
    RetiredSystemError,
    SeqOrderError,
    UnknownAttestationError,
    UnknownSystemError,
    ai_attestation_audit_event,
)

_HERE = Path(__file__).resolve().parent.parent
_GOOD_DIGEST = "sha256:" + "0" * 64


def _fresh() -> AIAttestation:
    return AIAttestation()


def _attest(aa: AIAttestation, seq: int, system_id: str = "sys-1") -> object:
    return aa.attest(system_id, KIND_SAFETY_CLAIM, VERDICT_ATTESTED, seq,
                     _GOOD_DIGEST)


# 1. pins and pinned vocabularies.
def test_pins_and_vocabularies():
    assert AI_ATTESTATION_VERSION == "ai-attestation.v1"
    assert AI_ATTESTATION_SCHEMA == "northstar.ai-attestation.v1"
    assert len(ATTESTATION_KINDS) == 8 and len(set(ATTESTATION_KINDS)) == 8
    assert len(VERDICTS) == 4 and len(set(VERDICTS)) == 4
    assert len(POSTURES) == 5
    assert len(REASONS) == 4
    assert KIND_CAPABILITY_CLAIM in ATTESTATION_KINDS
    assert VERDICT_FAILED in VERDICTS
    assert POSTURE_UNASSESSED in POSTURES
    assert REASON_ATTESTATION_LOSS in REASONS


# 2. stdlib-only AST check.
def test_stdlib_only_ast():
    src = (Path(ai_attestation.__file__)).read_text()
    tree = ast.parse(src)
    allowed_top = {"canonical_json"}
    stdlib_like = {"hashlib", "re", "threading", "dataclasses", "typing",
                   "__future__", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top in stdlib_like, f"non-stdlib import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            assert top in stdlib_like or top in allowed_top, (
                f"non-stdlib import: {node.module}")
    assert ai_attestation.stdlib_only()


# 3. attest roundtrip + verify() + frozen-ness + minted att-N ids.
def test_attest_roundtrip_and_minting():
    aa = _fresh()
    r1 = _attest(aa, seq=1)
    r2 = aa.attest("sys-1", KIND_SECURITY_CLAIM, VERDICT_ATTESTED, 2,
                   _GOOD_DIGEST)
    assert r1.attestation_id == "att-1"
    assert r2.attestation_id == "att-2"
    assert r1.verify("att-1", "sys-1", KIND_SAFETY_CLAIM, VERDICT_ATTESTED,
                    _GOOD_DIGEST)
    assert not r1.verify("att-1", "sys-1", KIND_SAFETY_CLAIM, VERDICT_FAILED,
                         _GOOD_DIGEST)
    import dataclasses
    with pytest.raises(dataclasses.FrozenInstanceError):
        r1.verdict = "attested"  # type: ignore[misc]
    # empty digest is allowed.
    r3 = aa.attest("sys-2", KIND_FAIRNESS_CLAIM, VERDICT_PARTIAL, 3)
    assert r3.attestation_id == "att-3"
    assert r3.verify("att-3", "sys-2", KIND_FAIRNESS_CLAIM, VERDICT_PARTIAL,
                     "")
    assert aa.attestations_for("sys-1", 4) == ("att-1", "att-2")
    assert aa.system_ids(5) == ("sys-1", "sys-2")


# 4. bad-input table: each burns its seq, books one rejected row, rewinds raise bare.
def test_attest_bad_input_table_seq_burn_and_rejected_rows():
    aa = _fresh()
    bad_calls = [
        lambda s: aa.attest("", KIND_SAFETY_CLAIM, VERDICT_ATTESTED, s),
        lambda s: aa.attest("has space", KIND_SAFETY_CLAIM, VERDICT_ATTESTED, s),
        lambda s: aa.attest("x" * 257, KIND_SAFETY_CLAIM, VERDICT_ATTESTED, s),
        lambda s: aa.attest("sys-1", "nope-kind", VERDICT_ATTESTED, s),
        lambda s: aa.attest("sys-1", True, VERDICT_ATTESTED, s),
        lambda s: aa.attest("sys-1", KIND_SAFETY_CLAIM, "nope-verdict", s),
        lambda s: aa.attest("sys-1", KIND_SAFETY_CLAIM, True, s),
        lambda s: aa.attest("sys-1", KIND_SAFETY_CLAIM, VERDICT_ATTESTED, s,
                            "sha256:not-hex"),
        lambda s: aa.attest("sys-1", KIND_SAFETY_CLAIM, VERDICT_ATTESTED, s,
                            "sha256:" + "0" * 63),
    ]
    seq = 1
    for call in bad_calls:
        with pytest.raises(Exception):
            call(seq)
        seq += 1
    # seq rewound: raises bare SeqOrderError, consumes nothing.
    with pytest.raises(SeqOrderError):
        aa.attest("sys-1", KIND_SAFETY_CLAIM, VERDICT_ATTESTED, 1)
    rows = aa.audit_log()
    assert len(rows) == len(bad_calls)
    assert all(r["kind"] == KIND_REJECTED for r in rows)
    assert all(r["schema"] == "audit.ndjson/1" for r in rows)
    assert aa.stats()["attestations"] == 0


# 5. full attestation-kind vocabulary accepted.
def test_full_attestation_kind_vocabulary():
    aa = _fresh()
    for i, kind in enumerate(ATTESTATION_KINDS):
        rec = aa.attest(f"sys-{i}", kind, VERDICT_ATTESTED, i + 1)
        assert rec.attestation_kind == kind
    assert aa.stats()["attestations"] == 8


# 6. full verdict vocabulary accepted; digest shape enforced.
def test_full_verdict_vocabulary_and_digest_shape():
    aa = _fresh()
    for i, verdict in enumerate(VERDICTS):
        rec = aa.attest(f"sys-{i}", KIND_CAPABILITY_CLAIM, verdict, i + 1,
                        _GOOD_DIGEST)
        assert rec.verdict == verdict
    # verify() pin self-checks deterministically.
    vr = aa.verify("att-1", 100)
    assert vr.verdict == "verified"
    assert vr.verify("att-1", "verified")


# 7. verify semantics: tamper-as-data, read purity, unknown refusal.
def test_verify_semantics_tamper_as_data_and_read_purity():
    aa = _fresh()
    r1 = _attest(aa, seq=1)
    before = aa.stats()["audit_rows"]
    vr1 = aa.verify("att-1", 2)
    vr2 = aa.verify("att-1", 3)
    assert vr1.verdict == "verified" and vr2.verdict == "verified"
    assert vr1.digest != vr2.digest  # seq differs -> different pin
    # reads write no rows and consume no seq.
    assert aa.stats()["audit_rows"] == before
    with pytest.raises(Exception):
        aa.attest("sys-1", KIND_SAFETY_CLAIM, VERDICT_ATTESTED, 1)
    # tamper: frozen record mutated via object.__setattr__ -> reported as data.
    object.__setattr__(r1, "verdict", VERDICT_FAILED)
    vr3 = aa.verify("att-1", 10)
    assert vr3.verdict == "tampered"
    with pytest.raises(UnknownAttestationError):
        aa.verify("att-999", 11)


# 8. evaluate posture math: all 5 postures + precedence + tallies.
def test_evaluate_posture_math_and_precedence():
    aa = _fresh()
    aa.attest("sys-1", KIND_SAFETY_CLAIM, VERDICT_ATTESTED, 1, _GOOD_DIGEST)
    assert aa.evaluate("sys-1", 2).posture == POSTURE_ATTESTED
    aa.attest("sys-1", KIND_SECURITY_CLAIM, VERDICT_PARTIAL, 3, _GOOD_DIGEST)
    assert aa.evaluate("sys-1", 4).posture == POSTURE_PARTIALLY_ATTESTED
    aa.attest("sys-1", KIND_PRIVACY_CLAIM, VERDICT_INCONCLUSIVE, 5,
              _GOOD_DIGEST)
    assert aa.evaluate("sys-1", 6).posture == POSTURE_CONTESTED
    aa.attest("sys-1", KIND_FAIRNESS_CLAIM, VERDICT_FAILED, 7, _GOOD_DIGEST)
    ev = aa.evaluate("sys-1", 8)
    assert ev.posture == POSTURE_FAILED  # failed outranks all
    assert ev.n_attestations == 4
    assert ev.n_attested == 1 and ev.n_partial == 1
    assert ev.n_inconclusive == 1 and ev.n_failed == 1
    assert ev.integrity_ok
    assert ev.verify("sys-1", POSTURE_FAILED)
    # tamper flips integrity_ok as data, posture math unchanged.
    r1 = aa.attestation_record("att-1", 9)
    object.__setattr__(r1, "verdict", VERDICT_FAILED)
    ev2 = aa.evaluate("sys-1", 10)
    assert ev2.integrity_ok is False


# 9. evaluate read purity + unknown-system refusal.
def test_evaluate_read_purity_and_unknown_system_refusal():
    aa = _fresh()
    with pytest.raises(UnknownSystemError):
        aa.evaluate("nope", 1)
    r = _attest(aa, seq=2)
    before = aa.stats()["audit_rows"]
    ev1 = aa.evaluate("sys-1", 3)
    ev2 = aa.evaluate("sys-1", 3)  # same seq twice: pure read
    assert ev1 == ev2
    assert aa.stats()["audit_rows"] == before
    assert r.verify("att-1", "sys-1", KIND_SAFETY_CLAIM, VERDICT_ATTESTED,
                    _GOOD_DIGEST)


# 10. retire terminality: bad reason, double-retire, id non-recycling, post-retire reads.
def test_retire_terminality():
    aa = _fresh()
    _attest(aa, seq=1)
    with pytest.raises(BadReasonError):
        aa.retire("sys-1", 2, "nope")
    rr = aa.retire("sys-1", 3)
    assert rr.verify("sys-1", REASON_MANUAL)
    with pytest.raises(DoubleRetireError):
        aa.retire("sys-1", 4)
    # post-retire mutations fail closed.
    with pytest.raises(RetiredSystemError):
        aa.attest("sys-1", KIND_SAFETY_CLAIM, VERDICT_ATTESTED, 5)
    # ids never recycled: retire again impossible, att-1 still exists.
    with pytest.raises(UnknownAttestationError):
        aa.verify("att-2", 6)
    # post-retire reads still work.
    assert aa.retired_ids(7) == ("sys-1",)
    assert aa.evaluate("sys-1", 8).posture == POSTURE_ATTESTED
    assert aa.verify("att-1", 9).verdict == "verified"
    assert aa.stats()["retired"] == 1
    kinds = [row["kind"] for row in aa.audit_log()]
    assert kinds.count(KIND_RETIRED) == 1


# 11. seq discipline: genesis rewind bare, malformed seqs, failed-mutation-consumes-seq.
def test_seq_discipline():
    aa = _fresh()
    r = _attest(aa, seq=0)  # genesis: seq=0 is the first valid claim (> -1)
    with pytest.raises(SeqOrderError):
        aa.attest("sys-1", KIND_SAFETY_CLAIM, VERDICT_ATTESTED, 0)
    assert aa.stats()["audit_rows"] == 1  # bare rewind: no row consumed
    for bad in (True, -1, "1", 1.0, None):
        with pytest.raises(SeqOrderError):
            aa.attest("sys-1", KIND_SAFETY_CLAIM, VERDICT_ATTESTED, bad)
    with pytest.raises(SeqOrderError):
        aa.verify("att-1", True)
    with pytest.raises(SeqOrderError):
        aa.evaluate("sys-1", -2)
    with pytest.raises(SeqOrderError):
        aa.retire("sys-1", 1.5)
    # gap seqs are allowed.
    r2 = aa.attest("sys-1", KIND_SECURITY_CLAIM, VERDICT_ATTESTED, 50)
    assert r2.attestation_id == "att-2"
    assert r.attestation_id == "att-1"


# 12. audit shapes + leak ban + bad-kind.
def test_audit_shapes_and_leak_ban():
    aa = _fresh()
    _attest(aa, seq=1)
    aa.retire("sys-1", 2)
    with pytest.raises(Exception):
        aa.attest("sys-1", KIND_SAFETY_CLAIM, VERDICT_ATTESTED, 3)
    rows = aa.audit_log()
    assert [r["kind"] for r in rows] == [
        KIND_ATTESTED, KIND_RETIRED, KIND_REJECTED]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == AI_ATTESTATION_VERSION
        assert set(r["detail"]) <= {
            "system_id", "attestation_id", "attestation_kind", "verdict",
            "attestation_digest", "reason"}
    with pytest.raises(AuditKindError):
        ai_attestation_audit_event("nope", {}, 1)
    with pytest.raises(AuditKindError):
        ai_attestation_audit_event(
            KIND_ATTESTED, {"claim_text": "raw!"}, 1)
    ev = ai_attestation_audit_event(KIND_ATTESTED, {"system_id": "s"}, 1)
    assert ev["seq"] == 1


# 13. views/stats + unknown lookups.
def test_views_stats_and_unknown_lookups():
    aa = _fresh()
    assert aa.stats() == {"systems": 0, "attestations": 0, "retired": 0,
                          "audit_rows": 0}
    _attest(aa, seq=1)
    assert aa.stats()["attestations"] == 1
    rec = aa.attestation_record("att-1", 2)
    assert rec.system_id == "sys-1" and rec.attestation_kind == KIND_SAFETY_CLAIM
    with pytest.raises(UnknownAttestationError):
        aa.attestation_record("att-404", 3)
    with pytest.raises(UnknownSystemError):
        aa.attestations_for("nope", 4)
    assert aa.retired_ids(5) == ()


# 14. cross-instance digest determinism + 8-thread read smoke + frozen-ness.
def test_cross_instance_determinism_and_thread_read_smoke():
    aa1, aa2 = _fresh(), _fresh()
    for aa in (aa1, aa2):
        aa.attest("sys-1", KIND_ROBUSTNESS_CLAIM, VERDICT_ATTESTED, 1,
                  _GOOD_DIGEST)
        aa.attest("sys-1", KIND_PROVENANCE_CLAIM, VERDICT_PARTIAL, 2,
                  _GOOD_DIGEST)
    assert aa1.attestation_record("att-1", 3).digest == (
        aa2.attestation_record("att-1", 3).digest)
    errs = []

    def reader():
        try:
            for i in range(50):
                assert aa1.verify("att-1", 100 + i).verdict == "verified"
                assert aa1.evaluate("sys-1", 200 + i).posture == (
                    POSTURE_PARTIALLY_ATTESTED)
        except Exception as exc:  # pragma: no cover
            errs.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs
    import dataclasses
    rec = aa1.attestation_record("att-1", 300)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "attested"  # type: ignore[misc]


# 15. main() subprocess self-check.
def test_main_subprocess_self_check():
    proc = subprocess.run(
        [sys.executable, str(_HERE / "ai_attestation.py")],
        capture_output=True, text=True, cwd=_HERE)
    assert proc.returncode == 0, proc.stderr
    assert "ai-attestation OK: attest, verify, evaluate, retire, pins, audit" in (
        proc.stdout)
