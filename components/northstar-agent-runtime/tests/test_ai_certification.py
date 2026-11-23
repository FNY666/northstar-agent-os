"""Targeted tests for ai_certification.py (15 tests)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_certification
from ai_certification import (
    AI_CERTIFICATION_SCHEMA,
    AI_CERTIFICATION_VERSION,
    CERT_KINDS,
    KIND_EU_AI_ACT,
    KIND_ISO_42001,
    KIND_ISO_23894,
    KIND_INDEPENDENT_AUDIT,
    KIND_NIST_AI_RMF,
    KIND_OECD_AI,
    KIND_SELF_DECLARATION,
    KIND_SOC2_AI,
    KIND_CERTIFIED,
    KIND_REJECTED,
    KIND_RETIRED,
    OUTCOMES,
    OUTCOME_CERTIFIED,
    OUTCOME_CONDITIONAL,
    OUTCOME_REVOKED,
    OUTCOME_SUSPENDED,
    POSTURE_CERTIFIED,
    POSTURE_CONDITIONAL,
    POSTURE_REVOKED,
    POSTURE_SUSPENDED,
    POSTURE_UNCERTIFIED,
    REASON_CERT_LOSS,
    REASON_MANUAL,
    REASONS,
    AICertification,
    AuditKindError,
    BadCertKindError,
    BadDigestError,
    BadIdError,
    BadOutcomeError,
    BadReasonError,
    DoubleRetireError,
    RetiredSystemError,
    SeqOrderError,
    UnknownCertificationError,
    UnknownSystemError,
    ai_certification_audit_event,
)

_HERE = Path(__file__).resolve().parent.parent
_GOOD_DIGEST = "sha256:" + "0" * 64


def _fresh() -> AICertification:
    return AICertification()


def _certify(ac: AICertification, sys_id: str = "sys-1",
             kind: str = KIND_ISO_42001,
             outcome: str = OUTCOME_CERTIFIED, seq: int = 1) -> object:
    return ac.certify(sys_id, kind, outcome, seq, _GOOD_DIGEST)


# 1. Pins: version, schema, stdlib_only, vocabulary sizes.
def test_pins_and_vocabularies():
    assert AI_CERTIFICATION_VERSION == "ai-certification.v1"
    assert AI_CERTIFICATION_SCHEMA == "northstar.ai-certification.v1"
    assert ai_certification.stdlib_only() is True
    assert len(CERT_KINDS) == 8
    assert len(set(CERT_KINDS)) == 8
    assert KIND_ISO_42001 in CERT_KINDS
    assert KIND_INDEPENDENT_AUDIT in CERT_KINDS
    assert len(OUTCOMES) == 4
    assert set(OUTCOMES) == {OUTCOME_CERTIFIED, OUTCOME_CONDITIONAL,
                             OUTCOME_SUSPENDED, OUTCOME_REVOKED}
    assert set(REASONS) == {REASON_MANUAL, REASON_CERT_LOSS,
                            "decommissioned", "scope-change"}


# 2. stdlib-only AST self-check: no non-stdlib imports in module source.
def test_stdlib_only_ast():
    src = (Path(ai_certification.__file__)).read_text()
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


# 3. certify roundtrip + verify() + frozen-ness + minted crt-N ids.
def test_certify_roundtrip_and_minting():
    ac = _fresh()
    r1 = _certify(ac, seq=1)
    r2 = ac.certify("sys-1", KIND_EU_AI_ACT, OUTCOME_CERTIFIED, 2, _GOOD_DIGEST)
    assert r1.certification_id == "crt-1"
    assert r2.certification_id == "crt-2"
    assert r1.verify("crt-1", "sys-1", KIND_ISO_42001, OUTCOME_CERTIFIED,
                    _GOOD_DIGEST)
    assert not r1.verify("crt-1", "sys-1", KIND_ISO_42001, OUTCOME_SUSPENDED,
                         _GOOD_DIGEST)
    assert not r1.verify("crt-1", "sys-1", KIND_NIST_AI_RMF, OUTCOME_CERTIFIED,
                         _GOOD_DIGEST)
    with pytest.raises(AttributeError):
        r1.outcome = OUTCOME_REVOKED  # frozen dataclass


# 4. certify bad-input table + seq-burn + rejected-row accounting.
def test_certify_bad_inputs_burn_seq():
    ac = _fresh()
    bads = [
        ("", KIND_ISO_42001, OUTCOME_CERTIFIED, _GOOD_DIGEST, BadIdError),
        ("sys 1", KIND_ISO_42001, OUTCOME_CERTIFIED, _GOOD_DIGEST, BadIdError),
        ("x" * 257, KIND_ISO_42001, OUTCOME_CERTIFIED, _GOOD_DIGEST,
         BadIdError),
        (None, KIND_ISO_42001, OUTCOME_CERTIFIED, _GOOD_DIGEST, BadIdError),
        ("sys-1", "not-a-kind", OUTCOME_CERTIFIED, _GOOD_DIGEST,
         BadCertKindError),
        ("sys-1", KIND_ISO_42001, "not-an-outcome", _GOOD_DIGEST,
         BadOutcomeError),
        ("sys-1", KIND_ISO_42001, OUTCOME_CERTIFIED, "sha256:zzz",
         BadDigestError),
        ("sys-1", KIND_ISO_42001, OUTCOME_CERTIFIED, _GOOD_DIGEST[:-1],
         BadDigestError),
    ]
    seq = 1
    for sys_id, kind, outcome, digest, exc in bads:
        with pytest.raises(exc):
            ac.certify(sys_id, kind, outcome, seq, digest)
        seq += 1
    with pytest.raises(SeqOrderError):  # rewind is bare: no burn, no row
        ac.certify("sys-1", KIND_ISO_42001, OUTCOME_CERTIFIED, 1,
                   _GOOD_DIGEST)
    rows = [r for r in ac.audit_log() if r["kind"] == KIND_REJECTED]
    assert len(rows) == len(bads)
    assert ac.stats()["certifications"] == 0
    assert ac.stats()["systems"] == 0
    # malformed seqs never even get claimed
    for bad_seq in ("1", 1.0, None, True, -1):
        with pytest.raises(SeqOrderError):
            ac.certify("sys-1", KIND_ISO_42001, OUTCOME_CERTIFIED, bad_seq,
                       _GOOD_DIGEST)


# 5. Full 8-kind vocabulary acceptance.
def test_full_cert_kind_vocabulary():
    ac = _fresh()
    seq = 0
    for i, kind in enumerate(CERT_KINDS):
        seq += 1
        rec = ac.certify(f"sys-{i}", kind, OUTCOME_CERTIFIED, seq, _GOOD_DIGEST)
        assert rec.cert_kind == kind
    assert ac.stats()["systems"] == 8
    assert ac.stats()["certifications"] == 8


# 6. Full 4-outcome vocabulary acceptance.
def test_full_outcome_vocabulary():
    ac = _fresh()
    seq = 0
    for outcome in OUTCOMES:
        seq += 1
        rec = ac.certify("sys-1", KIND_ISO_42001, outcome, seq, _GOOD_DIGEST)
        assert rec.outcome == outcome
    ev = ac.evaluate("sys-1", seq + 1)
    assert ev.n_certifications == 4
    assert (ev.n_certified, ev.n_conditional, ev.n_suspended, ev.n_revoked) == \
        (1, 1, 1, 1)


# 7. verify semantics: tamper-as-data, read purity, unknown refusal.
def test_verify_semantics_and_read_purity():
    ac = _fresh()
    rec = _certify(ac, seq=1)
    n_audit = len(ac.audit_log())
    v1 = ac.verify("crt-1", 2)
    v2 = ac.verify("crt-1", 2)
    assert v1.verdict == "verified"
    assert v2.verdict == "verified"
    assert v1.digest == v2.digest  # same-seq read twice: pure
    assert len(ac.audit_log()) == n_audit  # no audit rows on reads
    assert v1.verify("crt-1", "verified")
    assert not v1.verify("crt-1", "tampered")
    # tamper reported as data, never raised
    object.__setattr__(rec, "outcome", OUTCOME_REVOKED)
    vt = ac.verify("crt-1", 3)
    assert vt.verdict == "tampered"
    ev = ac.evaluate("sys-1", 4)
    assert ev.integrity_ok is False
    with pytest.raises(UnknownCertificationError):
        ac.verify("crt-999", 5)


# 8. evaluate posture math: all reachable postures + precedence.
def test_evaluate_posture_math():
    ac = _fresh()
    s = 1
    ac.certify("a", KIND_ISO_42001, OUTCOME_CERTIFIED, s, _GOOD_DIGEST)
    assert ac.evaluate("a", s + 1).posture == POSTURE_CERTIFIED
    s += 2
    ac.certify("b", KIND_ISO_42001, OUTCOME_CONDITIONAL, s, _GOOD_DIGEST)
    assert ac.evaluate("b", s + 1).posture == POSTURE_CONDITIONAL
    s += 2
    ac.certify("c", KIND_ISO_42001, OUTCOME_SUSPENDED, s, _GOOD_DIGEST)
    assert ac.evaluate("c", s + 1).posture == POSTURE_SUSPENDED
    s += 2
    ac.certify("d", KIND_ISO_42001, OUTCOME_REVOKED, s, _GOOD_DIGEST)
    assert ac.evaluate("d", s + 1).posture == POSTURE_REVOKED
    s += 2
    # precedence: revoked > suspended > conditional > certified
    ac.certify("mix", KIND_ISO_42001, OUTCOME_CERTIFIED, s, _GOOD_DIGEST)
    ac.certify("mix", KIND_EU_AI_ACT, OUTCOME_CONDITIONAL, s + 1, _GOOD_DIGEST)
    ac.certify("mix", KIND_NIST_AI_RMF, OUTCOME_SUSPENDED, s + 2, _GOOD_DIGEST)
    assert ac.evaluate("mix", s + 3).posture == POSTURE_SUSPENDED
    ac.certify("mix", KIND_OECD_AI, OUTCOME_REVOKED, s + 4, _GOOD_DIGEST)
    assert ac.evaluate("mix", s + 5).posture == POSTURE_REVOKED
    with pytest.raises(UnknownSystemError):
        ac.evaluate("nope", s + 6)


# 9. evaluate read purity: no seq consumption, no audit rows.
def test_evaluate_read_purity():
    ac = _fresh()
    _certify(ac, seq=1)
    before = len(ac.audit_log())
    e1 = ac.evaluate("sys-1", 2)
    e2 = ac.evaluate("sys-1", 2)
    assert e1.digest == e2.digest
    assert len(ac.audit_log()) == before
    assert e1.integrity_ok is True


# 10. retire terminality: double-retire, id non-recycling, reads-still-work.
def test_retire_terminality():
    ac = _fresh()
    _certify(ac, seq=1)
    rr = ac.retire("sys-1", 2, REASON_CERT_LOSS)
    assert rr.verify("sys-1", REASON_CERT_LOSS)
    with pytest.raises(BadReasonError):
        ac.retire("sys-2", 3, "bogus")
    with pytest.raises(DoubleRetireError):
        ac.retire("sys-1", 4)
    with pytest.raises(RetiredSystemError):
        ac.certify("sys-1", KIND_ISO_42001, OUTCOME_CERTIFIED, 5, _GOOD_DIGEST)
    # post-retire reads still work
    assert ac.certification_record("crt-1", 6).system_id == "sys-1"
    assert ac.evaluate("sys-1", 7).posture == POSTURE_CERTIFIED
    assert ac.certifications_for("sys-1", 8) == ("crt-1",)
    assert ac.retired_ids(9) == ("sys-1",)
    assert ac.stats()["retired"] == 1
    kinds = [r["kind"] for r in ac.audit_log()]
    assert kinds.count(KIND_RETIRED) == 1
    assert kinds.count(KIND_REJECTED) == 3  # bad-reason + double + mutation


# 11. seq discipline: failed mutations consume seq, rewinds bare.
def test_seq_discipline():
    ac = _fresh()
    _certify(ac, seq=1)
    with pytest.raises(SeqOrderError):
        ac.certify("sys-1", KIND_ISO_42001, OUTCOME_CERTIFIED, 1, _GOOD_DIGEST)
    assert ac.stats()["audit_rows"] == 1  # no new rejected row on rewind
    with pytest.raises(BadCertKindError):
        ac.certify("sys-2", "bogus", OUTCOME_CERTIFIED, 2, _GOOD_DIGEST)
    assert ac.stats()["audit_rows"] == 2  # failed mutation burned seq
    # input validation fires before retired check (sibling convention):
    # bad outcome on a retired system still raises BadOutcomeError, burned.
    ac.retire("sys-1", 3)
    with pytest.raises(BadOutcomeError):
        ac.certify("sys-1", KIND_ISO_42001, "bogus", 4, _GOOD_DIGEST)
    with pytest.raises(RetiredSystemError):
        ac.certify("sys-1", KIND_ISO_42001, OUTCOME_CERTIFIED, 5,
                   _GOOD_DIGEST)


# 12. audit shapes + leak ban + bad-kind.
def test_audit_shapes_and_leak_ban():
    good = ai_certification_audit_event(
        KIND_CERTIFIED, {"system_id": "s", "cert_kind": KIND_ISO_42001}, 1)
    assert good["schema"] == "audit.ndjson/1"
    assert good["module"] == AI_CERTIFICATION_VERSION
    assert good["kind"] == KIND_CERTIFIED
    assert good["seq"] == 1
    with pytest.raises(AuditKindError):
        ai_certification_audit_event(
            KIND_CERTIFIED, {"certificate": "raw-text"}, 2)
    with pytest.raises(AuditKindError):
        ai_certification_audit_event(
            KIND_CERTIFIED, {"evidence": "raw-evidence"}, 3)
    with pytest.raises(AuditKindError):
        ai_certification_audit_event("bogus-kind", {}, 4)
    with pytest.raises(SeqOrderError):
        ai_certification_audit_event(KIND_CERTIFIED, {}, "1")


# 13. cross-instance digest determinism + views + unknown lookups.
def test_determinism_views_and_unknown_lookups():
    a1, a2 = _fresh(), _fresh()
    r1 = _certify(a1, seq=1)
    r2 = _certify(a2, seq=1)
    assert r1.digest == r2.digest  # cross-instance determinism
    object.__setattr__(r1, "outcome", OUTCOME_REVOKED)
    assert not r2.verify("crt-1", "sys-1", KIND_ISO_42001, OUTCOME_REVOKED,
                         _GOOD_DIGEST)  # peer still clean
    assert a1.system_ids(2) == ("sys-1",)
    assert a1.certifications_for("sys-1", 3) == ("crt-1",)
    with pytest.raises(UnknownSystemError):
        a1.certifications_for("nope", 4)
    with pytest.raises(UnknownCertificationError):
        a1.certification_record("crt-999", 5)
    with pytest.raises(SeqOrderError):
        a1.system_ids(-1)  # view seq shape still validated
    assert a2.evaluate("sys-1", 6).integrity_ok is True


# 14. 8-thread read smoke + frozen records.
def test_thread_read_smoke_and_frozenness():
    ac = _fresh()
    _certify(ac, seq=1)
    errors = []

    def worker():
        try:
            for _ in range(200):
                ac.evaluate("sys-1", 2)
                ac.verify("crt-1", 3)
                ac.system_ids(4)
        except Exception as e:  # pragma: no cover - any error fails test
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    rec = ac.certification_record("crt-1", 5)
    with pytest.raises(AttributeError):
        rec.cert_kind = KIND_SOC2_AI


# 15. main() subprocess check: self-check passes standalone.
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, %r); "
         "import ai_certification; ai_certification.main()" % str(_HERE)],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("ai-certification OK")
