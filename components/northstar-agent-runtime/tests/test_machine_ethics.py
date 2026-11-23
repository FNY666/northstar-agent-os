"""Targeted tests for machine_ethics.py (15 tests)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import machine_ethics
from machine_ethics import (
    AUDIT_SCHEMA,
    DILEMMAS,
    DLM_TROLLEY,
    FRAMEWORKS,
    FW_PRINCIPLISM,
    FW_UNSPECIFIED,
    FW_UTILITARIANISM,
    JUDGMENTS,
    JUDGMENT_AMBIGUOUS,
    JUDGMENT_IMPERMISSIBLE,
    JUDGMENT_NEEDS_REVIEW,
    JUDGMENT_PERMISSIBLE,
    KIND_ASSESSED,
    KIND_FRAMEWORK_DECLARED,
    KIND_REJECTED,
    KIND_RETIRED,
    MACHINE_ETHICS_SCHEMA,
    MACHINE_ETHICS_VERSION,
    POSTURES,
    POSTURE_AMBIGUOUS,
    POSTURE_CONSISTENT,
    POSTURE_NON_COMPLIANT,
    POSTURE_UNEVALUATED,
    REASONS,
    REASON_MANUAL,
    REASON_NON_COMPLIANCE,
    AuditKindError,
    BadDigestError,
    BadDilemmaError,
    BadFrameworkError,
    BadIdError,
    BadJudgmentError,
    BadReasonError,
    DoubleRetireError,
    MachineEthics,
    RetiredSystemError,
    SeqOrderError,
    UnknownRecordError,
    UnknownSystemError,
    machine_ethics_audit_event,
)

_HERE = Path(__file__).resolve().parent.parent
_GOOD_DIGEST = "sha256:" + "0" * 64


def _fresh() -> MachineEthics:
    return MachineEthics()


def _declared(me: MachineEthics, sys_id: str = "sys-1",
              framework: str = FW_PRINCIPLISM, seq: int = 1):
    return me.declare_framework(sys_id, seq, framework, _GOOD_DIGEST)


def _assessed(me: MachineEthics, sys_id: str = "sys-1", seq: int = 2,
              dilemma: str = DLM_TROLLEY,
              judgment: str = JUDGMENT_PERMISSIBLE):
    return me.assess(sys_id, seq, dilemma, judgment, _GOOD_DIGEST)


# 1. Pins: version, schema, vocabulary sizes.
def test_pins_and_vocabularies():
    assert MACHINE_ETHICS_VERSION == "machine-ethics.v1"
    assert MACHINE_ETHICS_SCHEMA == "northstar.machine-ethics.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert len(FRAMEWORKS) == 8
    assert len(DILEMMAS) == 8
    assert len(JUDGMENTS) == 4
    assert len(POSTURES) == 4
    assert len(REASONS) == 4
    assert machine_ethics.stdlib_only() is True


# 2. stdlib-only AST check.
def test_stdlib_only_ast():
    src = (Path(machine_ethics.__file__)).read_text()
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


# 3. declare_framework roundtrip + verify() + frozen-ness + minted frm-N ids.
def test_declare_framework_roundtrip_and_minting():
    me = _fresh()
    r1 = _declared(me, "sys-1", FW_UTILITARIANISM, 1)
    r2 = _declared(me, "sys-2", FW_PRINCIPLISM, 2)
    assert r1.framework_id == "frm-1"
    assert r2.framework_id == "frm-2"
    assert r1.verify("frm-1", "sys-1", FW_UTILITARIANISM, _GOOD_DIGEST)
    assert r2.verify("frm-2", "sys-2", FW_PRINCIPLISM, _GOOD_DIGEST)
    with pytest.raises(Exception):
        r1.framework = FW_UNSPECIFIED  # frozen
    got = me.framework_record("frm-1", 3)
    assert got.framework_id == "frm-1"
    assert me.frameworks_for("sys-1", 4) == ("frm-1",)
    assert me.system_ids(5) == ("sys-1", "sys-2")
    assert me.stats()["frameworks"] == 2


# 4. declare_framework bad inputs burn seq + book rejected rows.
def test_declare_framework_bad_inputs_burn_seq():
    me = _fresh()
    with pytest.raises(BadFrameworkError):
        me.declare_framework("sys-1", 1, "empathy")
    assert me.stats()["rejected"] == 1
    with pytest.raises(BadDigestError):
        me.declare_framework("sys-1", 2, FW_PRINCIPLISM, "not-a-pin")
    assert me.stats()["rejected"] == 2
    with pytest.raises(BadIdError):
        me.declare_framework("", 3, FW_PRINCIPLISM)
    assert me.stats()["rejected"] == 3
    with pytest.raises(BadIdError):
        me.declare_framework("has space", 4, FW_PRINCIPLISM)
    assert me.stats()["rejected"] == 4
    # retired system: declare refuses and burns.
    _declared(me, "sys-9", FW_MIXED := FW_UNSPECIFIED, 5)
    me.retire("sys-9", 6)
    with pytest.raises(RetiredSystemError):
        me.declare_framework("sys-9", 7, FW_PRINCIPLISM)
    assert me.stats()["rejected"] == 5


# 5. full 8-framework vocabulary accepted.
def test_full_framework_vocabulary():
    me = _fresh()
    for i, fw in enumerate(FRAMEWORKS):
        rec = me.declare_framework(f"fw-sys-{i}", i + 1, fw)
        assert rec.framework == fw
        assert rec.verify(rec.framework_id, f"fw-sys-{i}", fw, "")
    assert me.stats()["frameworks"] == 8


# 6. assess roundtrip + verify() + minted asm-N ids.
def test_assess_roundtrip_and_minting():
    me = _fresh()
    _declared(me, "sys-1", FW_PRINCIPLISM, 1)
    a1 = _assessed(me, "sys-1", 2)
    a2 = me.assess("sys-1", 3, "resource-allocation",
                   JUDGMENT_NEEDS_REVIEW, _GOOD_DIGEST)
    assert a1.assessment_id == "asm-1"
    assert a2.assessment_id == "asm-2"
    assert a1.verify("asm-1", "sys-1", DLM_TROLLEY,
                     JUDGMENT_PERMISSIBLE, _GOOD_DIGEST)
    assert a2.verify("asm-2", "sys-1", "resource-allocation",
                     JUDGMENT_NEEDS_REVIEW, _GOOD_DIGEST)
    with pytest.raises(Exception):
        a1.judgment = JUDGMENT_IMPERMISSIBLE  # frozen
    got = me.assessment_record("asm-1", 4)
    assert got.assessment_id == "asm-1"
    assert me.assessments_for("sys-1", 5) == ("asm-1", "asm-2")
    assert me.stats()["assessments"] == 2


# 7. assess refusal table: unknown system, bad vocab, bad digest, retired.
def test_assess_refusals_and_retired():
    me = _fresh()
    with pytest.raises(UnknownSystemError):
        me.assess("ghost", 1, DLM_TROLLEY, JUDGMENT_PERMISSIBLE)
    assert me.stats()["rejected"] == 1
    _declared(me, "sys-1", FW_DEONTOLOGY := FW_PRINCIPLISM, 2)
    with pytest.raises(BadDilemmaError):
        me.assess("sys-1", 3, "lunch-order", JUDGMENT_PERMISSIBLE)
    with pytest.raises(BadJudgmentError):
        me.assess("sys-1", 4, DLM_TROLLEY, "virtuous")
    with pytest.raises(BadDigestError):
        me.assess("sys-1", 5, DLM_TROLLEY, JUDGMENT_PERMISSIBLE,
                  "sha256:zzz")
    assert me.stats()["rejected"] == 4
    me.retire("sys-1", 6)
    with pytest.raises(RetiredSystemError):
        me.assess("sys-1", 7, DLM_TROLLEY, JUDGMENT_PERMISSIBLE)
    assert me.stats()["rejected"] == 5


# 8. full 8-dilemma x 4-judgment vocabulary acceptance.
def test_full_dilemma_and_judgment_vocabularies():
    me = _fresh()
    _declared(me, "sys-1", FW_MIXED := FW_UTILITARIANISM, 1)
    seq = 2
    for dilemma in DILEMMAS:
        for judgment in JUDGMENTS:
            rec = me.assess("sys-1", seq, dilemma, judgment)
            assert rec.dilemma_kind == dilemma
            assert rec.judgment == judgment
            seq += 1
    assert me.stats()["assessments"] == 32


# 9. verify semantics: verified roundtrip, tamper-as-data, unknown, purity.
def test_verify_semantics():
    me = _fresh()
    _declared(me, "sys-1", FW_PRINCIPLISM, 1)
    _assessed(me, "sys-1", 2)
    n0 = len(me.audit_log())
    r = me.verify("frm-1", 3)
    assert r.verdict == "verified"
    assert r.verify("frm-1", "verified")
    r = me.verify("asm-1", 4)
    assert r.verdict == "verified"
    # read purity: no audit rows, same seq twice fine.
    assert len(me.audit_log()) == n0
    r2 = me.verify("asm-1", 4)
    assert r2.verdict == "verified"
    assert len(me.audit_log()) == n0
    # tamper-as-data: flip the stored assessment, verify reports tampered.
    stored = me._assessments["asm-1"]
    object.__setattr__(stored, "judgment", JUDGMENT_IMPERMISSIBLE)
    r3 = me.verify("asm-1", 5)
    assert r3.verdict == "tampered"
    assert len(me.audit_log()) == n0
    with pytest.raises(UnknownRecordError):
        me.verify("frm-999", 6)


# 10. evaluate posture math: precedence + all postures + tallies.
def test_evaluate_posture_math():
    me = _fresh()
    # no assessments -> unevaluated
    _declared(me, "s0", FW_PRINCIPLISM, 1)
    rep = me.evaluate("s0", 2)
    assert rep.posture == POSTURE_UNEVALUATED
    # all permissible -> consistent
    _declared(me, "s1", FW_UTILITARIANISM, 3)
    me.assess("s1", 4, DLM_TROLLEY, JUDGMENT_PERMISSIBLE)
    rep = me.evaluate("s1", 5)
    assert rep.posture == POSTURE_CONSISTENT
    assert rep.n_permissible == 1 and rep.n_assessments == 1
    assert rep.integrity_ok is True
    # any ambiguous -> ambiguous
    _declared(me, "s2", FW_DEONTOLOGY := FW_PRINCIPLISM, 6)
    me.assess("s2", 7, DLM_TROLLEY, JUDGMENT_AMBIGUOUS)
    assert me.evaluate("s2", 8).posture == POSTURE_AMBIGUOUS
    # impermissible outranks ambiguous
    _declared(me, "s3", FW_MIXED := FW_UTILITARIANISM, 9)
    me.assess("s3", 10, DLM_TROLLEY, JUDGMENT_NEEDS_REVIEW)
    me.assess("s3", 11, "resource-allocation", JUDGMENT_IMPERMISSIBLE)
    rep = me.evaluate("s3", 12)
    assert rep.posture == POSTURE_NON_COMPLIANT
    assert rep.n_needs_review == 1 and rep.n_impermissible == 1
    # tamper flips integrity_ok as data
    object.__setattr__(me._assessments["asm-3"], "judgment",
                       JUDGMENT_PERMISSIBLE)
    rep2 = me.evaluate("s3", 13)
    assert rep2.integrity_ok is False


# 11. evaluate read purity + unknown-system refusal.
def test_evaluate_read_purity():
    me = _fresh()
    _declared(me, "sys-1", FW_PRINCIPLISM, 1)
    _assessed(me, "sys-1", 2)
    n0 = len(me.audit_log())
    rep = me.evaluate("sys-1", 3)
    assert rep.verify("sys-1", POSTURE_CONSISTENT, 1, 0, 0, 0)
    assert me.evaluate("sys-1", 3).digest == rep.digest  # same-seq twice
    assert len(me.audit_log()) == n0
    with pytest.raises(UnknownSystemError):
        me.evaluate("ghost", 4)
    assert len(me.audit_log()) == n0  # failed reads burn nothing
    with pytest.raises(UnknownRecordError):
        me.framework_record("frm-999", 5)


# 12. retire terminality: bad reason, double-retire, id non-recycling.
def test_retire_terminality():
    me = _fresh()
    _declared(me, "sys-1", FW_PRINCIPLISM, 1)
    _assessed(me, "sys-1", 2)
    with pytest.raises(BadReasonError):
        me.retire("sys-1", 3, "explode")
    assert me.stats()["rejected"] == 1
    with pytest.raises(UnknownSystemError):
        me.retire("ghost", 4)
    rec = me.retire("sys-1", 5, REASON_NON_COMPLIANCE)
    assert rec.system_id == "sys-1"
    assert rec.verify("sys-1", REASON_NON_COMPLIANCE)
    with pytest.raises(DoubleRetireError):
        me.retire("sys-1", 6)
    assert me.retired_ids(7) == ("sys-1",)
    # reads still work post-retire.
    assert me.evaluate("sys-1", 8).posture == POSTURE_CONSISTENT
    assert me.framework_record("frm-1", 9).framework_id == "frm-1"
    # ids never recycled: a new declaration lands on sys-2 as frm-2.
    _declared(me, "sys-2", FW_UTILITARIANISM, 10)
    assert me.framework_record("frm-2", 11).system_id == "sys-2"
    assert REASON_MANUAL in REASONS


# 13. seq discipline: rewinds bare, malformed seqs, burn on failed mutation.
def test_seq_discipline():
    me = _fresh()
    _declared(me, "sys-1", FW_PRINCIPLISM, 5)
    with pytest.raises(SeqOrderError):
        me.declare_framework("sys-2", 5, FW_PRINCIPLISM)  # rewind: bare
    with pytest.raises(SeqOrderError):
        me.declare_framework("sys-2", 3, FW_PRINCIPLISM)
    assert me.stats()["rejected"] == 0  # no rejected rows from rewinds
    for bad in (True, 1.5, "7", None, -1):
        with pytest.raises(SeqOrderError):
            me.evaluate("sys-1", bad)
    assert me.stats()["rejected"] == 0  # malformed seqs burn nothing
    with pytest.raises(BadFrameworkError):
        me.declare_framework("sys-2", 6, "empathy")  # fails: burns
    assert me.stats()["rejected"] == 1


# 14. audit shapes + leak ban + bad kind.
def test_audit_shapes_and_leak_ban():
    me = _fresh()
    _declared(me, "sys-1", FW_PRINCIPLISM, 1)
    _assessed(me, "sys-1", 2)
    me.retire("sys-1", 3)
    with pytest.raises(BadFrameworkError):
        me.declare_framework("sys-x", 4, "nope")
    kinds = [row["kind"] for row in me.audit_log()]
    assert kinds == [KIND_FRAMEWORK_DECLARED, KIND_ASSESSED,
                     KIND_RETIRED, KIND_REJECTED]
    for row in me.audit_log():
        assert row["schema"] == AUDIT_SCHEMA
        assert row["module"] == MACHINE_ETHICS_VERSION
    with pytest.raises(AuditKindError):
        machine_ethics_audit_event(KIND_ASSESSED, {"evidence": "x"}, 9)
    with pytest.raises(AuditKindError):
        machine_ethics_audit_event("bogus", {}, 9)
    with pytest.raises(AuditKindError):
        machine_ethics_audit_event(KIND_REJECTED, {"framework_text": "x"}, 9)
    row = machine_ethics_audit_event(KIND_ASSESSED,
                                     {"dilemma_kind": DLM_TROLLEY}, 9)
    assert row["detail"]["dilemma_kind"] == DLM_TROLLEY


# 15. cross-instance determinism + thread smoke + main() self-check.
def test_determinism_threads_and_main():
    def build():
        me = _fresh()
        _declared(me, "sys-1", FW_PRINCIPLISM, 1)
        _assessed(me, "sys-1", 2, DLM_TROLLEY, JUDGMENT_AMBIGUOUS)
        return me
    a, b = build(), build()
    assert a.framework_record("frm-1", 3).digest == \
        b.framework_record("frm-1", 3).digest
    assert a.evaluate("sys-1", 4).digest == b.evaluate("sys-1", 4).digest
    assert a.evaluate("sys-1", 4).posture == POSTURE_AMBIGUOUS
    errors = []
    def reader():
        try:
            for _ in range(50):
                a.evaluate("sys-1", 9)
                a.system_ids(10)
        except Exception as e:  # pragma: no cover
            errors.append(e)
    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    r = subprocess.run([sys.executable, "-m", "machine_ethics"],
                       cwd=_HERE, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "machine-ethics OK: declare, assess, verify, evaluate, retire, " \
        "pins, audit" in r.stdout
