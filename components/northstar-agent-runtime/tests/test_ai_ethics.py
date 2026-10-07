"""Targeted tests for ai_ethics.py (15 tests)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_ethics
from ai_ethics import (
    AI_ETHICS_SCHEMA,
    AI_ETHICS_VERSION,
    DIMENSIONS,
    DIM_AUTONOMY,
    DIM_FAIRNESS,
    DIM_HUMAN_OVERSIGHT,
    DIM_PRIVACY,
    DIM_TRANSPARENCY,
    KIND_ASSESSED,
    KIND_REJECTED,
    KIND_RETIRED,
    POSTURE_COMPLIANT,
    POSTURE_CONDITIONAL,
    POSTURE_INCONCLUSIVE,
    POSTURE_NON_COMPLIANT,
    POSTURE_UNEVALUATED,
    REASON_MANUAL,
    REASON_NON_COMPLIANCE,
    REASONS,
    VERDICTS,
    VERDICT_FAILS,
    VERDICT_INCONCLUSIVE,
    VERDICT_NEEDS_REVIEW,
    VERDICT_PASSES,
    AIEthics,
    AuditKindError,
    BadDigestError,
    BadDimensionError,
    BadIdError,
    BadReasonError,
    BadVerdictError,
    DoubleRetireError,
    RetiredSystemError,
    SeqOrderError,
    UnknownAssessmentError,
    UnknownSystemError,
    ai_ethics_audit_event,
)

_HERE = Path(__file__).resolve().parent.parent
_GOOD_DIGEST = "sha256:" + "0" * 64


def _fresh() -> AIEthics:
    return AIEthics()


def _assess(ae: AIEthics, sys_id: str = "sys-1", dim: str = DIM_FAIRNESS,
            verdict: str = VERDICT_PASSES, seq: int = 1) -> object:
    return ae.assess(sys_id, dim, verdict, seq, _GOOD_DIGEST)


# 1. Pins: version, schema, stdlib_only, vocabulary sizes.
def test_pins_and_vocabularies():
    assert AI_ETHICS_VERSION == "ai-ethics.v1"
    assert AI_ETHICS_SCHEMA == "northstar.ai-ethics.v1"
    assert ai_ethics.stdlib_only() is True
    assert len(DIMENSIONS) == 8
    assert len(set(DIMENSIONS)) == 8
    assert DIM_FAIRNESS in DIMENSIONS and DIM_HUMAN_OVERSIGHT in DIMENSIONS
    assert len(VERDICTS) == 4
    assert set(VERDICTS) == {VERDICT_PASSES, VERDICT_FAILS,
                             VERDICT_INCONCLUSIVE, VERDICT_NEEDS_REVIEW}
    assert set(REASONS) == {REASON_MANUAL, REASON_NON_COMPLIANCE,
                            "decommissioned", "policy-change"}


# 2. stdlib-only AST self-check: no non-stdlib imports in module source.
def test_stdlib_only_ast():
    src = (Path(ai_ethics.__file__)).read_text()
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


# 3. assess roundtrip + verify() + frozen-ness + minted ast-N ids.
def test_assess_roundtrip_and_minting():
    ae = _fresh()
    r1 = _assess(ae, seq=1)
    r2 = ae.assess("sys-1", DIM_PRIVACY, VERDICT_PASSES, 2, _GOOD_DIGEST)
    assert r1.assessment_id == "ast-1"
    assert r2.assessment_id == "ast-2"
    assert r1.verify("ast-1", "sys-1", DIM_FAIRNESS, VERDICT_PASSES,
                    _GOOD_DIGEST)
    assert not r1.verify("ast-1", "sys-1", DIM_FAIRNESS, VERDICT_FAILS,
                         _GOOD_DIGEST)
    assert not r1.verify("ast-1", "sys-1", DIM_PRIVACY, VERDICT_PASSES,
                        _GOOD_DIGEST)
    with pytest.raises(AttributeError):
        r1.verdict = VERDICT_FAILS  # frozen dataclass


# 4. assess bad-input table + seq-burn + rejected-row accounting.
def test_assess_bad_inputs_burn_seq():
    ae = _fresh()
    bads = [
        ("", DIM_FAIRNESS, VERDICT_PASSES, _GOOD_DIGEST),            # empty id
        ("sys 1", DIM_FAIRNESS, VERDICT_PASSES, _GOOD_DIGEST),       # ws in id
        ("sys-1", "empathy", VERDICT_PASSES, _GOOD_DIGEST),          # bad dim
        ("sys-1", True, VERDICT_PASSES, _GOOD_DIGEST),               # bool dim
        ("sys-1", DIM_FAIRNESS, "excellent", _GOOD_DIGEST),          # bad verdict
        ("sys-1", DIM_FAIRNESS, VERDICT_PASSES, "not-a-pin"),        # bad digest
    ]
    seq = 0
    for sys_id, dim, verdict, digest in bads:
        seq += 1
        with pytest.raises(Exception):
            ae.assess(sys_id, dim, verdict, seq, digest)
    assert ae.stats()["audit_rows"] == len(bads)
    kinds = [row["kind"] for row in ae.audit_log()]
    assert all(k == KIND_REJECTED for k in kinds)
    # burned seqs still count: next good seq must strictly increase.
    rec = ae.assess("sys-1", DIM_FAIRNESS, VERDICT_PASSES, seq + 1)
    assert rec.assessment_id == "ast-1"


# 5. Full 8-dimension vocabulary acceptance.
def test_full_dimension_vocabulary():
    ae = _fresh()
    seq = 0
    for dim in DIMENSIONS:
        seq += 1
        rec = ae.assess(f"sys-{seq}", dim, VERDICT_PASSES, seq)
        assert rec.dimension == dim
    assert ae.stats()["systems"] == 8
    assert ae.stats()["assessments"] == 8


# 6. Full 4-verdict vocabulary acceptance.
def test_full_verdict_vocabulary():
    ae = _fresh()
    seq = 0
    for verdict in VERDICTS:
        seq += 1
        rec = ae.assess("sys-1", DIM_FAIRNESS, verdict, seq)
        assert rec.verdict == verdict
    ev = ae.evaluate("sys-1", seq + 1)
    assert ev.n_assessments == 4
    assert ev.posture == POSTURE_NON_COMPLIANT  # fails outranks the rest


# 7. verify semantics: pure read, tamper-as-data, unknown refusal.
def test_verify_semantics():
    ae = _fresh()
    rec = _assess(ae, seq=1)
    v1 = ae.verify("ast-1", 2)
    assert v1.verdict == "verified"
    assert v1.verify("ast-1", "verified")
    # tamper the frozen record; verify reports tamper as data, never raises.
    object.__setattr__(rec, "verdict", VERDICT_FAILS)
    v2 = ae.verify("ast-1", 3)
    assert v2.verdict == "tampered"
    assert v2.verify("ast-1", "tampered")
    # read purity: same seq twice, no audit rows.
    before = ae.stats()["audit_rows"]
    ae.verify("ast-1", 4)
    ae.verify("ast-1", 4)
    assert ae.stats()["audit_rows"] == before
    with pytest.raises(UnknownAssessmentError):
        ae.verify("ast-999", 5)


# 8. evaluate posture math: all postures + precedence.
def test_evaluate_posture_math():
    ae = _fresh()
    # compliant: all passes.
    ae.assess("s-ok", DIM_FAIRNESS, VERDICT_PASSES, 1, _GOOD_DIGEST)
    ae.assess("s-ok", DIM_PRIVACY, VERDICT_PASSES, 2, _GOOD_DIGEST)
    assert ae.evaluate("s-ok", 3).posture == POSTURE_COMPLIANT
    # needs-review outranked by fails but above inconclusive... check order:
    # non-compliant > inconclusive > conditionally-compliant > compliant.
    ae.assess("s-mix", DIM_FAIRNESS, VERDICT_NEEDS_REVIEW, 4, _GOOD_DIGEST)
    assert ae.evaluate("s-mix", 5).posture == POSTURE_CONDITIONAL
    ae.assess("s-mix", DIM_PRIVACY, VERDICT_INCONCLUSIVE, 6, _GOOD_DIGEST)
    assert ae.evaluate("s-mix", 7).posture == POSTURE_INCONCLUSIVE
    ae.assess("s-mix", DIM_TRANSPARENCY, VERDICT_FAILS, 8, _GOOD_DIGEST)
    assert ae.evaluate("s-mix", 9).posture == POSTURE_NON_COMPLIANT
    ev = ae.evaluate("s-mix", 10)
    assert ev.n_assessments == 3 and ev.n_fails == 1
    assert ev.n_needs_review == 1 and ev.n_inconclusive == 1
    assert ev.integrity_ok
    assert ev.verify("s-mix", POSTURE_NON_COMPLIANT)
    assert not ev.verify("s-mix", POSTURE_COMPLIANT)


# 9. evaluate read purity + unknown system refusal.
def test_evaluate_read_purity():
    ae = _fresh()
    _assess(ae, seq=1)
    before = ae.stats()["audit_rows"]
    e1 = ae.evaluate("sys-1", 2)
    e2 = ae.evaluate("sys-1", 2)
    assert e1 == e2
    assert ae.stats()["audit_rows"] == before
    with pytest.raises(UnknownSystemError):
        ae.evaluate("no-such", 3)


# 10. retire terminality + id non-recycling + post-retire reads.
def test_retire_terminality():
    ae = _fresh()
    _assess(ae, seq=1)
    rec = ae.retire("sys-1", 2, REASON_NON_COMPLIANCE)
    assert rec.verify("sys-1", REASON_NON_COMPLIANCE)
    with pytest.raises(DoubleRetireError):
        ae.retire("sys-1", 3)
    with pytest.raises(RetiredSystemError):
        ae.assess("sys-1", DIM_AUTONOMY, VERDICT_PASSES, 4)
    assert ae.retired_ids(5) == ("sys-1",)
    # reads still work post-retire.
    ev = ae.evaluate("sys-1", 6)
    assert ev.posture == POSTURE_COMPLIANT
    vr = ae.verify("ast-1", 7)
    assert vr.verdict == "verified"
    with pytest.raises(BadReasonError):
        ae.retire("sys-1", 8, "vibes")


# 11. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes.
def test_seq_discipline():
    ae = _fresh()
    _assess(ae, seq=5)
    with pytest.raises(SeqOrderError):
        ae.assess("sys-2", DIM_FAIRNESS, VERDICT_PASSES, 5)  # rewind: bare
    with pytest.raises(SeqOrderError):
        ae.assess("sys-2", DIM_FAIRNESS, VERDICT_PASSES, 3)
    assert ae.stats()["audit_rows"] == 1  # no rejected rows from rewinds
    for bad in (True, 1.5, "7", None, -1):
        with pytest.raises(SeqOrderError):
            ae.evaluate("sys-1", bad)
    # malformed seqs on reads: no rows burned.
    assert ae.stats()["audit_rows"] == 1
    with pytest.raises(BadDimensionError):
        ae.assess("sys-2", "empathy", VERDICT_PASSES, 6)  # fails: burns
    assert ae.stats()["audit_rows"] == 2


# 12. audit shapes + leak ban + bad kind.
def test_audit_shapes_and_leak_ban():
    ae = _fresh()
    _assess(ae, seq=1)
    ae.retire("sys-1", 2)
    rows = ae.audit_log()
    kinds = [row["kind"] for row in rows]
    assert kinds == [KIND_ASSESSED, KIND_RETIRED]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == AI_ETHICS_VERSION
    with pytest.raises(AuditKindError):
        ai_ethics_audit_event("nuked", {}, 3)
    with pytest.raises(AuditKindError):
        ai_ethics_audit_event(KIND_ASSESSED, {"evidence": "x"}, 3)
    with pytest.raises(AuditKindError):
        ai_ethics_audit_event(KIND_RETIRED, {"rationale": "x"}, 3)
    for banned in ("evidence", "finding", "justification", "analysis",
                   "weights", "policy", "transcript"):
        with pytest.raises(AuditKindError):
            ai_ethics_audit_event(KIND_ASSESSED, {banned: "x"}, 3)


# 13. cross-instance digest determinism + views + stats.
def test_determinism_and_views():
    a, b = _fresh(), _fresh()
    for ae in (a, b):
        ae.assess("sys-1", DIM_FAIRNESS, VERDICT_PASSES, 1, _GOOD_DIGEST)
        ae.assess("sys-1", DIM_PRIVACY, VERDICT_NEEDS_REVIEW, 2, _GOOD_DIGEST)
    assert a.assessment_record("ast-1", 3) == b.assessment_record("ast-1", 3)
    assert a.assessments_for("sys-1", 3) == ("ast-1", "ast-2")
    assert a.system_ids(3) == ("sys-1",)
    st = a.stats()
    assert st["systems"] == 1 and st["assessments"] == 2
    assert st["retired"] == 0 and st["audit_rows"] == 2
    with pytest.raises(UnknownSystemError):
        a.assessments_for("nope", 3)
    with pytest.raises(UnknownAssessmentError):
        a.assessment_record("ast-999", 3)


# 14. thread read smoke: concurrent pure reads never error.
def test_thread_read_smoke():
    ae = _fresh()
    ae.assess("sys-1", DIM_FAIRNESS, VERDICT_PASSES, 1, _GOOD_DIGEST)
    errors = []

    def reader(n):
        try:
            for _ in range(50):
                ae.evaluate("sys-1", 2)
                ae.verify("ast-1", 2)
                ae.assessment_record("ast-1", 2)
                ae.system_ids(2)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert ae.evaluate("sys-1", 2).posture == POSTURE_COMPLIANT


# 15. main() subprocess self-check.
def test_main_self_check():
    r = subprocess.run([sys.executable, "-m", "ai_ethics"],
                       cwd=_HERE, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "ai-ethics OK: assess, verify, evaluate, retire, pins, audit" in r.stdout
