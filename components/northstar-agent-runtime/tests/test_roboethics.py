"""Targeted tests for roboethics.py (15 tests)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import roboethics
from roboethics import (
    ROBOETHICS_SCHEMA,
    ROBOETHICS_VERSION,
    DIMENSIONS,
    DIM_ACCOUNTABILITY,
    DIM_DUAL_USE,
    DIM_HUMAN_ROBOT_INTERACTION,
    DIM_OPERATIONAL_AUTONOMY,
    DIM_PHYSICAL_SAFETY,
    DIM_SENSORY_PRIVACY,
    DIM_SOCIETAL_IMPACT,
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
    Roboethics,
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
    roboethics_audit_event,
)

_HERE = Path(__file__).resolve().parent.parent
_GOOD_DIGEST = "sha256:" + "0" * 64


def _fresh() -> Roboethics:
    return Roboethics()


def _assess(rb: Roboethics, sys_id: str = "sys-1",
            dim: str = DIM_PHYSICAL_SAFETY,
            verdict: str = VERDICT_PASSES, seq: int = 1) -> object:
    return rb.assess(sys_id, dim, verdict, seq, _GOOD_DIGEST)


# 1. Pins: version, schema, stdlib_only, vocabulary sizes.
def test_pins_and_vocabularies():
    assert ROBOETHICS_VERSION == "roboethics.v1"
    assert ROBOETHICS_SCHEMA == "northstar.roboethics.v1"
    assert roboethics.stdlib_only() is True
    assert len(DIMENSIONS) == 8
    assert len(set(DIMENSIONS)) == 8
    assert DIM_PHYSICAL_SAFETY in DIMENSIONS
    assert DIM_HUMAN_ROBOT_INTERACTION in DIMENSIONS
    assert DIM_DUAL_USE in DIMENSIONS
    assert len(VERDICTS) == 4
    assert set(VERDICTS) == {VERDICT_PASSES, VERDICT_FAILS,
                             VERDICT_INCONCLUSIVE, VERDICT_NEEDS_REVIEW}
    assert set(REASONS) == {REASON_MANUAL, REASON_NON_COMPLIANCE,
                            "decommissioned", "policy-change"}


# 2. stdlib-only AST self-check: no non-stdlib imports in module source.
def test_stdlib_only_ast():
    src = (Path(roboethics.__file__)).read_text()
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


# 3. assess roundtrip + verify() + frozen-ness + minted rbt-N ids.
def test_assess_roundtrip_and_minting():
    rb = _fresh()
    r1 = _assess(rb, seq=1)
    r2 = rb.assess("sys-1", DIM_SENSORY_PRIVACY, VERDICT_PASSES, 2, _GOOD_DIGEST)
    assert r1.assessment_id == "rbt-1"
    assert r2.assessment_id == "rbt-2"
    assert r1.verify("rbt-1", "sys-1", DIM_PHYSICAL_SAFETY, VERDICT_PASSES,
                    _GOOD_DIGEST)
    assert not r1.verify("rbt-1", "sys-1", DIM_PHYSICAL_SAFETY, VERDICT_FAILS,
                         _GOOD_DIGEST)
    assert not r1.verify("rbt-1", "sys-1", DIM_SENSORY_PRIVACY, VERDICT_PASSES,
                        _GOOD_DIGEST)
    with pytest.raises(AttributeError):
        r1.verdict = VERDICT_FAILS  # frozen dataclass


# 4. assess bad-input table + seq-burn + rejected-row accounting.
def test_assess_bad_inputs_burn_seq():
    rb = _fresh()
    bads = [
        ("", DIM_PHYSICAL_SAFETY, VERDICT_PASSES, _GOOD_DIGEST),            # empty id
        ("sys 1", DIM_PHYSICAL_SAFETY, VERDICT_PASSES, _GOOD_DIGEST),       # ws in id
        ("sys-1", "empathy", VERDICT_PASSES, _GOOD_DIGEST),          # bad dim
        ("sys-1", True, VERDICT_PASSES, _GOOD_DIGEST),               # bool dim
        ("sys-1", DIM_PHYSICAL_SAFETY, "excellent", _GOOD_DIGEST),          # bad verdict
        ("sys-1", DIM_PHYSICAL_SAFETY, VERDICT_PASSES, "not-a-pin"),        # bad digest
    ]
    seq = 0
    for sys_id, dim, verdict, digest in bads:
        seq += 1
        with pytest.raises(Exception):
            rb.assess(sys_id, dim, verdict, seq, digest)
    assert rb.stats()["audit_rows"] == len(bads)
    kinds = [row["kind"] for row in rb.audit_log()]
    assert all(k == KIND_REJECTED for k in kinds)
    # burned seqs still count: next good seq must strictly increase.
    rec = rb.assess("sys-1", DIM_PHYSICAL_SAFETY, VERDICT_PASSES, seq + 1)
    assert rec.assessment_id == "rbt-1"


# 5. Full 8-dimension vocabulary acceptance.
def test_full_dimension_vocabulary():
    rb = _fresh()
    seq = 0
    for dim in DIMENSIONS:
        seq += 1
        rec = rb.assess(f"sys-{seq}", dim, VERDICT_PASSES, seq)
        assert rec.dimension == dim
    assert rb.stats()["systems"] == 8
    assert rb.stats()["assessments"] == 8


# 6. Full 4-verdict vocabulary acceptance.
def test_full_verdict_vocabulary():
    rb = _fresh()
    seq = 0
    for verdict in VERDICTS:
        seq += 1
        rec = rb.assess("sys-1", DIM_PHYSICAL_SAFETY, verdict, seq)
        assert rec.verdict == verdict
    ev = rb.evaluate("sys-1", seq + 1)
    assert ev.n_assessments == 4
    assert ev.posture == POSTURE_NON_COMPLIANT  # fails outranks the rest


# 7. verify semantics: pure read, tamper-as-data, unknown refusal.
def test_verify_semantics():
    rb = _fresh()
    rec = _assess(rb, seq=1)
    v1 = rb.verify("rbt-1", 2)
    assert v1.verdict == "verified"
    assert v1.verify("rbt-1", "verified")
    # tamper the frozen record; verify reports tamper as data, never raises.
    object.__setattr__(rec, "verdict", VERDICT_FAILS)
    v2 = rb.verify("rbt-1", 3)
    assert v2.verdict == "tampered"
    assert v2.verify("rbt-1", "tampered")
    # read purity: same seq twice, no audit rows.
    before = rb.stats()["audit_rows"]
    rb.verify("rbt-1", 4)
    rb.verify("rbt-1", 4)
    assert rb.stats()["audit_rows"] == before
    with pytest.raises(UnknownAssessmentError):
        rb.verify("rbt-999", 5)


# 8. evaluate posture math: all postures + precedence.
def test_evaluate_posture_math():
    rb = _fresh()
    # compliant: all passes.
    rb.assess("s-ok", DIM_PHYSICAL_SAFETY, VERDICT_PASSES, 1, _GOOD_DIGEST)
    rb.assess("s-ok", DIM_TRANSPARENCY, VERDICT_PASSES, 2, _GOOD_DIGEST)
    assert rb.evaluate("s-ok", 3).posture == POSTURE_COMPLIANT
    # precedence: non-compliant > inconclusive > conditionally-compliant > compliant.
    rb.assess("s-mix", DIM_PHYSICAL_SAFETY, VERDICT_NEEDS_REVIEW, 4, _GOOD_DIGEST)
    assert rb.evaluate("s-mix", 5).posture == POSTURE_CONDITIONAL
    rb.assess("s-mix", DIM_DUAL_USE, VERDICT_INCONCLUSIVE, 6, _GOOD_DIGEST)
    assert rb.evaluate("s-mix", 7).posture == POSTURE_INCONCLUSIVE
    rb.assess("s-mix", DIM_SOCIETAL_IMPACT, VERDICT_FAILS, 8, _GOOD_DIGEST)
    assert rb.evaluate("s-mix", 9).posture == POSTURE_NON_COMPLIANT
    ev = rb.evaluate("s-mix", 10)
    assert ev.n_assessments == 3 and ev.n_fails == 1
    assert ev.n_needs_review == 1 and ev.n_inconclusive == 1
    assert ev.integrity_ok
    assert ev.verify("s-mix", POSTURE_NON_COMPLIANT)
    assert not ev.verify("s-mix", POSTURE_COMPLIANT)


# 9. evaluate read purity + unknown system refusal.
def test_evaluate_read_purity():
    rb = _fresh()
    _assess(rb, seq=1)
    before = rb.stats()["audit_rows"]
    e1 = rb.evaluate("sys-1", 2)
    e2 = rb.evaluate("sys-1", 2)
    assert e1 == e2
    assert rb.stats()["audit_rows"] == before
    with pytest.raises(UnknownSystemError):
        rb.evaluate("no-such", 3)


# 10. retire terminality + id non-recycling + post-retire reads.
def test_retire_terminality():
    rb = _fresh()
    _assess(rb, seq=1)
    rec = rb.retire("sys-1", 2, REASON_NON_COMPLIANCE)
    assert rec.verify("sys-1", REASON_NON_COMPLIANCE)
    with pytest.raises(DoubleRetireError):
        rb.retire("sys-1", 3)
    with pytest.raises(RetiredSystemError):
        rb.assess("sys-1", DIM_OPERATIONAL_AUTONOMY, VERDICT_PASSES, 4)
    assert rb.retired_ids(5) == ("sys-1",)
    # reads still work post-retire.
    ev = rb.evaluate("sys-1", 6)
    assert ev.posture == POSTURE_COMPLIANT
    vr = rb.verify("rbt-1", 7)
    assert vr.verdict == "verified"
    with pytest.raises(BadReasonError):
        rb.retire("sys-1", 8, "vibes")


# 11. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes.
def test_seq_discipline():
    rb = _fresh()
    _assess(rb, seq=5)
    with pytest.raises(SeqOrderError):
        rb.assess("sys-2", DIM_PHYSICAL_SAFETY, VERDICT_PASSES, 5)  # rewind: bare
    with pytest.raises(SeqOrderError):
        rb.assess("sys-2", DIM_PHYSICAL_SAFETY, VERDICT_PASSES, 3)
    assert rb.stats()["audit_rows"] == 1  # no rejected rows from rewinds
    for bad in (True, 1.5, "7", None, -1):
        with pytest.raises(SeqOrderError):
            rb.evaluate("sys-1", bad)
    # malformed seqs on reads: no rows burned.
    assert rb.stats()["audit_rows"] == 1
    with pytest.raises(BadDimensionError):
        rb.assess("sys-2", "empathy", VERDICT_PASSES, 6)  # fails: burns
    assert rb.stats()["audit_rows"] == 2


# 12. audit shapes + leak ban + bad kind.
def test_audit_shapes_and_leak_ban():
    rb = _fresh()
    _assess(rb, seq=1)
    rb.retire("sys-1", 2)
    rows = rb.audit_log()
    kinds = [row["kind"] for row in rows]
    assert kinds == [KIND_ASSESSED, KIND_RETIRED]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == ROBOETHICS_VERSION
    with pytest.raises(AuditKindError):
        roboethics_audit_event("nuked", {}, 3)
    with pytest.raises(AuditKindError):
        roboethics_audit_event(KIND_ASSESSED, {"evidence": "x"}, 3)
    with pytest.raises(AuditKindError):
        roboethics_audit_event(KIND_RETIRED, {"rationale": "x"}, 3)
    for banned in ("evidence", "finding", "justification", "analysis",
                   "weights", "policy", "transcript"):
        with pytest.raises(AuditKindError):
            roboethics_audit_event(KIND_ASSESSED, {banned: "x"}, 3)


# 13. cross-instance digest determinism + views + stats.
def test_determinism_and_views():
    a, b = _fresh(), _fresh()
    for rb in (a, b):
        rb.assess("sys-1", DIM_PHYSICAL_SAFETY, VERDICT_PASSES, 1, _GOOD_DIGEST)
        rb.assess("sys-1", DIM_ACCOUNTABILITY, VERDICT_NEEDS_REVIEW, 2, _GOOD_DIGEST)
    assert a.assessment_record("rbt-1", 3) == b.assessment_record("rbt-1", 3)
    assert a.assessments_for("sys-1", 3) == ("rbt-1", "rbt-2")
    assert a.system_ids(3) == ("sys-1",)
    st = a.stats()
    assert st["systems"] == 1 and st["assessments"] == 2
    assert st["retired"] == 0 and st["audit_rows"] == 2
    with pytest.raises(UnknownSystemError):
        a.assessments_for("nope", 3)
    with pytest.raises(UnknownAssessmentError):
        a.assessment_record("rbt-999", 3)


# 14. thread read smoke: concurrent pure reads never error.
def test_thread_read_smoke():
    rb = _fresh()
    rb.assess("sys-1", DIM_PHYSICAL_SAFETY, VERDICT_PASSES, 1, _GOOD_DIGEST)
    errors = []

    def reader(n):
        try:
            for _ in range(50):
                rb.evaluate("sys-1", 2)
                rb.verify("rbt-1", 2)
                rb.assessment_record("rbt-1", 2)
                rb.system_ids(2)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert rb.evaluate("sys-1", 2).posture == POSTURE_COMPLIANT


# 15. main() subprocess self-check.
def test_main_self_check():
    r = subprocess.run([sys.executable, "-m", "roboethics"],
                       cwd=_HERE, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "roboethics OK: assess, verify, evaluate, retire, pins, audit" in r.stdout
