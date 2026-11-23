"""Tests for the ai-alignment assessment decision ledger."""

import ast
import dataclasses
import pathlib
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import ai_alignment
from ai_alignment import (
    AI_ALIGNMENT_VERSION,
    SCHEMA_PIN,
    ASSESS_KINDS,
    ASSESS_POSTURES,
    RETIRE_REASONS,
    AUDIT_KINDS,
    AIAlignment,
    AIAlignmentError,
    AssessmentRecord,
    AuditKindError,
    BadAssessmentKindError,
    BadDigestError,
    BadIdError,
    BadPostureError,
    BadReasonError,
    EvaluationReport,
    RetireRecord,
    RetiredSystemError,
    SeqOrderError,
    UnknownAssessmentError,
    UnknownSystemError,
    VerificationReport,
    ai_alignment_audit_event,
)

PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _new() -> AIAlignment:
    return AIAlignment()


# ---------------------------------------------------------------------------
# 1. version / schema pins
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert AI_ALIGNMENT_VERSION == "ai-alignment.v1"
    assert SCHEMA_PIN == "northstar.ai-alignment.v1"
    assert len(ASSESS_KINDS) == 8
    assert set(ASSESS_POSTURES) == {
        "aligned",
        "misaligned",
        "uncertain",
        "inconclusive",
        "unassessed",
    }
    assert set(RETIRE_REASONS) == {
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    }
    assert set(AUDIT_KINDS) == {"assessed", "retired", "rejected"}


# ---------------------------------------------------------------------------
# 2. stdlib-only AST check
# ---------------------------------------------------------------------------


def test_stdlib_only_ast():
    assert AIAlignment.stdlib_only() is True
    # Test-side independent walk with the house allowlist.
    allowed = {
        "__future__",
        "threading",
        "dataclasses",
        "hashlib",
        "json",
        "typing",
        "canonical_json",
        "ast",
        "pathlib",
    }
    tree = ast.parse(pathlib.Path(ai_alignment.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] in allowed


# ---------------------------------------------------------------------------
# 3. assess roundtrip + verify() + frozen-ness
# ---------------------------------------------------------------------------


def test_assess_roundtrip_verify_frozen():
    al = _new()
    rec = al.assess(
        "sys-1",
        1,
        assessment_kind="deception-screen",
        posture="misaligned",
        evidence_digest=PIN,
    )
    assert rec.assessment_id == "asm-1"
    assert rec.system_id == "sys-1"
    assert rec.assessment_kind == "deception-screen"
    assert rec.posture == "misaligned"
    assert rec.evidence_digest == PIN
    assert rec.verify() is True
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.posture = "aligned"  # type: ignore
    # Same record back from the view.
    again = al.assessment_record("asm-1", 2)
    assert again == rec


# ---------------------------------------------------------------------------
# 4. bad-input table + seq-burn + rejected-row accounting
# ---------------------------------------------------------------------------


def test_assess_bad_input_table_seq_burn():
    al = _new()
    rejected = 0

    def expect_fail(fn, exc):
        nonlocal rejected
        with pytest.raises(exc):
            fn()
        rejected += 1

    expect_fail(lambda: al.assess("", 1, evidence_digest=PIN), BadIdError)
    expect_fail(lambda: al.assess(None, 2, evidence_digest=PIN), BadIdError)
    expect_fail(lambda: al.assess("x" * 129, 3, evidence_digest=PIN), BadIdError)
    expect_fail(
        lambda: al.assess("sys-1", 4, assessment_kind="vibes", evidence_digest=PIN),
        BadAssessmentKindError,
    )
    expect_fail(
        lambda: al.assess("sys-1", 5, posture="super-aligned", evidence_digest=PIN),
        BadPostureError,
    )
    expect_fail(lambda: al.assess("sys-1", 6, evidence_digest="not-a-pin"), BadDigestError)
    expect_fail(lambda: al.assess("sys-1", 7, evidence_digest=""), BadDigestError)
    expect_fail(
        lambda: al.assess("sys-1", 8, evidence_digest="sha256:" + "ZZ" * 32),
        BadDigestError,
    )
    expect_fail(lambda: al.assess("sys-1", True, evidence_digest=PIN), SeqOrderError)
    expect_fail(lambda: al.assess("sys-1", 0, evidence_digest=PIN), SeqOrderError)
    # The two malformed seqs raised in _check_seq (before claim), so they
    # burn no seq and book no row; the other eight failed mutations did.
    expected_burns = rejected - 2
    stats = al.stats(100)
    assert stats["rejected"] == expected_burns == 8
    assert stats["assessments"] == 0
    kinds = [row["kind"] for row in al.audit_log(101)]
    assert kinds == ["rejected"] * 8
    # Rewind raises bare (no burn, no row).
    with pytest.raises(SeqOrderError):
        al.assess("sys-1", 8, evidence_digest=PIN)
    assert al.stats(102)["rejected"] == 8


# ---------------------------------------------------------------------------
# 5. full 8-kind vocabulary
# ---------------------------------------------------------------------------


def test_full_assessment_kind_vocabulary():
    al = _new()
    for i, kind in enumerate(ASSESS_KINDS, start=1):
        rec = al.assess(f"sys-{i}", i, assessment_kind=kind, evidence_digest=PIN)
        assert rec.assessment_kind == kind
        assert rec.verify() is True
    assert al.assessment_ids(99) == tuple(f"asm-{i}" for i in range(1, 9))


# ---------------------------------------------------------------------------
# 6. posture defaults + full 5-posture vocabulary
# ---------------------------------------------------------------------------


def test_posture_defaults_and_full_vocabulary():
    al = _new()
    rec = al.assess("sys-1", 1, evidence_digest=PIN)
    assert rec.posture == "unassessed"  # default posture is data, not a claim
    for i, posture in enumerate(ASSESS_POSTURES, start=2):
        rec = al.assess(
            f"sys-{i}", i, posture=posture, evidence_digest=PIN2
        )
        assert rec.posture == posture
        assert rec.verify() is True


# ---------------------------------------------------------------------------
# 7. verify semantics: roundtrip, tamper-as-data, unknown refusal
# ---------------------------------------------------------------------------


def test_verify_semantics():
    al = _new()
    rec = al.assess("sys-1", 1, posture="aligned", evidence_digest=PIN)
    vrf = al.verify("asm-1", 2)
    assert vrf.verdict == "verified"
    assert vrf.integrity_ok is True
    assert vrf.verify() is True
    assert vrf.as_dict()["schema"] == SCHEMA_PIN
    # Tamper is reported, never raised.
    object.__setattr__(rec, "posture", "misaligned")
    assert rec.verify() is False
    rep = al.verify("asm-1", 3)
    assert rep.verdict == "tampered"
    assert rep.integrity_ok is False
    # Unknown ids raise.
    with pytest.raises(UnknownAssessmentError):
        al.verify("asm-999", 4)
    with pytest.raises(UnknownAssessmentError):
        al.assessment_record("asm-999", 5)


# ---------------------------------------------------------------------------
# 8. evaluate posture math (all postures + precedence)
# ---------------------------------------------------------------------------


def test_evaluate_posture_math():
    al = _new()
    # misaligned outranks everything.
    al.assess("s-mis", 1, posture="misaligned", evidence_digest=PIN)
    al.assess("s-mis", 2, posture="aligned", evidence_digest=PIN)
    assert al.evaluate("s-mis", 3).posture == "misaligned"
    # uncertain/inconclusive outrank aligned and unassessed.
    al.assess("s-unc", 4, posture="uncertain", evidence_digest=PIN)
    al.assess("s-unc", 5, posture="aligned", evidence_digest=PIN)
    assert al.evaluate("s-unc", 6).posture == "uncertain"
    al.assess("s-inc", 7, posture="inconclusive", evidence_digest=PIN)
    assert al.evaluate("s-inc", 8).posture == "uncertain"
    # any booked unassessed holds the system at unassessed.
    al.assess("s-pen", 9, evidence_digest=PIN)
    assert al.evaluate("s-pen", 10).posture == "unassessed"
    assert al.evaluate("s-pen", 11).n_unassessed == 1
    # all aligned -> aligned.
    al.assess("s-ok", 12, posture="aligned", evidence_digest=PIN)
    al.assess("s-ok", 13, posture="aligned", evidence_digest=PIN2)
    rep = al.evaluate("s-ok", 14)
    assert rep.posture == "aligned"
    assert rep.n_assessments == 2
    assert rep.n_aligned == 2
    assert rep.integrity_ok is True
    assert rep.verify() is True


# ---------------------------------------------------------------------------
# 9. evaluate read purity + unknown-system refusal
# ---------------------------------------------------------------------------


def test_evaluate_read_purity():
    al = _new()
    al.assess("sys-1", 1, posture="aligned", evidence_digest=PIN)
    first = al.evaluate("sys-1", 5)
    second = al.evaluate("sys-1", 5)  # same seq twice: no consumption
    assert first == second
    assert first.verify() is True
    kinds = [row["kind"] for row in al.audit_log(6)]
    assert kinds == ["assessed"]  # no audit rows from reads
    with pytest.raises(UnknownSystemError):
        al.evaluate("sys-unknown", 7)


# ---------------------------------------------------------------------------
# 10. retire terminality
# ---------------------------------------------------------------------------


def test_retire_terminality():
    al = _new()
    al.assess("sys-1", 1, posture="aligned", evidence_digest=PIN)
    rtr = al.retire("sys-1", 2, reason="superseded")
    assert rtr.verify() is True
    assert rtr.reason == "superseded"
    # Ids never recycled: assess and double-retire both refused.
    with pytest.raises(RetiredSystemError):
        al.assess("sys-1", 3, evidence_digest=PIN)
    with pytest.raises(RetiredSystemError):
        al.retire("sys-1", 4)
    # Post-retire reads still work.
    assert al.evaluate("sys-1", 5).posture == "aligned"
    assert al.verify("asm-1", 6).verdict == "verified"
    assert al.retired_ids(7) == ("sys-1",)
    assert al.assessments_for("sys-1", 8) == ("asm-1",)
    # Bad reason burns its seq; on a retired system the retired check
    # fires first (fail-closed ordering, sibling convention).
    with pytest.raises(RetiredSystemError):
        al.retire("sys-1", 9, reason="because")
    al.assess("sys-2", 10, evidence_digest=PIN)
    with pytest.raises(BadReasonError):
        al.retire("sys-2", 11, reason="because")
    stats = al.stats(12)
    assert stats["retired"] == 1
    assert stats["rejected"] == 4


# ---------------------------------------------------------------------------
# 11. seq discipline
# ---------------------------------------------------------------------------


def test_seq_discipline():
    al = _new()
    # Rewind on a fresh ledger raises bare: zero rows, zero rejected.
    with pytest.raises(SeqOrderError):
        al.assess("sys-1", 0, evidence_digest=PIN)
    assert al.stats(100)["rejected"] == 0
    assert al.audit_log(101) == ()
    # Malformed seqs on views raise SeqOrderError.
    for bad in (True, 0, -1, "1", None, 1.5):
        with pytest.raises(SeqOrderError):
            al.system_ids(bad)
    # Failed mutation consumes its seq: the next must be strictly greater.
    with pytest.raises(BadDigestError):
        al.assess("sys-1", 1, evidence_digest="bad")
    with pytest.raises(SeqOrderError):
        al.assess("sys-1", 1, evidence_digest=PIN)  # reuse: bare rewind
    rec = al.assess("sys-1", 2, evidence_digest=PIN)
    assert rec.assessment_id == "asm-1"
    assert al.stats(3)["rejected"] == 1


# ---------------------------------------------------------------------------
# 12. audit shapes + leak ban + bad-kind
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban():
    al = _new()
    al.assess(
        "sys-1",
        1,
        assessment_kind="outcome-audit",
        posture="uncertain",
        evidence_digest=PIN,
    )
    al.retire("sys-1", 2)
    rows = al.audit_log(3)
    assert [r["kind"] for r in rows] == ["assessed", "retired"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert isinstance(row["seq"], int) and row["seq"] > 0
        assert isinstance(row["details"], dict)
    assessed = rows[0]["details"]
    assert assessed["assessment_kind"] == "outcome-audit"
    assert assessed["posture"] == "uncertain"
    assert assessed["assessment_id"] == "asm-1"
    # Raw keys banned at the builder level.
    for banned in ("transcript", "weights", "activations", "evidence", "score"):
        with pytest.raises(AuditKindError):
            ai_alignment_audit_event("assessed", 1, **{banned: "x"})
    # Declared-data keys (digest pins, pinned vocab) pass through.
    row = ai_alignment_audit_event(
        "assessed", 1, assessment_id="asm-1", evidence_digest=PIN, posture="aligned"
    )
    assert row["kind"] == "assessed"
    with pytest.raises(AuditKindError):
        ai_alignment_audit_event("bogus-kind", 1)
    with pytest.raises(SeqOrderError):
        ai_alignment_audit_event("assessed", -1)


# ---------------------------------------------------------------------------
# 13. cross-instance determinism + tamper breaks verify()
# ---------------------------------------------------------------------------


def test_cross_instance_determinism_and_tamper():
    kw = dict(assessment_kind="behavioral-probe", posture="aligned", evidence_digest=PIN)
    a = _new()
    b = _new()
    ra = a.assess("sys-1", 1, **kw)
    rb = b.assess("sys-1", 1, **kw)
    assert ra.digest == rb.digest
    assert ra.verify() is True and rb.verify() is True
    # Tamper one field on a returned record: verify flips, ledger untouched.
    object.__setattr__(ra, "evidence_digest", PIN2)
    assert ra.verify() is False
    assert rb.verify() is True
    assert b.assessment_record("asm-1", 2).verify() is True
    # evaluate integrity reflects tamper in the stored record.
    object.__setattr__(a.assessment_record("asm-1", 3), "posture", "misaligned")
    rep = a.evaluate("sys-1", 4)
    assert rep.integrity_ok is False
    assert rep.posture == "misaligned"  # derived as data, not proof


# ---------------------------------------------------------------------------
# 14. views / stats / unknown lookups
# ---------------------------------------------------------------------------


def test_views_stats_and_unknown_lookups():
    al = _new()
    al.assess("sys-1", 1, evidence_digest=PIN)
    al.assess("sys-2", 2, posture="aligned", evidence_digest=PIN2)
    assert al.system_ids(3) == ("sys-1", "sys-2")
    assert al.assessment_ids(4) == ("asm-1", "asm-2")
    assert al.assessments_for("sys-1", 5) == ("asm-1",)
    assert al.assessments_for("sys-2", 6) == ("asm-2",)
    assert al.retired_ids(7) == ()
    with pytest.raises(UnknownSystemError):
        al.assessments_for("sys-404", 8)
    assert al.stats(9) == {
        "systems": 2,
        "assessments": 2,
        "retired": 0,
        "rejected": 0,
    }


# ---------------------------------------------------------------------------
# 15. main() subprocess check + 8-thread read smoke
# ---------------------------------------------------------------------------


def test_main_and_read_smoke():
    proc = subprocess.run(
        [sys.executable, ai_alignment.__file__],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-alignment OK: assess, verify, evaluate, retire, pins, audit" in proc.stdout

    al = _new()
    al.assess("sys-1", 1, posture="aligned", evidence_digest=PIN)
    errors = []

    def reader():
        try:
            for _ in range(50):
                al.evaluate("sys-1", 2)
                al.system_ids(2)
                al.stats(2)
                al.audit_log(2)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # Records are frozen under concurrency too.
    rec = al.assessment_record("asm-1", 3)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.assessment_kind = "vibes"  # type: ignore
