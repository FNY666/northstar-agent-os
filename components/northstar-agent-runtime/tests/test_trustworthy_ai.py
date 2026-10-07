"""Tests for the trustworthy-AI assessment ledger."""

import subprocess
import sys
import threading

import pytest

from trustworthy_ai import (
    AUDIT_KINDS,
    DIMENSIONS,
    FRAMEWORKS,
    OUTCOMES,
    POSTURES,
    RETIRE_REASONS,
    SCHEMA_PIN,
    TRUSTWORTHY_AI_VERSION,
    AuditKindError,
    BadDigestError,
    BadDimensionError,
    BadFrameworkError,
    BadIdError,
    BadOutcomeError,
    BadReasonError,
    RetiredSystemError,
    SeqOrderError,
    TrustworthyAI,
    TrustworthyAIError,
    UnknownAssessmentError,
    UnknownSystemError,
    stdlib_only,
    trustworthy_ai_audit_event,
)

PIN = "sha256:" + "a" * 64


def test_version_schema_and_vocabulary_pins():
    assert TRUSTWORTHY_AI_VERSION == "trustworthy-ai.v1"
    assert SCHEMA_PIN == "northstar.trustworthy-ai.v1"
    assert len(FRAMEWORKS) == 6
    assert len(DIMENSIONS) == 7
    assert len(OUTCOMES) == 5
    assert len(POSTURES) == 4
    assert set(AUDIT_KINDS) == {"assessed", "retired", "rejected"}
    assert set(RETIRE_REASONS) == {"manual", "superseded", "withdrawn"}
    assert stdlib_only()


def test_assess_roundtrip_and_verify():
    ledger = TrustworthyAI()
    rec = ledger.assess("sys-1", 1, framework="eu-hleg", dimension="robustness",
                        outcome="trustworthy", evidence_digest=PIN)
    assert rec.assessment_id == "ast-1"
    assert rec.verify()
    frozen = dict(rec.as_dict())
    assert frozen["schema"] == SCHEMA_PIN
    view = ledger.assessment_record("ast-1", 2)
    assert view == rec
    rep = ledger.verify("ast-1", 3)
    assert rep.verdict == "verified"
    assert rep.integrity_ok
    assert rep.verify()


def test_full_framework_and_dimension_vocabularies():
    ledger = TrustworthyAI()
    for i, framework in enumerate(FRAMEWORKS):
        ledger.assess(f"fw-{i}", i + 1, framework=framework, outcome="trustworthy")
    for j, dimension in enumerate(DIMENSIONS):
        ledger.assess(f"dim-{j}", 10 + j, dimension=dimension, outcome="not-assessed")
    assert ledger.stats(20)["n_assessments"] == len(FRAMEWORKS) + len(DIMENSIONS)


def test_full_outcome_vocabulary():
    ledger = TrustworthyAI()
    for i, outcome in enumerate(OUTCOMES):
        rec = ledger.assess(f"out-{i}", i + 1, outcome=outcome)
        assert rec.outcome == outcome


def test_assess_bad_input_table_burns_seq():
    ledger = TrustworthyAI()
    ledger.assess("sys-1", 1)
    seq = 2
    cases = [
        (dict(system_id=""), BadIdError),
        (dict(system_id="sys-1", framework="nope"), BadFrameworkError),
        (dict(system_id="sys-1", dimension="nope"), BadDimensionError),
        (dict(system_id="sys-1", outcome="nope"), BadOutcomeError),
        (dict(system_id="sys-1", evidence_digest="bad"), BadDigestError),
    ]
    for kwargs, exc in cases:
        with pytest.raises(exc):
            ledger.assess(**kwargs, seq=seq)
        seq += 1
    rejected = [r for r in ledger.audit_log(seq) if r["kind"] == "rejected"]
    assert len(rejected) == len(cases)
    # failed mutations consumed seqs: next valid seq must be higher
    rec = ledger.assess("sys-2", seq)
    assert rec.assessment_id == "ast-2"


def test_seq_rewind_raises_bare_without_consuming():
    ledger = TrustworthyAI()
    ledger.assess("sys-1", 5)
    with pytest.raises(SeqOrderError):
        ledger.assess("sys-1", 5)
    with pytest.raises(SeqOrderError):
        ledger.assess("sys-1", 1)
    for bad in (0, -1, "3", 3.5, True, None):
        with pytest.raises(SeqOrderError):
            ledger.assess("sys-1", bad)
    assert ledger.stats(0)["rejected"] == 0
    # seq not consumed: next strictly-increasing seq still works
    rec = ledger.assess("sys-1", 6)
    assert rec.assessment_id == "ast-2"


def test_evaluate_posture_math_and_precedence():
    ledger = TrustworthyAI()
    ledger.assess("s-ok", 1, outcome="trustworthy")
    assert ledger.evaluate("s-ok", 2).posture == "trustworthy"
    ledger.assess("s-mix", 3, outcome="not-trustworthy")
    ledger.assess("s-mix", 4, outcome="trustworthy")
    assert ledger.evaluate("s-mix", 5).posture == "not-trustworthy"
    ledger.assess("s-cond", 6, outcome="conditionally-trustworthy")
    ledger.assess("s-cond", 7, outcome="inconclusive")
    assert ledger.evaluate("s-cond", 8).posture == "conditionally-trustworthy"
    ledger.assess("s-none", 9, outcome="inconclusive")
    assert ledger.evaluate("s-none", 10).posture == "unevaluated"
    with pytest.raises(UnknownSystemError):
        ledger.evaluate("missing", 11)


def test_evaluate_and_verify_are_pure_reads():
    ledger = TrustworthyAI()
    rec = ledger.assess("sys-1", 1)
    rep1 = ledger.evaluate("sys-1", 2)
    rep2 = ledger.evaluate("sys-1", 2)
    assert rep1 == rep2
    kinds = [r["kind"] for r in ledger.audit_log(3)]
    assert "assessed" in kinds and "rejected" not in kinds
    v1 = ledger.verify("ast-1", 2)
    v2 = ledger.verify("ast-1", 2)
    assert v1 == v2
    with pytest.raises(UnknownAssessmentError):
        ledger.verify("ast-999", 2)
    with pytest.raises(UnknownAssessmentError):
        ledger.assessment_record("ast-999", 2)


def test_tamper_breaks_verify_and_integrity_ok():
    import dataclasses
    ledger = TrustworthyAI()
    rec = ledger.assess("sys-1", 1, outcome="trustworthy")
    object.__setattr__(rec, "outcome", "not-trustworthy")
    assert not rec.verify()
    assert ledger.verify("ast-1", 2).verdict == "tampered"
    report = ledger.evaluate("sys-1", 3)
    assert report.integrity_ok is False
    assert report.posture == "not-trustworthy"
    assert report.verify()


def test_retire_terminality_and_id_non_recycling():
    ledger = TrustworthyAI()
    ledger.assess("sys-1", 1)
    record = ledger.retire("sys-1", 2, reason="superseded")
    assert record.verify()
    assert ledger.retired_ids(3) == ("sys-1",)
    with pytest.raises(RetiredSystemError):
        ledger.assess("sys-1", 4)
    with pytest.raises(RetiredSystemError):
        ledger.retire("sys-1", 5)
    # reads still work post-retire
    assert ledger.assessments_for("sys-1", 6) == ("ast-1",)
    assert ledger.evaluate("sys-1", 7).n_assessments == 1
    with pytest.raises(BadReasonError):
        ledger.retire("sys-2", 8, reason="nope")
    with pytest.raises(UnknownSystemError):
        ledger.retire("missing", 9)


def test_seq_discipline_across_mutations():
    ledger = TrustworthyAI()
    ledger.assess("sys-1", 1)
    ledger.retire("sys-1", 2)
    stats = ledger.stats(3)
    assert stats["seq"] == 2
    assert stats["n_retired"] == 1
    with pytest.raises(SeqOrderError):
        ledger.assess("sys-2", 2)
    rec = ledger.assess("sys-2", 3)
    assert rec.assessment_id == "ast-2"


def test_audit_shapes_and_leak_ban():
    ledger = TrustworthyAI()
    ledger.assess("sys-1", 1)
    ledger.retire("sys-1", 2)
    for row in ledger.audit_log(3):
        assert row["schema"] == "audit.ndjson/1"
        assert row["kind"] in AUDIT_KINDS
    with pytest.raises(AuditKindError):
        trustworthy_ai_audit_event("nope", 1)
    for banned in ("evidence", "scorecard", "findings_text", "model_weights"):
        with pytest.raises(AuditKindError):
            trustworthy_ai_audit_event("assessed", 1, **{banned: "x"})
    # pinned vocabulary values remain emittable as declared data
    row = trustworthy_ai_audit_event("assessed", 1, outcome="trustworthy",
                                    dimension="robustness")
    assert row["details"]["outcome"] == "trustworthy"


def test_views_and_stats():
    ledger = TrustworthyAI()
    ledger.assess("sys-a", 1)
    ledger.assess("sys-b", 2)
    assert ledger.system_ids(3) == ("sys-a", "sys-b")
    assert ledger.assessment_ids(4) == ("ast-1", "ast-2")
    assert ledger.assessments_for("sys-a", 5) == ("ast-1",)
    with pytest.raises(UnknownSystemError):
        ledger.assessments_for("missing", 6)
    stats = ledger.stats(7)
    assert stats["n_systems"] == 2
    assert stats["n_assessments"] == 2
    assert stats["rejected"] == 0


def test_cross_instance_digest_determinism_and_threads():
    l1, l2 = TrustworthyAI(), TrustworthyAI()
    r1 = l1.assess("sys-1", 1, outcome="trustworthy")
    r2 = l2.assess("sys-1", 1, outcome="trustworthy")
    assert r1.digest == r2.digest
    ledger = TrustworthyAI()
    ledger.assess("sys-1", 1, outcome="trustworthy")
    errors = []

    def read():
        try:
            for _ in range(50):
                ledger.evaluate("sys-1", 2)
                ledger.verify("ast-1", 2)
                ledger.audit_log(2)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert ledger.evaluate("sys-1", 2).posture == "trustworthy"


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, "-c", "from trustworthy_ai import main; main()"],
        capture_output=True,
        text=True,
        cwd=__import__("pathlib").Path(__file__).parent.parent,
    )
    assert result.returncode == 0, result.stderr
    assert "trustworthy-ai OK" in result.stdout
