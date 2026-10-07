"""Tests for the beneficial_ai governance ledger (Simulated)."""

from __future__ import annotations

import dataclasses
import subprocess
import sys
import threading

import pytest

from beneficial_ai import (
    AUDIT_KINDS,
    BENEFICIAL_AI_VERSION,
    BENEFIT_KINDS,
    POSTURES,
    RETIRE_REASONS,
    SCHEMA_PIN,
    VERDICTS,
    AuditKindError,
    BadDigestError,
    BadIdError,
    BadKindError,
    BadReasonError,
    BadVerdictError,
    BeneficialAI,
    RetiredSystemError,
    SeqOrderError,
    UnknownAssessmentError,
    UnknownSystemError,
    beneficial_ai_audit_event,
)

PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def make_ledger() -> BeneficialAI:
    return BeneficialAI()


# ---------------------------------------------------------------------------
# 1. version / schema / vocabulary pins
# ---------------------------------------------------------------------------


def test_pins() -> None:
    assert BENEFICIAL_AI_VERSION == "beneficial-ai.v1"
    assert SCHEMA_PIN == "northstar.beneficial-ai.v1"
    assert len(BENEFIT_KINDS) == 8
    assert "human-wellbeing" in BENEFIT_KINDS
    assert len(VERDICTS) == 4
    assert tuple(VERDICTS) == ("beneficial", "net-positive", "ambiguous", "harmful")
    assert tuple(POSTURES) == (
        "unassessed",
        "harmful-detected",
        "ambiguous",
        "net-positive",
        "beneficial",
    )
    assert tuple(AUDIT_KINDS) == ("assessed", "retired", "rejected")
    assert len(RETIRE_REASONS) == 4


# ---------------------------------------------------------------------------
# 2. stdlib-only AST self-check
# ---------------------------------------------------------------------------


def test_stdlib_only() -> None:
    assert BeneficialAI.stdlib_only()


# ---------------------------------------------------------------------------
# 3. assess roundtrip + minted ids + verify() + frozen-ness
# ---------------------------------------------------------------------------


def test_assess_roundtrip() -> None:
    b = make_ledger()
    rec = b.assess("SYS-1", 1, benefit_kind="human-wellbeing", verdict="beneficial",
                   claim_digest=PIN)
    assert rec.assessment_id == "asr-1"
    assert rec.system_id == "SYS-1"
    assert rec.benefit_kind == "human-wellbeing"
    assert rec.verdict == "beneficial"
    assert rec.claim_digest == PIN
    assert rec.verify()
    assert rec.digest.startswith("sha256:")
    rec2 = b.assess("SYS-1", 2, benefit_kind="public-safety", verdict="net-positive")
    assert rec2.assessment_id == "asr-2"
    assert rec2.verify()
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "harmful"  # type: ignore


# ---------------------------------------------------------------------------
# 4. assess bad-input table + seq-burn + rejected-row accounting
# ---------------------------------------------------------------------------


def test_assess_bad_inputs() -> None:
    b = make_ledger()
    bad_calls = [
        (1, lambda: b.assess("", 1)),
        (2, lambda: b.assess("x" * 129, 2)),
        (3, lambda: b.assess(None, 3)),  # type: ignore
        (4, lambda: b.assess("SYS-1", 4, benefit_kind="happiness")),
        (5, lambda: b.assess("SYS-1", 5, verdict="mostly-fine")),
        (6, lambda: b.assess("SYS-1", 6, claim_digest="sha256:zz")),
        (7, lambda: b.assess("SYS-1", 7, claim_digest="abc")),
        (8, lambda: b.assess("SYS-1", 8, claim_digest="sha256:" + "ab" * 31)),
    ]
    for seq, bad in bad_calls:
        with pytest.raises(
            (BadIdError, BadKindError, BadVerdictError, BadDigestError)
        ):
            bad()
    stats = b.stats(0)
    assert stats["rejected"] == len(bad_calls)
    assert stats["assessments"] == 0
    assert stats["seq"] == 8  # failed mutations consumed their seqs
    rows = b.audit_log(0)
    assert all(row["kind"] == "rejected" for row in rows)
    assert all(row["details"]["rejected_kind"] == "assess" for row in rows)


# ---------------------------------------------------------------------------
# 5. full 8-kind vocabulary acceptance
# ---------------------------------------------------------------------------


def test_all_benefit_kinds() -> None:
    b = make_ledger()
    for i, kind in enumerate(BENEFIT_KINDS, start=1):
        rec = b.assess("SYS-1", i, benefit_kind=kind, verdict="beneficial")
        assert rec.benefit_kind == kind
        assert rec.verify()
    assert b.stats(0)["assessments"] == 8


# ---------------------------------------------------------------------------
# 6. full 4-verdict vocabulary acceptance
# ---------------------------------------------------------------------------


def test_all_verdicts() -> None:
    b = make_ledger()
    for i, verdict in enumerate(VERDICTS, start=1):
        rec = b.assess(f"SYS-{i}", i, verdict=verdict)
        assert rec.verdict == verdict
        assert rec.verify()


# ---------------------------------------------------------------------------
# 7. retired-system assess refused
# ---------------------------------------------------------------------------


def test_retired_system_refused() -> None:
    b = make_ledger()
    b.assess("SYS-1", 1)
    b.retire("SYS-1", 2)
    with pytest.raises(RetiredSystemError):
        b.assess("SYS-1", 3)
    assert b.stats(0)["rejected"] == 1


# ---------------------------------------------------------------------------
# 8. verify semantics: roundtrip, tamper-as-data, unknown, read purity
# ---------------------------------------------------------------------------


def test_verify_semantics() -> None:
    b = make_ledger()
    rec = b.assess("SYS-1", 1, verdict="beneficial")
    v1 = b.verify("asr-1", 0)
    assert v1.verdict == "verified"
    assert v1.integrity_ok is True
    assert v1.verify()
    # tamper is reported as data, never raised
    object.__setattr__(rec, "verdict", "harmful")
    v2 = b.verify("asr-1", 0)
    assert v2.verdict == "tampered"
    assert v2.integrity_ok is False
    assert v2.verify()
    # unknown id refused
    with pytest.raises(UnknownAssessmentError):
        b.verify("asr-999", 0)
    # pure read: same seq twice, no audit rows, seq not consumed
    b2 = make_ledger()
    b2.assess("SYS-1", 1)
    n_rows = len(b2.audit_log(0))
    b2.verify("asr-1", 0)
    b2.verify("asr-1", 0)
    assert len(b2.audit_log(0)) == n_rows
    assert b2.stats(0)["seq"] == 1


# ---------------------------------------------------------------------------
# 9. evaluate posture math: all 5 postures + precedence + tally
# ---------------------------------------------------------------------------


def test_evaluate_posture_math() -> None:
    b = make_ledger()
    b.assess("A", 1, verdict="beneficial")
    b.assess("A", 2, verdict="beneficial")
    e = b.evaluate("A", 0)
    assert e.posture == "beneficial"
    assert e.integrity_ok is True
    assert e.n_assessments == 2
    assert dict(e.verdict_tally)["beneficial"] == 2

    b.assess("B", 3, verdict="beneficial")
    b.assess("B", 4, verdict="net-positive")
    assert b.evaluate("B", 0).posture == "net-positive"

    b.assess("C", 5, verdict="net-positive")
    b.assess("C", 6, verdict="ambiguous")
    assert b.evaluate("C", 0).posture == "ambiguous"

    b.assess("D", 7, verdict="beneficial")
    b.assess("D", 8, verdict="harmful")
    assert b.evaluate("D", 0).posture == "harmful-detected"

    # precedence: harmful outranks ambiguous outranks net-positive
    b.assess("E", 9, verdict="ambiguous")
    b.assess("E", 10, verdict="harmful")
    b.assess("E", 11, verdict="net-positive")
    assert b.evaluate("E", 0).posture == "harmful-detected"

    for rep in (b.evaluate("A", 0), b.evaluate("D", 0)):
        assert rep.verify()

    # tamper flips integrity_ok as data, posture unchanged otherwise
    rec = b.assessment_record("asr-1", 0)
    object.__setattr__(rec, "benefit_kind", "equity")
    e2 = b.evaluate("A", 0)
    assert e2.integrity_ok is False
    assert e2.posture == "beneficial"


# ---------------------------------------------------------------------------
# 10. evaluate unknown system + read purity
# ---------------------------------------------------------------------------


def test_evaluate_unknown_and_purity() -> None:
    b = make_ledger()
    with pytest.raises(UnknownSystemError):
        b.evaluate("NOPE", 0)
    b.assess("SYS-1", 1)
    n_rows = len(b.audit_log(0))
    e1 = b.evaluate("SYS-1", 0)
    e2 = b.evaluate("SYS-1", 0)
    assert e1.posture == e2.posture == "beneficial"
    assert len(b.audit_log(0)) == n_rows
    assert b.stats(0)["seq"] == 1
    # malformed view seqs
    for bad in (-1, True, "0", None):
        with pytest.raises(SeqOrderError):
            b.evaluate("SYS-1", bad)  # type: ignore


# ---------------------------------------------------------------------------
# 11. retire terminality + id non-recycling + post-retire reads
# ---------------------------------------------------------------------------


def test_retire_terminality() -> None:
    b = make_ledger()
    b.assess("SYS-1", 1)
    rec = b.retire("SYS-1", 2, reason="manual")
    assert rec.verify()
    assert "SYS-1" in b.retired_ids(0)
    # double retire refused
    with pytest.raises(RetiredSystemError):
        b.retire("SYS-1", 3)
    # post-retire mutations refused; reads still work
    with pytest.raises(RetiredSystemError):
        b.assess("SYS-1", 4)
    assert b.evaluate("SYS-1", 0).posture == "beneficial"
    assert b.assessments_for("SYS-1", 0) == ("asr-1",)
    # bad reason burns
    b.assess("SYS-2", 5)
    with pytest.raises(BadReasonError):
        b.retire("SYS-2", 6, reason="changed-my-mind")
    # unknown system refused
    with pytest.raises(UnknownSystemError):
        b.retire("GHOST", 7)
    stats = b.stats(0)
    assert stats["retired"] == 1
    assert stats["rejected"] == 4


# ---------------------------------------------------------------------------
# 12. seq discipline
# ---------------------------------------------------------------------------


def test_seq_discipline() -> None:
    b = make_ledger()
    # rewind raises bare with zero audit rows
    b.assess("SYS-1", 5)
    with pytest.raises(SeqOrderError):
        b.assess("SYS-1", 5)
    assert len(b.audit_log(0)) == 1
    # malformed seqs
    for bad in (0, -1, True, 1.5, "2", None):
        with pytest.raises(SeqOrderError):
            b.assess("SYS-1", bad)  # type: ignore
    # failed mutation consumes its seq
    with pytest.raises(BadVerdictError):
        b.assess("SYS-1", 10, verdict="bogus")
    with pytest.raises(SeqOrderError):
        b.assess("SYS-1", 10)  # already consumed
    b.assess("SYS-1", 11)
    assert b.stats(0)["seq"] == 11


# ---------------------------------------------------------------------------
# 13. audit shapes + leak ban + bad-kind
# ---------------------------------------------------------------------------


def test_audit_shapes() -> None:
    b = make_ledger()
    b.assess("SYS-1", 1, benefit_kind="equity", verdict="ambiguous", claim_digest=PIN)
    b.retire("SYS-1", 2, reason="reassessed")
    rows = b.audit_log(0)
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["kind"] == "assessed"
    assert rows[0]["details"]["benefit_kind"] == "equity"
    assert rows[0]["details"]["verdict"] == "ambiguous"
    assert "claim_digest" not in rows[0]["details"]
    assert rows[1]["kind"] == "retired"
    assert rows[1]["details"]["reason"] == "reassessed"
    # banned raw keys cannot cross the audit boundary
    for banned in ("impact", "analysis", "welfare", "outcomes", "metrics",
                   "stakeholder", "transcript", "reasoning", "weights",
                   "trajectory", "feedback", "content", "notes"):
        with pytest.raises(AuditKindError):
            beneficial_ai_audit_event("assessed", 1, **{banned: "raw"})
    # pinned vocabulary values remain emittable
    row = beneficial_ai_audit_event("assessed", 1, benefit_kind="equity",
                                    verdict="ambiguous", posture="ambiguous")
    assert row["kind"] == "assessed"
    # bad kind / bad seq
    with pytest.raises(AuditKindError):
        beneficial_ai_audit_event("audited", 1)
    with pytest.raises(SeqOrderError):
        beneficial_ai_audit_event("assessed", -1)


# ---------------------------------------------------------------------------
# 14. cross-instance determinism + frozen-ness + thread smoke
# ---------------------------------------------------------------------------


def test_determinism_and_threads() -> None:
    def build() -> BeneficialAI:
        bb = BeneficialAI()
        bb.assess("SYS-1", 1, verdict="net-positive", claim_digest=PIN)
        return bb

    b1, b2 = build(), build()
    assert b1.assessment_record("asr-1", 0).digest == b2.assessment_record("asr-1", 0).digest
    assert b1.evaluate("SYS-1", 0).digest == b2.evaluate("SYS-1", 0).digest

    b = make_ledger()
    for i in range(1, 6):
        b.assess("SYS-1", i)
    errors: list = []

    def reader() -> None:
        try:
            for _ in range(50):
                assert b.evaluate("SYS-1", 0).posture == "beneficial"
                assert b.assessment_ids(0)
                assert b.stats(0)["assessments"] == 5
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# ---------------------------------------------------------------------------
# 15. main() self-check subprocess
# ---------------------------------------------------------------------------


def test_main_subprocess() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "beneficial_ai"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert "beneficial-ai OK: assess, evaluate, verify, pins, audit" in proc.stdout
