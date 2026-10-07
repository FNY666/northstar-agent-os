"""Tests for aligned_ai: alignment-assessment decision ledger, Simulated."""

from __future__ import annotations

import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aligned_ai  # noqa: E402
from aligned_ai import (  # noqa: E402
    ALIGNED_AI_VERSION,
    AUDIT_KINDS,
    DIMENSIONS,
    POSTURES,
    RETIRE_REASONS,
    SCHEMA_PIN,
    VERDICTS,
    AlignedAI,
    AlignedAIError,
    AuditKindError,
    BadDigestError,
    BadDimensionError,
    BadReasonError,
    BadSystemError,
    BadVerdictError,
    RetiredSystemError,
    SeqOrderError,
    UnknownAssessmentError,
    UnknownSystemError,
    aligned_ai_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def _fresh() -> AlignedAI:
    return AlignedAI()


# 1. pins
def test_pins():
    assert ALIGNED_AI_VERSION == "aligned-ai.v1"
    assert SCHEMA_PIN == "northstar.aligned-ai.v1"
    assert DIMENSIONS == (
        "helpfulness",
        "harmlessness",
        "honesty",
        "obedience",
        "fidelity",
        "autonomy-respect",
        "fairness",
        "care",
    )
    assert VERDICTS == ("aligned", "misaligned", "uncertain", "inconclusive")
    assert POSTURES == ("unevaluated", "misaligned", "contested", "aligned")
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert AUDIT_KINDS == ("assessed", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    assert stdlib_only()


# 3. assess roundtrip + verify() + frozen-ness
def test_assess_roundtrip_verify_frozen():
    ledger = _fresh()
    rec = ledger.assess("sys-1", 1, dimension="honesty", verdict="aligned",
                        assessment_digest=GOOD_DIGEST)
    assert rec.assessment_id == "asm-1"
    assert rec.system_id == "sys-1"
    assert rec.seq == 1
    assert rec.verify()
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "misaligned"  # type: ignore


# 4. bad-input table + seq-burn + rejected-row accounting
def test_bad_inputs_burn_seq_and_book_rejected():
    ledger = _fresh()
    bad_calls = [
        lambda: ledger.assess("", 1),                                   # bad system id
        lambda: ledger.assess("sys-1", 2, dimension="nope"),            # bad dimension
        lambda: ledger.assess("sys-1", 3, verdict="nope"),              # bad verdict
        lambda: ledger.assess("sys-1", 4, assessment_digest="xx"),     # bad digest
        lambda: ledger.assess(123, 5),                                  # non-str id
        lambda: ledger.assess("sys-1", 6, verdict=True),                # bool verdict
        lambda: ledger.assess("sys-1", 7, assessment_digest=12345),     # non-str digest
    ]
    errors = (BadSystemError, BadDimensionError, BadVerdictError, BadDigestError)
    for call in bad_calls:
        with pytest.raises(errors):
            call()
    # rewinds raise bare with zero rejected rows
    with pytest.raises(SeqOrderError):
        ledger.assess("sys-1", 3)
    rows = ledger.audit_log(0)
    assert len(rows) == 7
    assert all(r["kind"] == "rejected" for r in rows)
    assert {r["seq"] for r in rows} == {1, 2, 3, 4, 5, 6, 7}
    # ledger seq advanced past the burned seqs
    rec = ledger.assess("sys-1", 8)
    assert rec.assessment_id == "asm-1"


# 5. full 8-dimension vocabulary
def test_all_dimensions_accepted():
    ledger = _fresh()
    for i, dim in enumerate(DIMENSIONS, start=1):
        rec = ledger.assess("sys-d", i, dimension=dim, verdict="aligned")
        assert rec.verify()
        assert rec.dimension == dim
    assert len(ledger.assessments_for("sys-d", 0)) == 8


# 6. full 4-verdict vocabulary
def test_all_verdicts_accepted():
    ledger = _fresh()
    for i, verdict in enumerate(VERDICTS, start=1):
        rec = ledger.assess("sys-v", i, dimension="helpfulness", verdict=verdict)
        assert rec.verify()
        assert rec.verdict == verdict


# 7. verify roundtrip + tamper-as-data + unknown refusal + read purity
def test_verify_semantics_and_read_purity():
    ledger = _fresh()
    rec = ledger.assess("sys-1", 1)
    rep = ledger.verify(rec.assessment_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok
    assert rep.verify()
    # read purity: same seq twice, no audit rows, no seq consumption
    before = len(ledger.audit_log(0))
    ledger.verify(rec.assessment_id, 2)
    assert len(ledger.audit_log(0)) == before
    assert ledger.stats(0)["seq"] == 1
    # tamper reported as data
    object.__setattr__(rec, "verdict", "misaligned")
    assert not rec.verify()
    tampered = ledger.verify(rec.assessment_id, 2)
    assert tampered.verdict == "tampered"
    assert not tampered.integrity_ok
    assert tampered.verify()
    with pytest.raises(UnknownAssessmentError):
        ledger.verify("asm-999", 2)


# 8. evaluate posture math (all postures + precedence)
def test_evaluate_posture_math():
    ledger = _fresh()
    ledger.assess("s-ok", 1, verdict="aligned")
    ledger.assess("s-ok", 2, verdict="aligned")
    assert ledger.evaluate("s-ok", 0).posture == "aligned"
    ledger.assess("s-bad", 3, verdict="aligned")
    ledger.assess("s-bad", 4, verdict="misaligned")
    assert ledger.evaluate("s-bad", 0).posture == "misaligned"
    ledger.assess("s-mix", 5, verdict="aligned")
    ledger.assess("s-mix", 6, verdict="uncertain")
    assert ledger.evaluate("s-mix", 0).posture == "contested"
    ledger.assess("s-mix", 7, verdict="inconclusive")
    assert ledger.evaluate("s-mix", 0).posture == "contested"
    # misaligned outranks contested
    ledger.assess("s-mix", 8, verdict="misaligned")
    rep = ledger.evaluate("s-mix", 0)
    assert rep.posture == "misaligned"
    assert rep.n_assessments == 4
    assert rep.n_aligned == 1 and rep.n_misaligned == 1
    assert rep.n_uncertain == 1 and rep.n_inconclusive == 1
    assert rep.integrity_ok and rep.verify()
    with pytest.raises(UnknownSystemError):
        ledger.evaluate("ghost", 0)


# 9. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    ledger = _fresh()
    ledger.assess("sys-1", 1)
    ret = ledger.retire("sys-1", 2, reason="superseded")
    assert ret.verify()
    assert ledger.retired_ids(0) == ("sys-1",)
    # re-registering a retired id is refused; assess is blocked
    with pytest.raises(RetiredSystemError):
        ledger.assess("sys-1", 3)
    # bad reason burns seq
    with pytest.raises(BadReasonError):
        ledger.retire("sys-1", 4, reason="nope")
    # double retire refused
    with pytest.raises(RetiredSystemError):
        ledger.retire("sys-1", 5)
    # unknown system refused
    with pytest.raises(UnknownSystemError):
        ledger.retire("ghost", 6)
    # post-retire reads still work
    assert ledger.evaluate("sys-1", 0).posture == "aligned"
    assert ledger.assessment_record("asm-1", 0).verdict == "aligned"


# 10. seq discipline
def test_seq_discipline():
    ledger = _fresh()
    with pytest.raises(SeqOrderError):
        ledger.assess("sys-1", 0)
    ledger.assess("sys-1", 1)
    with pytest.raises(SeqOrderError):
        ledger.assess("sys-1", 1)  # rewind: bare raise
    for bad in (True, "2", 2.0, None):
        with pytest.raises(SeqOrderError):
            ledger.assess("sys-2", bad)  # type: ignore
    rows = ledger.audit_log(0)
    assert rows == () or all(r["kind"] != "rejected" for r in rows)


# 11. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = _fresh()
    ledger.assess("sys-1", 1, dimension="honesty", verdict="aligned")
    rows = ledger.audit_log(0)
    assert len(rows) == 1
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "aligned-ai"
    assert row["version"] == ALIGNED_AI_VERSION
    assert row["kind"] == "assessed"
    assert row["seq"] == 1
    assert row["details"]["dimension"] == "honesty"
    assert row["details"]["verdict"] == "aligned"
    with pytest.raises(AuditKindError):
        aligned_ai_audit_event("bogus", 1)
    for banned in ("transcript", "weights", "policy", "labels", "reward"):
        with pytest.raises(AlignedAIError):
            aligned_ai_audit_event("assessed", 1, **{banned: "raw"})
    with pytest.raises(SeqOrderError):
        aligned_ai_audit_event("assessed", "1")


# 12. cross-instance digest determinism + integrity_ok flip
def test_digest_determinism_and_integrity_flip():
    a, b = _fresh(), _fresh()
    ra = a.assess("sys-1", 1, dimension="care", verdict="uncertain")
    rb = b.assess("sys-1", 1, dimension="care", verdict="uncertain")
    assert ra.digest == rb.digest
    object.__setattr__(ra, "verdict", "aligned")
    assert not ra.verify()
    rep = a.evaluate("sys-1", 0)
    assert not rep.integrity_ok
    assert rep.verify()


# 13. views/stats + unknown lookups
def test_views_and_stats():
    ledger = _fresh()
    ledger.assess("sys-1", 1)
    ledger.assess("sys-2", 2)
    assert set(ledger.system_ids(0)) == {"sys-1", "sys-2"}
    assert ledger.assessment_ids(0) == ("asm-1", "asm-2")
    assert ledger.assessments_for("sys-1", 0) == ("asm-1",)
    stats = ledger.stats(0)
    assert stats["n_systems"] == 2
    assert stats["n_assessments"] == 2
    assert stats["n_retired"] == 0
    assert stats["n_audit_rows"] == 2
    assert stats["schema"] == SCHEMA_PIN
    with pytest.raises(UnknownSystemError):
        ledger.assessments_for("ghost", 0)
    with pytest.raises(UnknownAssessmentError):
        ledger.assessment_record("asm-999", 0)


# 14. thread read smoke + frozen-ness
def test_thread_read_smoke():
    ledger = _fresh()
    ledger.assess("sys-1", 1, verdict="aligned")
    errors = []

    def reader():
        try:
            for _ in range(100):
                assert ledger.evaluate("sys-1", 0).posture == "aligned"
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    rec = ledger.assessment_record("asm-1", 0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.dimension = "nope"  # type: ignore


# 15. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, "-m", "aligned_ai"],
        cwd=Path(__file__).resolve().parent.parent,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "aligned-ai OK: assess, verify, evaluate, retire, pins, audit"
