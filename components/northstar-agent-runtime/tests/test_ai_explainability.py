"""Tests for the ai-explainability provision decision ledger."""

import ast
import dataclasses
import pathlib
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import ai_explainability
from ai_explainability import (
    AI_EXPLAINABILITY_VERSION,
    SCHEMA_PIN,
    EXPLAIN_KINDS,
    EXPLAIN_COVERAGES,
    RETIRE_REASONS,
    AUDIT_KINDS,
    AIExplainability,
    AIExplainabilityError,
    ExplanationRecord,
    AuditKindError,
    BadExplanationKindError,
    BadDigestError,
    BadIdError,
    BadCoverageError,
    BadReasonError,
    EvaluationReport,
    RetireRecord,
    RetiredSystemError,
    SeqOrderError,
    UnknownExplanationError,
    UnknownSystemError,
    VerificationReport,
    ai_explainability_audit_event,
)

PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _new() -> AIExplainability:
    return AIExplainability()


# ---------------------------------------------------------------------------
# 1. version / schema pins
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert AI_EXPLAINABILITY_VERSION == "ai-explainability.v1"
    assert SCHEMA_PIN == "northstar.ai-explainability.v1"
    assert len(EXPLAIN_KINDS) == 8
    assert set(EXPLAIN_COVERAGES) == {
        "satisfactory",
        "partial",
        "inadequate",
        "unverifiable",
        "not-assessed",
    }
    assert set(RETIRE_REASONS) == {
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    }
    assert set(AUDIT_KINDS) == {"explained", "retired", "rejected"}


# ---------------------------------------------------------------------------
# 2. stdlib-only AST check
# ---------------------------------------------------------------------------


def test_stdlib_only_ast():
    assert AIExplainability.stdlib_only() is True
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
    tree = ast.parse(pathlib.Path(ai_explainability.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] in allowed


# ---------------------------------------------------------------------------
# 3. explain roundtrip + verify() + frozen-ness
# ---------------------------------------------------------------------------


def test_explain_roundtrip_verify_frozen():
    ae = _new()
    rec = ae.explain(
        "sys-1",
        1,
        explanation_kind="counterfactual",
        coverage="satisfactory",
        explanation_digest=PIN,
    )
    assert rec.explanation_id == "exp-1"
    assert rec.system_id == "sys-1"
    assert rec.explanation_kind == "counterfactual"
    assert rec.coverage == "satisfactory"
    assert rec.explanation_digest == PIN
    assert rec.verify() is True
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.coverage = "inadequate"  # type: ignore[misc]
    # Same id roundtrip through the pure-read view.
    view = ae.explanation_record("exp-1", 2)
    assert view == rec


# ---------------------------------------------------------------------------
# 4. explain bad-input table + seq-burn + rejected rows
# ---------------------------------------------------------------------------


def test_explain_bad_inputs_burn_seq_and_book_rejected():
    ae2 = _new()
    seq2 = 0

    def burn2(*args, **kwargs):
        nonlocal seq2
        seq2 += 1
        with pytest.raises(AIExplainabilityError):
            ae2.explain(*args, seq2, **kwargs)

    # Bad system ids.
    burn2("", explanation_digest=PIN)
    burn2(None, explanation_digest=PIN)
    burn2(123, explanation_digest=PIN)
    burn2("x" * 129, explanation_digest=PIN)
    # Bad kind / coverage.
    burn2("sys-a", explanation_digest=PIN, explanation_kind="tea-leaves")
    burn2("sys-a", explanation_digest=PIN, explanation_kind=None)
    burn2("sys-a", explanation_digest=PIN, coverage="mostly-fine")
    burn2("sys-a", explanation_digest=PIN, coverage=42)
    # Bad digest pins.
    burn2("sys-a", explanation_digest="")
    burn2("sys-a", explanation_digest="sha256:zzz")
    burn2("sys-a", explanation_digest="sha256:" + "AB" * 32)
    burn2("sys-a", explanation_digest="sha256:" + "ab" * 31)

    stats = ae2.stats(seq2 + 1)
    assert stats["rejected"] == 12
    assert stats["systems"] == 0
    assert stats["explanations"] == 0
    rows = ae2.audit_log(seq2 + 2)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 12
    assert all(r["details"]["method"] == "explain" for r in rejected)
    assert all(r["schema"] == "audit.ndjson/1" for r in rejected)


# ---------------------------------------------------------------------------
# 5. full 8-kind explanation vocabulary
# ---------------------------------------------------------------------------


def test_full_explanation_kind_vocabulary():
    ae = _new()
    for i, kind in enumerate(EXPLAIN_KINDS):
        rec = ae.explain(
            f"sys-k{i}",
            i + 1,
            explanation_kind=kind,
            coverage="partial",
            explanation_digest=PIN,
        )
        assert rec.explanation_id == f"exp-{i + 1}"
        assert rec.explanation_kind == kind
        assert rec.verify() is True
    assert ae.explanation_ids(len(EXPLAIN_KINDS) + 1) == tuple(
        f"exp-{i}" for i in range(1, len(EXPLAIN_KINDS) + 1)
    )


# ---------------------------------------------------------------------------
# 6. full 5-coverage vocabulary + tally math
# ---------------------------------------------------------------------------


def test_full_coverage_vocabulary_and_tallies():
    ae = _new()
    for i, coverage in enumerate(EXPLAIN_COVERAGES):
        ae.explain(
            "sys-1",
            i + 1,
            explanation_kind="local-attribution",
            coverage=coverage,
            explanation_digest=PIN,
        )
    rep = ae.evaluate("sys-1", len(EXPLAIN_COVERAGES) + 1)
    assert rep.n_explanations == 5
    assert rep.n_satisfactory == 1
    assert rep.n_partial == 1
    assert rep.n_inadequate == 1
    assert rep.n_unverifiable == 1
    assert rep.n_not_assessed == 1
    assert rep.verify() is True


# ---------------------------------------------------------------------------
# 7. verify semantics + tamper as data + unknown + read purity
# ---------------------------------------------------------------------------


def test_verify_semantics_tamper_as_data_read_purity():
    ae = _new()
    rec = ae.explain(
        "sys-1",
        1,
        explanation_kind="concept-activation",
        coverage="satisfactory",
        explanation_digest=PIN,
    )
    v1 = ae.verify("exp-1", 2)
    assert v1.verdict == "verified"
    assert v1.integrity_ok is True
    assert v1.verify() is True
    # Same-seq twice: pure read consumes nothing, appends no rows.
    n_rows_before = len(ae.audit_log(3))
    v2 = ae.verify("exp-1", 3)
    v3 = ae.verify("exp-1", 3)
    assert v2.digest == v3.digest
    assert len(ae.audit_log(4)) == n_rows_before
    # Tamper a stored record: reported as data, never raised.
    object.__setattr__(rec, "coverage", "inadequate")
    vt = ae.verify("exp-1", 5)
    assert vt.verdict == "tampered"
    assert vt.integrity_ok is False
    assert vt.verify() is True
    # Unknown explanation raises; no rejected row for pure reads.
    with pytest.raises(UnknownExplanationError):
        ae.verify("exp-99", 6)


# ---------------------------------------------------------------------------
# 8. evaluate posture math (all postures + precedence + integrity)
# ---------------------------------------------------------------------------


def test_evaluate_posture_math_all_postures_and_precedence():
    ae = _new()
    seq = 0

    def explain(sys, coverage, kind="local-attribution"):
        nonlocal seq
        seq += 1
        return ae.explain(
            sys, seq, explanation_kind=kind, coverage=coverage,
            explanation_digest=PIN,
        )

    # unexplained: no explanations at all cannot happen for a known
    # system (first explain registers it), so use one not-assessed.
    explain("s-expl", "satisfactory")
    explain("s-expl", "satisfactory")
    rep = ae.evaluate("s-expl", seq + 1)
    assert rep.posture == "explained"

    explain("s-inad", "satisfactory")
    explain("s-inad", "inadequate")
    rep = ae.evaluate("s-inad", seq + 1)
    assert rep.posture == "inadequate"

    explain("s-cont", "satisfactory")
    explain("s-cont", "partial")
    rep = ae.evaluate("s-cont", seq + 1)
    assert rep.posture == "contested"

    explain("s-cont2", "satisfactory")
    explain("s-cont2", "unverifiable")
    rep = ae.evaluate("s-cont2", seq + 1)
    assert rep.posture == "contested"

    explain("s-unas", "satisfactory")
    explain("s-unas", "not-assessed")
    rep = ae.evaluate("s-unas", seq + 1)
    assert rep.posture == "unassessed"

    # Precedence: inadequate outranks contested outranks unassessed.
    explain("s-prec", "inadequate")
    explain("s-prec", "partial")
    explain("s-prec", "not-assessed")
    rep = ae.evaluate("s-prec", seq + 1)
    assert rep.posture == "inadequate"
    assert rep.integrity_ok is True
    assert rep.verify() is True


# ---------------------------------------------------------------------------
# 9. evaluate read purity + unknown-system refusal + integrity flip
# ---------------------------------------------------------------------------


def test_evaluate_read_purity_unknown_refusal_integrity_flip():
    ae = _new()
    rec = ae.explain(
        "sys-1", 1, explanation_kind="counterfactual",
        coverage="satisfactory", explanation_digest=PIN,
    )
    n_rows = len(ae.audit_log(2))
    r1 = ae.evaluate("sys-1", 3)
    r2 = ae.evaluate("sys-1", 3)
    assert r1.digest == r2.digest
    assert len(ae.audit_log(4)) == n_rows
    with pytest.raises(UnknownSystemError):
        ae.evaluate("nope", 5)
    # Tamper flips integrity_ok as data.
    object.__setattr__(rec, "coverage", "partial")
    r3 = ae.evaluate("sys-1", 6)
    assert r3.integrity_ok is False
    assert r3.verify() is True


# ---------------------------------------------------------------------------
# 10. retire terminality + id non-recycling + bad reason
# ---------------------------------------------------------------------------


def test_retire_terminality_id_non_recycling_bad_reason():
    ae = _new()
    ae.explain(
        "sys-1", 1, explanation_kind="local-attribution",
        coverage="satisfactory", explanation_digest=PIN,
    )
    rtr = ae.retire("sys-1", 2, reason="decommissioned")
    assert rtr.system_id == "sys-1"
    assert rtr.reason == "decommissioned"
    assert rtr.verify() is True
    assert ae.retired_ids(3) == ("sys-1",)
    # Double retire refuses; id never recycled.
    with pytest.raises(RetiredSystemError):
        ae.retire("sys-1", 4)
    with pytest.raises(RetiredSystemError):
        ae.explain(
            "sys-1", 5, explanation_kind="local-attribution",
            coverage="satisfactory", explanation_digest=PIN,
        )
    # Bad reason burns a seq and books a rejected row.
    ae2 = _new()
    ae2.explain(
        "sys-2", 1, explanation_kind="local-attribution",
        coverage="satisfactory", explanation_digest=PIN,
    )
    with pytest.raises(BadReasonError):
        ae2.retire("sys-2", 2, reason="vibes")
    with pytest.raises(UnknownSystemError):
        ae2.retire("ghost", 3)
    stats = ae2.stats(4)
    assert stats["rejected"] == 2
    assert stats["retired"] == 0
    # Reads still work after retire.
    assert ae.explanation_ids(6) == ("exp-1",)
    rep = ae.evaluate("sys-1", 7)
    assert rep.posture == "explained"
    assert rep.verify() is True


# ---------------------------------------------------------------------------
# 11. seq discipline: rewind bare, malformed seqs, failed consumes
# ---------------------------------------------------------------------------


def test_seq_discipline_rewind_malformed_failed_consumes():
    ae = _new()
    # Genesis rewind (seq 0) raises bare with zero rows.
    with pytest.raises(SeqOrderError):
        ae.explain(
            "sys-1", 0, explanation_kind="local-attribution",
            coverage="satisfactory", explanation_digest=PIN,
        )
    assert ae.stats(1)["rejected"] == 0
    assert len(ae.audit_log(2)) == 0
    # Malformed seqs raise bare before any mutation.
    for bad in (True, False, 1.5, "1", None, -3):
        with pytest.raises(SeqOrderError):
            ae.explain(
                "sys-1", bad, explanation_kind="local-attribution",
                coverage="satisfactory", explanation_digest=PIN,
            )
    assert ae.stats(3)["rejected"] == 0
    # Live seq: a failed mutation consumes its seq.
    ae.explain(
        "sys-1", 4, explanation_kind="local-attribution",
        coverage="satisfactory", explanation_digest=PIN,
    )
    with pytest.raises(BadCoverageError):
        ae.explain(
            "sys-1", 5, explanation_kind="local-attribution",
            coverage="bogus", explanation_digest=PIN,
        )
    assert ae.stats(6)["rejected"] == 1
    # Rewind after live rows raises bare (no new rejected row).
    with pytest.raises(SeqOrderError):
        ae.explain(
            "sys-1", 5, explanation_kind="local-attribution",
            coverage="satisfactory", explanation_digest=PIN,
        )
    assert ae.stats(7)["rejected"] == 1
    # Pure reads validate shape but never consume.
    for bad in (0, -1, True, "x"):
        with pytest.raises(SeqOrderError):
            ae.evaluate("sys-1", bad)
    assert ae.stats(8)["rejected"] == 1


# ---------------------------------------------------------------------------
# 12. audit shapes + leak ban + bad-kind
# ---------------------------------------------------------------------------


def test_audit_shapes_leak_ban_bad_kind():
    ae = _new()
    ae.explain(
        "sys-1", 1, explanation_kind="local-attribution",
        coverage="satisfactory", explanation_digest=PIN,
    )
    ae.retire("sys-1", 2, reason="manual")
    rows = ae.audit_log(3)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["explained", "retired"]
    first = rows[0]
    assert first["schema"] == "audit.ndjson/1"
    assert first["seq"] == 1
    assert first["details"]["explanation_id"] == "exp-1"
    # Pinned vocabulary values may cross the audit boundary...
    assert first["details"]["coverage"] == "satisfactory"
    # ...but raw material keys are banned at the builder level.
    for banned in (
        "explanation", "attribution", "rationale", "saliency",
        "weights", "transcript", "trajectory", "prompt",
    ):
        with pytest.raises(AuditKindError):
            ai_explainability_audit_event("explained", 9, **{banned: "x"})
    with pytest.raises(AuditKindError):
        ai_explainability_audit_event("bogus-kind", 1)
    with pytest.raises(SeqOrderError):
        ai_explainability_audit_event("explained", -1)
    with pytest.raises(SeqOrderError):
        ai_explainability_audit_event("explained", True)


# ---------------------------------------------------------------------------
# 13. cross-instance digest determinism + views + unknown lookups
# ---------------------------------------------------------------------------


def test_cross_instance_determinism_views_unknown_lookups():
    ae1, ae2 = _new(), _new()
    for ae in (ae1, ae2):
        ae.explain(
            "sys-1", 1, explanation_kind="counterfactual",
            coverage="partial", explanation_digest=PIN,
        )
    assert ae1.explanation_record("exp-1", 2).digest == ae2.explanation_record("exp-1", 2).digest
    assert ae1.system_ids(3) == ae2.system_ids(3) == ("sys-1",)
    assert ae1.explanations_for("sys-1", 4) == ("exp-1",)
    with pytest.raises(UnknownExplanationError):
        ae1.explanation_record("exp-99", 5)
    with pytest.raises(UnknownSystemError):
        ae1.explanations_for("ghost", 6)
    stats = ae1.stats(7)
    assert stats == {"systems": 1, "explanations": 1, "retired": 0, "rejected": 0}


# ---------------------------------------------------------------------------
# 14. 8-thread read smoke + frozen-ness
# ---------------------------------------------------------------------------


def test_threaded_read_smoke_and_frozen_records():
    ae = _new()
    ae.explain(
        "sys-1", 1, explanation_kind="mechanistic-trace",
        coverage="satisfactory", explanation_digest=PIN,
    )
    errors = []

    def reader(n):
        try:
            for _ in range(25):
                rep = ae.evaluate("sys-1", n + 2)
                assert rep.posture == "explained"
                assert rep.verify() is True
                vrf = ae.verify("exp-1", n + 2)
                assert vrf.verdict == "verified"
                assert ae.stats(n + 2)["explanations"] == 1
        except Exception as exc:  # pragma: no cover - smoke only
            errors.append(exc)

    threads = [threading.Thread(target=reader, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    # All record types are frozen.
    rec = ae.explanation_record("exp-1", 100)
    for frozen in (rec, ae.evaluate("sys-1", 101), ae.verify("exp-1", 102)):
        with pytest.raises(dataclasses.FrozenInstanceError):
            frozen.digest = "x"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 15. main() subprocess check
# ---------------------------------------------------------------------------


def test_main_subprocess_check():
    out = subprocess.run(
        [sys.executable, "-c", "import ai_explainability; ai_explainability.main()"],
        capture_output=True,
        text=True,
        cwd=str(pathlib.Path(ai_explainability.__file__).resolve().parent),
    )
    assert out.returncode == 0
    assert out.stdout.strip() == (
        "ai-explainability OK: explain, verify, evaluate, retire, pins, audit"
    )
