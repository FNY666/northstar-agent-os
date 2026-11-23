"""Tests for the ai-mechanistic analysis decision ledger."""

import ast
import dataclasses
import pathlib
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import ai_mechanistic
from ai_mechanistic import (
    AI_MECHANISTIC_VERSION,
    SCHEMA_PIN,
    ANALYZE_KINDS,
    ANALYZE_FINDINGS,
    RETIRE_REASONS,
    AUDIT_KINDS,
    AIMechanistic,
    AIMechanisticError,
    AnalysisRecord,
    AuditKindError,
    BadAnalyzeKindError,
    BadDigestError,
    BadIdError,
    BadFindingError,
    BadReasonError,
    EvaluationReport,
    RetireRecord,
    RetiredSystemError,
    SeqOrderError,
    UnknownAnalysisError,
    UnknownSystemError,
    VerificationReport,
    ai_mechanistic_audit_event,
)

PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _new() -> AIMechanistic:
    return AIMechanistic()


# ---------------------------------------------------------------------------
# 1. version / schema pins
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert AI_MECHANISTIC_VERSION == "ai-mechanistic.v1"
    assert SCHEMA_PIN == "northstar.ai-mechanistic.v1"
    assert len(ANALYZE_KINDS) == 8
    assert set(ANALYZE_FINDINGS) == {
        "confirmed",
        "partial",
        "refuted",
        "inconclusive",
        "not-assessed",
    }
    assert set(RETIRE_REASONS) == {
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    }
    assert set(AUDIT_KINDS) == {"analyzed", "retired", "rejected"}


# ---------------------------------------------------------------------------
# 2. stdlib-only AST check
# ---------------------------------------------------------------------------


def test_stdlib_only_ast():
    assert AIMechanistic.stdlib_only() is True
    tree = ast.parse(pathlib.Path(ai_mechanistic.__file__).read_text())
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
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] in allowed


# ---------------------------------------------------------------------------
# 3. analyze roundtrip: booking, minting, frozen-ness
# ---------------------------------------------------------------------------


def test_analyze_roundtrip_and_frozen():
    am = _new()
    rec = am.analyze(
        "sys-1",
        1,
        analysis_kind="causal-ablation",
        finding="confirmed",
        analysis_digest=PIN,
    )
    assert rec.analysis_id == "anl-1"
    assert rec.system_id == "sys-1"
    assert rec.analysis_kind == "causal-ablation"
    assert rec.finding == "confirmed"
    assert rec.verify() is True
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.finding = "refuted"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 4. defaults: kind and finding default values
# ---------------------------------------------------------------------------


def test_analyze_defaults():
    am = _new()
    rec = am.analyze("sys-1", 1, analysis_digest=PIN)
    assert rec.analysis_kind == "circuit-discovery"
    assert rec.finding == "not-assessed"
    assert rec.verify() is True
    rep = am.evaluate("sys-1", 2)
    assert rep.posture == "unassessed"


# ---------------------------------------------------------------------------
# 5. bad-input table: fail-closed + seq burn + rejected row
# ---------------------------------------------------------------------------


def test_analyze_bad_inputs_burn_seq():
    am = _new()
    bad = [
        ("", 1, "circuit-discovery", "confirmed", PIN),  # empty system id
        ("sys-1", 2, "bogus-kind", "confirmed", PIN),  # bad kind
        ("sys-1", 3, "circuit-discovery", "bogus-finding", PIN),  # bad finding
        ("sys-1", 4, "circuit-discovery", "confirmed", "not-a-pin"),  # bad digest
        ("sys-1", 5, "circuit-discovery", "confirmed", "sha256:xyz"),  # bad hex
    ]
    for system_id, seq, kind, finding, digest in bad:
        with pytest.raises(AIMechanisticError):
            am.analyze(system_id, seq, analysis_kind=kind, finding=finding, analysis_digest=digest)
    assert am.stats(6)["rejected"] == 5
    # burned seqs are consumed: a rewind now raises bare with no new audit row
    with pytest.raises(SeqOrderError):
        am.analyze("sys-1", 3, analysis_digest=PIN)
    assert am.stats(7)["rejected"] == 5


# ---------------------------------------------------------------------------
# 6. seq discipline: rewinds raise bare, genesis rewind raises bare
# ---------------------------------------------------------------------------


def test_seq_discipline_rewinds_bare():
    am = _new()
    with pytest.raises(SeqOrderError):
        am.analyze("sys-1", 0, analysis_digest=PIN)
    assert am.stats(1)["rejected"] == 0
    am.analyze("sys-1", 1, analysis_digest=PIN)
    with pytest.raises(SeqOrderError):
        am.analyze("sys-1", 1, analysis_digest=PIN)
    with pytest.raises(SeqOrderError):
        am.analyze("sys-1", True, analysis_digest=PIN)  # bool is not an int seq
    assert am.stats(2)["rejected"] == 0


# ---------------------------------------------------------------------------
# 7. full analysis-kind vocabulary
# ---------------------------------------------------------------------------


def test_full_analyze_kind_vocabulary():
    am = _new()
    seq = 0
    for i, kind in enumerate(sorted(ANALYZE_KINDS)):
        seq += 1
        rec = am.analyze(
            f"sys-{i}",
            seq,
            analysis_kind=kind,
            finding="not-assessed",
            analysis_digest=PIN,
        )
        assert rec.analysis_id == f"anl-{i + 1}"
        assert rec.analysis_kind == kind
    assert am.stats(seq + 1)["analyses"] == 8


# ---------------------------------------------------------------------------
# 8. full finding vocabulary + tally math
# ---------------------------------------------------------------------------


def test_full_finding_vocabulary_and_tallies():
    am = _new()
    seq = 0
    for i, finding in enumerate(sorted(ANALYZE_FINDINGS)):
        seq += 1
        am.analyze(
            "sys-1",
            seq,
            analysis_kind="linear-probing",
            finding=finding,
            analysis_digest=PIN,
        )
    seq += 1
    rep = am.evaluate("sys-1", seq)
    assert rep.n_analyses == 5
    assert rep.n_confirmed == 1
    assert rep.n_partial == 1
    assert rep.n_refuted == 1
    assert rep.n_inconclusive == 1
    assert rep.n_not_assessed == 1
    # refuted outranks contested: posture is refuted, not contested
    assert rep.posture == "refuted"
    assert rep.integrity_ok is True
    assert rep.verify() is True


# ---------------------------------------------------------------------------
# 9. evaluate posture ladder precedence
# ---------------------------------------------------------------------------


def test_evaluate_posture_precedence():
    am = _new()
    seq = 1
    # all confirmed -> mechanistically-understood
    am.analyze("sys-a", seq, finding="confirmed", analysis_digest=PIN)
    seq += 1
    assert am.evaluate("sys-a", seq).posture == "mechanistically-understood"
    # one inconclusive -> contested
    seq += 1
    am.analyze("sys-b", seq, finding="confirmed", analysis_digest=PIN)
    seq += 1
    am.analyze("sys-b", seq, finding="inconclusive", analysis_digest=PIN)
    seq += 1
    assert am.evaluate("sys-b", seq).posture == "contested"
    # unknown system refuses as data error, not posture
    seq += 1
    with pytest.raises(UnknownSystemError):
        am.evaluate("sys-nope", seq)


# ---------------------------------------------------------------------------
# 10. verify semantics: tamper as data, read purity, unknown refusal
# ---------------------------------------------------------------------------


def test_verify_tamper_as_data_and_purity():
    am = _new()
    am.analyze("sys-1", 1, finding="confirmed", analysis_digest=PIN)
    rep = am.verify("anl-1", 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # tamper as data: mutation reported, never raised
    rec = am.analysis_record("anl-1", 3)
    object.__setattr__(rec, "finding", "refuted")
    rep2 = am.verify("anl-1", 4)
    assert rep2.verdict == "tampered"
    assert rep2.integrity_ok is False
    assert rep2.verify() is True
    # unknown id refuses
    with pytest.raises(UnknownAnalysisError):
        am.verify("anl-999", 5)
    # verify is a pure read: seq shape validated, never consumed
    am.verify("anl-1", 6)
    am.verify("anl-1", 6)  # same seq twice is fine for pure reads
    # read purity: no audit rows for verify
    rows = am.audit_log(7)
    assert all(r["kind"] == "analyzed" for r in rows)


# ---------------------------------------------------------------------------
# 11. evaluate read purity: same-seq twice, no audit rows
# ---------------------------------------------------------------------------


def test_evaluate_read_purity():
    am = _new()
    am.analyze("sys-1", 1, finding="partial", analysis_digest=PIN)
    r1 = am.evaluate("sys-1", 2)
    assert r1.posture == "contested"
    # same seq twice is fine for pure reads
    r2 = am.evaluate("sys-1", 2)
    assert r2.posture == "contested"
    rows = am.audit_log(3)
    assert all(r["kind"] == "analyzed" for r in rows)


# ---------------------------------------------------------------------------
# 12. retire terminality: bad reason, double retire, reads still work
# ---------------------------------------------------------------------------


def test_retire_terminality():
    am = _new()
    am.analyze("sys-1", 1, analysis_digest=PIN)
    with pytest.raises(BadReasonError):
        am.retire("sys-1", 2, reason="bogus")
    assert am.stats(3)["rejected"] == 1
    rtr = am.retire("sys-1", 4, reason="decommissioned")
    assert rtr.verify() is True
    # double retire refuses
    with pytest.raises(RetiredSystemError):
        am.retire("sys-1", 5)
    # id never recycled: post-retire mutation refused
    with pytest.raises(RetiredSystemError):
        am.analyze("sys-1", 6, analysis_digest=PIN)
    # post-retire reads still work
    assert am.evaluate("sys-1", 7).n_analyses == 1
    assert am.verify("anl-1", 8).verdict == "verified"
    assert am.retired_ids(9) == ("sys-1",)
    # all four reasons accepted on a fresh system
    am.analyze("sys-2", 10, analysis_digest=PIN)
    for i, reason in enumerate(sorted(RETIRE_REASONS)):
        sid = f"sys-r-{i}"
        am.analyze(sid, 11 + 2 * i, analysis_digest=PIN)
        assert am.retire(sid, 12 + 2 * i, reason=reason).reason == reason


# ---------------------------------------------------------------------------
# 13. audit shapes + leak ban
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban():
    row = ai_mechanistic_audit_event("analyzed", 1, analysis_id="anl-1")
    assert row["schema"] == "audit.ndjson/1"
    assert row["kind"] == "analyzed"
    assert row["seq"] == 1
    with pytest.raises(AuditKindError):
        ai_mechanistic_audit_event("bogus-kind", 1)
    with pytest.raises(AuditKindError):
        ai_mechanistic_audit_event("analyzed", 1, weights="raw-model-weights")
    with pytest.raises(AuditKindError):
        ai_mechanistic_audit_event("analyzed", 1, activations=[1.0, 2.0])
    # pinned vocab values remain emittable as declared data
    ok = ai_mechanistic_audit_event(
        "analyzed", 2, analysis_kind="causal-ablation", finding="partial"
    )
    assert ok["details"]["finding"] == "partial"
    # ledger audit log: analyzed + retired + rejected rows
    am = _new()
    am.analyze("sys-1", 1, analysis_digest=PIN)
    with pytest.raises(BadAnalyzeKindError):
        am.analyze("sys-1", 2, analysis_kind="nope", analysis_digest=PIN)
    am.retire("sys-1", 3)
    rows = am.audit_log(4)
    assert [r["kind"] for r in rows] == ["analyzed", "rejected", "retired"]


# ---------------------------------------------------------------------------
# 14. determinism + views + thread smoke + main() subprocess
# ---------------------------------------------------------------------------


def test_determinism_views_threads_and_main():
    am = _new()
    am.analyze("sys-1", 1, finding="confirmed", analysis_digest=PIN)
    am.analyze("sys-1", 2, finding="confirmed", analysis_digest=PIN)
    am2 = _new()
    am2.analyze("sys-1", 1, finding="confirmed", analysis_digest=PIN)
    am2.analyze("sys-1", 2, finding="confirmed", analysis_digest=PIN)
    # cross-instance digest determinism
    for aid in ("anl-1", "anl-2"):
        assert am.analysis_record(aid, 3).digest == am2.analysis_record(aid, 3).digest
    # views
    assert am.system_ids(4) == ("sys-1",)
    assert am.analysis_ids(5) == ("anl-1", "anl-2")
    assert am.analyses_for("sys-1", 6) == ("anl-1", "anl-2")
    assert am.retired_ids(7) == ()
    with pytest.raises(UnknownSystemError):
        am.analyses_for("sys-nope", 8)
    st = am.stats(9)
    assert st == {"systems": 1, "analyses": 2, "retired": 0, "rejected": 0}
    # thread smoke: concurrent pure reads
    errs: list = []
    def _read():
        try:
            for _ in range(50):
                am.evaluate("sys-1", 10)
                am.verify("anl-1", 10)
        except Exception as exc:  # pragma: no cover
            errs.append(exc)
    threads = [threading.Thread(target=_read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errs == []
    # main() self-check via subprocess
    proc = subprocess.run(
        [sys.executable, "-m", "ai_mechanistic"],
        capture_output=True,
        text=True,
        cwd=str(pathlib.Path(ai_mechanistic.__file__).resolve().parent),
    )
    assert proc.returncode == 0
    assert "ai-mechanistic OK: analyze, verify, evaluate, retire, pins, audit" in proc.stdout


# ---------------------------------------------------------------------------
# 15. frozen-ness across records + tamper flips integrity_ok
# ---------------------------------------------------------------------------


def test_frozen_records_and_integrity_flip():
    am = _new()
    am.analyze("sys-1", 1, finding="confirmed", analysis_digest=PIN)
    rec = am.analysis_record("anl-1", 2)
    assert rec.verify() is True
    object.__setattr__(rec, "analysis_digest", PIN2)
    assert rec.verify() is False
    rep = am.evaluate("sys-1", 3)
    assert rep.integrity_ok is False
    assert rep.verify() is True  # the report itself is still intact
    # VerificationReport is frozen too
    vrep = am.verify("anl-1", 4)
    with pytest.raises(dataclasses.FrozenInstanceError):
        vrep.verdict = "verified"  # type: ignore[misc]
