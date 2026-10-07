"""Tests for the controllable-AI governance ledger (Simulated)."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "controllable_ai.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("controllable_ai", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["controllable_ai"] = module
    spec.loader.exec_module(module)
    return module


ca = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ca.CONTROLLABLE_AI_VERSION == "controllable-ai.v1"
    assert ca.SCHEMA_PIN == "northstar.controllable-ai.v1"
    assert ca.CONTROL_DIMENSIONS == (
        "oversight-efficacy",
        "intervention-capability",
        "behavior-bounds",
        "shutdown-path",
        "corrigibility-posture",
        "containment-integrity",
        "monitoring-coverage",
        "escalation-readiness",
    )
    assert ca.CONTROL_VERDICTS == (
        "controllable",
        "partially-controllable",
        "uncontrollable",
        "inconclusive",
    )
    assert ca.RETIRE_REASONS == (
        "manual",
        "system-decommissioned",
        "protocol-complete",
        "invalidated",
    )
    assert ca.POSTURES == (
        "unassessed",
        "uncontrollable",
        "partially-controllable",
        "contested",
        "controllable",
    )
    assert ca.AUDIT_KINDS == ("assessed", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
        "ast",
        "pathlib",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed
    assert ca.ControllableAI.stdlib_only()


# 3. assess roundtrip + ass-N minting + verify() + frozen-ness
def test_assess_roundtrip_minting_verify_frozen():
    ledger = ca.ControllableAI()
    rec = ledger.assess(
        "SYS-A", 1, dimension="oversight-efficacy",
        verdict="controllable", evidence_digest=PIN,
    )
    assert rec.assessment_id == "ass-1"
    assert rec.system_id == "SYS-A"
    assert rec.dimension == "oversight-efficacy"
    assert rec.verdict == "controllable"
    assert rec.evidence_digest == PIN
    assert rec.seq == 1
    assert rec.verify()
    d = rec.as_dict()
    assert d["schema"] == ca.SCHEMA_PIN
    assert d["digest"].startswith("sha256:")
    rec2 = ledger.assess("SYS-A", 2, dimension="shutdown-path", verdict="partially-controllable")
    assert rec2.assessment_id == "ass-2"
    assert rec2.verify()
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "uncontrollable"  # type: ignore


# 4. assess bad-input table + seq-burn + rejected-row accounting
def test_assess_bad_input_table_seq_burn_rejected_rows():
    ledger = ca.ControllableAI()
    bads = [
        ({"system_id": ""}, ca.BadIdError),
        ({"system_id": 123}, ca.BadIdError),
        ({"system_id": "x" * 129}, ca.BadIdError),
        ({"dimension": "nonsense"}, ca.BadDimensionError),
        ({"verdict": "exploded"}, ca.BadVerdictError),
        ({"evidence_digest": "not-a-pin"}, ca.BadDigestError),
        ({"evidence_digest": "sha256:zzzz"}, ca.BadDigestError),
        ({"evidence_digest": "sha256:" + "ab" * 31 + "zz"}, ca.BadDigestError),
    ]
    seq = 1
    for kwargs, exc in bads:
        before_rejected = sum(
            1 for row in ledger.audit_log(0) if row["kind"] == "rejected"
        )
        kw = dict(kwargs)
        sid = kw.pop("system_id", "SYS-B")
        with pytest.raises(exc):
            ledger.assess(sid, seq, **kw)
        # failed mutation consumes the seq and books a rejected row
        assert ledger.stats(0)["seq"] == seq
        after_rejected = sum(
            1 for row in ledger.audit_log(0) if row["kind"] == "rejected"
        )
        assert after_rejected == before_rejected + 1
        seq += 1
    # retired system refusal also burns
    rec = ledger.assess("SYS-R", seq)
    ledger.retire("SYS-R", seq + 1)
    with pytest.raises(ca.RetiredSystemError):
        ledger.assess("SYS-R", seq + 2)
    assert ledger.stats(0)["rejected"] == len(bads) + 1


# 5. full 8-dimension vocabulary acceptance
def test_full_dimension_vocabulary():
    ledger = ca.ControllableAI()
    seq = 1
    for i, dimension in enumerate(ca.CONTROL_DIMENSIONS):
        rec = ledger.assess(
            f"SYS-D-{i}", seq, dimension=dimension, verdict="controllable"
        )
        assert rec.dimension == dimension
        assert rec.verify()
        seq += 1
    assert ledger.stats(0)["assessments"] == 8


# 6. full 4-verdict vocabulary acceptance
def test_full_verdict_vocabulary():
    ledger = ca.ControllableAI()
    seq = 1
    for i, verdict in enumerate(ca.CONTROL_VERDICTS):
        rec = ledger.assess(f"SYS-V-{i}", seq, verdict=verdict)
        assert rec.verdict == verdict
        assert rec.verify()
        seq += 1
    assert ledger.stats(0)["assessments"] == 4


# 7. evaluate posture math (all 5 postures + precedence) + read purity
def test_evaluate_posture_math_and_read_purity():
    ledger = ca.ControllableAI()
    # controllable: every verdict controllable
    ledger.assess("S-OK", 1, dimension="oversight-efficacy", verdict="controllable")
    ledger.assess("S-OK", 2, dimension="shutdown-path", verdict="controllable")
    # uncontrollable: any uncontrollable outranks all
    ledger.assess("S-BAD", 3, dimension="oversight-efficacy", verdict="controllable")
    ledger.assess("S-BAD", 4, dimension="behavior-bounds", verdict="uncontrollable")
    # partially-controllable: any partial (no uncontrollable)
    ledger.assess("S-PART", 5, dimension="oversight-efficacy", verdict="controllable")
    ledger.assess("S-PART", 6, dimension="containment-integrity", verdict="partially-controllable")
    ledger.assess("S-PART", 7, dimension="monitoring-coverage", verdict="inconclusive")
    # contested: any inconclusive (no worse verdict)
    ledger.assess("S-CON", 8, dimension="escalation-readiness", verdict="inconclusive")
    e_ok = ledger.evaluate("S-OK", 0)
    e_bad = ledger.evaluate("S-BAD", 0)
    e_part = ledger.evaluate("S-PART", 0)
    e_con = ledger.evaluate("S-CON", 0)
    assert e_ok.posture == "controllable"
    assert e_bad.posture == "uncontrollable"
    assert e_part.posture == "partially-controllable"
    assert e_con.posture == "contested"
    for e in (e_ok, e_bad, e_part, e_con):
        assert e.verify()
        assert e.integrity_ok
    # tallies match bookings
    tally_ok = dict(e_ok.verdict_tally)
    assert tally_ok == {
        "controllable": 2,
        "partially-controllable": 0,
        "uncontrollable": 0,
        "inconclusive": 0,
    }
    # read purity: same-seq twice, no audit rows, no seq consumption
    rows_before = len(ledger.audit_log(0))
    seq_before = ledger.stats(0)["seq"]
    again = ledger.evaluate("S-OK", 0)
    assert again.posture == "controllable"
    assert again.verify()
    assert len(ledger.audit_log(0)) == rows_before
    assert ledger.stats(0)["seq"] == seq_before


# 8. evaluate unknown-system refusal
def test_evaluate_unknown_system_refusal():
    ledger = ca.ControllableAI()
    with pytest.raises(ca.UnknownSystemError):
        ledger.evaluate("NOPE", 0)
    with pytest.raises(ca.BadIdError):
        ledger.evaluate("", 0)


# 9. verify semantics: verified, tampered-as-data, unknown refusal, read purity
def test_verify_semantics():
    ledger = ca.ControllableAI()
    rec = ledger.assess("S-V", 1, dimension="oversight-efficacy")
    v = ledger.verify("ass-1", 0)
    assert v.verdict == "verified"
    assert v.integrity_ok
    assert v.verify()
    # tamper flips the verdict as data (never raises)
    dataclasses.replace  # sanity: module uses frozen dataclasses
    object.__setattr__(rec, "verdict", "uncontrollable")
    v2 = ledger.verify("ass-1", 0)
    assert v2.verdict == "tampered"
    assert not v2.integrity_ok
    assert v2.verify()
    # tamper also flips evaluate's integrity_ok as data
    e = ledger.evaluate("S-V", 0)
    assert not e.integrity_ok
    assert e.verify()
    with pytest.raises(ca.UnknownAssessmentError):
        ledger.verify("ass-999", 0)
    with pytest.raises(ca.BadIdError):
        ledger.verify("", 0)
    # read purity: no audit rows added by verify()
    rows_before = len(ledger.audit_log(0))
    ledger.verify("ass-1", 0)
    assert len(ledger.audit_log(0)) == rows_before


# 10. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    ledger = ca.ControllableAI()
    ledger.assess("S-R", 1, dimension="oversight-efficacy", verdict="controllable")
    with pytest.raises(ca.BadReasonError):
        ledger.retire("S-R", 2, reason="nonsense")
    r = ledger.retire("S-R", 3, reason="protocol-complete")
    assert r.system_id == "S-R"
    assert r.reason == "protocol-complete"
    assert r.verify()
    with pytest.raises(ca.RetiredSystemError):
        ledger.retire("S-R", 4)
    with pytest.raises(ca.RetiredSystemError):
        ledger.assess("S-R", 5)
    # id never recycled: a fresh assess() on the retired id still refuses
    with pytest.raises(ca.RetiredSystemError):
        ledger.assess("S-R", 6, dimension="shutdown-path")
    # reads still work post-retire
    assert ledger.evaluate("S-R", 0).posture == "controllable"
    assert "S-R" in ledger.retired_ids(0)
    assert ledger.assessment_record("ass-1", 0).system_id == "S-R"
    with pytest.raises(ca.UnknownSystemError):
        ledger.retire("NOPE", 7)
    assert ledger.stats(0)["retired"] == 1


# 11. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    ledger = ca.ControllableAI()
    # genesis rewind: seq 0 vs _seq 0 -> bare raise, zero rejected rows
    with pytest.raises(ca.SeqOrderError):
        ledger.assess("S-Q", 0)
    assert ledger.stats(0)["rejected"] == 0
    ledger.assess("S-Q", 1)
    # rewind below current: bare raise, zero rows
    with pytest.raises(ca.SeqOrderError):
        ledger.assess("S-Q", 1)
    assert ledger.stats(0)["rejected"] == 0
    # malformed seqs on mutations
    for bad in (True, -1, 1.5, "2", None):
        with pytest.raises(ca.SeqOrderError):
            ledger.assess("S-Q", bad)
    # malformed seqs on pure reads
    for bad in (True, -1, 1.5, "2", None):
        with pytest.raises(ca.SeqOrderError):
            ledger.evaluate("S-Q", bad)
    # failed mutation consumes seq even when the failure is a bad verdict
    with pytest.raises(ca.BadVerdictError):
        ledger.assess("S-Q", 2, verdict="bogus")
    assert ledger.stats(0)["seq"] == 2
    ledger.assess("S-Q", 3)
    assert ledger.assessment_record("ass-2", 0).seq == 3


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_leak_ban_bad_kind():
    ledger = ca.ControllableAI()
    ledger.assess("S-A", 1, dimension="oversight-efficacy", verdict="controllable")
    rows = ledger.audit_log(0)
    assert len(rows) == 1
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["kind"] == "assessed"
    assert row["seq"] == 1
    # declared-data keys cross the boundary as pinned vocabulary values
    assert row["details"]["dimension"] == "oversight-efficacy"
    assert row["details"]["verdict"] == "controllable"
    # raw-material keys are banned at the builder level
    for banned in ("telemetry", "transcript", "weights", "policy", "prompt"):
        with pytest.raises(ca.AuditKindError):
            ca.controllable_ai_audit_event("assessed", 9, **{banned: "raw"})
    with pytest.raises(ca.AuditKindError):
        ca.controllable_ai_audit_event("invented-kind", 9)
    with pytest.raises(ca.SeqOrderError):
        ca.controllable_ai_audit_event("assessed", -1)


# 13. cross-instance digest determinism + views/stats + unknown lookups
def test_determinism_views_stats():
    ledgers = []
    for _ in range(2):
        ledger = ca.ControllableAI()
        ledger.assess("S-D", 1, dimension="oversight-efficacy", verdict="controllable")
        ledgers.append(ledger)
    a0 = ledgers[0].assessment_record("ass-1", 0)
    a1 = ledgers[1].assessment_record("ass-1", 0)
    assert a0.digest == a1.digest
    ledger = ledgers[0]
    assert ledger.assessments_for("S-D", 0) == ("ass-1",)
    assert ledger.system_ids(0) == ("S-D",)
    assert ledger.assessment_ids(0) == ("ass-1",)
    assert ledger.retired_ids(0) == ()
    stats = ledger.stats(0)
    assert stats["systems"] == 1
    assert stats["assessments"] == 1
    assert stats["retired"] == 0
    assert stats["rejected"] == 0
    assert stats["audit_rows"] == 1
    with pytest.raises(ca.UnknownSystemError):
        ledger.assessments_for("NOPE", 0)
    with pytest.raises(ca.UnknownAssessmentError):
        ledger.assessment_record("ass-999", 0)


# 14. 8-thread read smoke + frozen-ness
def test_threaded_read_smoke():
    ledger = ca.ControllableAI()
    ledger.assess("S-T", 1, dimension="oversight-efficacy", verdict="controllable")
    errors = []

    def reader():
        try:
            for _ in range(50):
                assert ledger.evaluate("S-T", 0).posture == "controllable"
                assert ledger.verify("ass-1", 0).verdict == "verified"
                assert ledger.assessment_record("ass-1", 0).verify()
        except Exception as exc:  # pragma: no cover - any failure is a bug
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    rec = ledger.assessment_record("ass-1", 0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.dimension = "shutdown-path"  # type: ignore


# 15. main() subprocess check
def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "controllable-ai OK: assess, evaluate, verify, pins, audit" in result.stdout
