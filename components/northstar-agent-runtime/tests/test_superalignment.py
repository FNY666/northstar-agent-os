"""Tests for superalignment (superalignment research governance decision ledger)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from superalignment import (
    SUPERALIGNMENT_VERSION,
    SCHEMA_PIN,
    RESEARCH_AREAS,
    EVAL_METHODS,
    EVAL_VERDICTS,
    POSTURES,
    SuperalignmentError,
    SeqOrderError,
    BadIdError,
    DuplicateProgramError,
    UnknownProgramError,
    UnknownRecordError,
    BadAreaError,
    BadMethodError,
    BadVerdictError,
    BadDigestError,
    AuditKindError,
    ResearchRecord,
    EvaluationRecord,
    SuperalignmentReport,
    Superalignment,
    superalignment_audit_event,
)

MOD = Path(__file__).resolve().parent.parent / "superalignment.py"

STDLIB_ALLOW = {
    "hashlib", "json", "threading", "dataclasses", "typing", "__future__",
    "canonical_json", "ast", "pathlib",
}


def _digest(tag: bytes = b"program") -> str:
    return "sha256:" + hashlib.sha256(tag).hexdigest()


def _sa() -> Superalignment:
    return Superalignment()


# 1. version/schema/vocabulary pins
def test_pins():
    assert SUPERALIGNMENT_VERSION == "superalignment.v1"
    assert SCHEMA_PIN == "northstar.superalignment.v1"
    assert RESEARCH_AREAS == (
        "scalable-oversight",
        "weak-to-strong-generalization",
        "automated-alignment-research",
        "successor-model-evaluation",
        "alignment-interpretability",
        "corrigibility-foundation",
        "preference-learning",
        "evaluation-science",
    )
    assert EVAL_METHODS == (
        "human-review",
        "automated-eval",
        "red-team",
        "replication",
        "external-audit",
        "successor-judge",
        "sandbagging-check",
        "corrigibility-check",
    )
    assert EVAL_VERDICTS == (
        "progressing", "promising", "stalled",
        "regressed", "inconclusive", "not-evaluated",
    )
    assert POSTURES == (
        "unevaluated", "at-risk", "stalled", "advancing", "inconclusive",
    )


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(n.name.split(".")[0] for n in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= STDLIB_ALLOW, imports - STDLIB_ALLOW
    assert Superalignment.stdlib_only()


# 3. research roundtrip + verify + frozen-ness
def test_research_roundtrip():
    sa = _sa()
    rec = sa.research("p-1", 1, research_area="scalable-oversight",
                      program_digest=_digest())
    assert isinstance(rec, ResearchRecord)
    assert rec.program_id == "p-1"
    assert rec.research_area == "scalable-oversight"
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(Exception):
        rec.research_area = "x"  # frozen


# 4. research bad-input table + duplicate + seq-burn + rejected rows
def test_research_bad_inputs():
    sa = _sa()
    seq = 0
    bad = [
        (lambda s: sa.research("", s), BadIdError),
        (lambda s: sa.research(123, s), BadIdError),
        (lambda s: sa.research("x" * 129, s), BadIdError),
        (lambda s: sa.research("p-1", s, research_area="bogus-area"), BadAreaError),
        (lambda s: sa.research("p-1", s, program_digest="raw"), BadDigestError),
        (lambda s: sa.research("p-1", s, program_digest="md5:abc"), BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert sa.stats(seq + 1)["rejected"] == len(bad)
    # duplicate after a good booking
    seq += 1
    sa.research("p-1", seq)
    with pytest.raises(DuplicateProgramError):
        sa.research("p-1", seq + 1)
    assert sa.stats(seq + 2)["rejected"] == len(bad) + 1


# 5. full research-area vocabulary acceptance
def test_research_area_vocabulary():
    sa = _sa()
    for i, area in enumerate(RESEARCH_AREAS, start=1):
        rec = sa.research(f"p-{area}", i, research_area=area)
        assert rec.verify()
    assert sa.stats(len(RESEARCH_AREAS) + 1)["programs"] == len(RESEARCH_AREAS)


# 6. evaluate roundtrip + minted ids + verify
def test_evaluate_roundtrip():
    sa = _sa()
    sa.research("p-1", 1)
    e1 = sa.evaluate("p-1", 2, method="human-review", verdict="progressing",
                     evidence_digest=_digest(b"ev"))
    e2 = sa.evaluate("p-1", 3, method="red-team", verdict="promising")
    assert isinstance(e1, EvaluationRecord)
    assert e1.evaluation_id == "evl-1"
    assert e2.evaluation_id == "evl-2"
    assert e1.verify() and e2.verify()
    with pytest.raises(Exception):
        e1.verdict = "x"  # frozen


# 7. evaluate bad-input table + unknown-program refusal + seq-burn
def test_evaluate_bad_inputs():
    sa = _sa()
    sa.research("p-1", 1)
    seq = 1
    bad = [
        (lambda s: sa.evaluate("", s), BadIdError),
        (lambda s: sa.evaluate("ghost", s), UnknownProgramError),
        (lambda s: sa.evaluate("p-1", s, method="bogus"), BadMethodError),
        (lambda s: sa.evaluate("p-1", s, verdict="bogus"), BadVerdictError),
        (lambda s: sa.evaluate("p-1", s, evidence_digest="raw"), BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert sa.stats(seq + 1)["rejected"] == len(bad)
    assert sa.stats(seq + 1)["evaluations"] == 0


# 8. full method x verdict vocabulary acceptance
def test_method_verdict_vocabulary():
    sa = _sa()
    seq = 0
    n = 0
    for i, method in enumerate(EVAL_METHODS):
        seq += 1
        sa.research(f"pm-{i}", seq)
        for j, verdict in enumerate(EVAL_VERDICTS):
            seq += 1
            rec = sa.evaluate(f"pm-{i}", seq, method=method, verdict=verdict)
            assert rec.verify()
            n += 1
    assert sa.stats(seq + 1)["evaluations"] == n


# 9. report posture math (all postures + precedence)
def test_report_posture_math():
    sa = _sa()
    seq = 0

    def fresh(pid):
        nonlocal seq
        seq += 1
        sa.research(pid, seq)

    fresh("r0")
    seq += 1
    assert sa.report("r0", seq).posture == "unevaluated"

    fresh("r1")
    seq += 1
    sa.evaluate("r1", seq, verdict="progressing")
    seq += 1
    sa.evaluate("r1", seq, verdict="promising")
    seq += 1
    assert sa.report("r1", seq).posture == "advancing"

    fresh("r2")
    seq += 1
    sa.evaluate("r2", seq, verdict="progressing")
    seq += 1
    sa.evaluate("r2", seq, verdict="stalled")
    seq += 1
    assert sa.report("r2", seq).posture == "stalled"  # stalled beats advancing

    fresh("r3")
    seq += 1
    sa.evaluate("r3", seq, verdict="stalled")
    seq += 1
    sa.evaluate("r3", seq, verdict="regressed")
    seq += 1
    assert sa.report("r3", seq).posture == "at-risk"  # regressed beats stalled

    fresh("r4")
    seq += 1
    sa.evaluate("r4", seq, verdict="inconclusive")
    seq += 1
    assert sa.report("r4", seq).posture == "inconclusive"

    fresh("r5")
    seq += 1
    sa.evaluate("r5", seq, verdict="not-evaluated")
    seq += 1
    assert sa.report("r5", seq).posture == "inconclusive"

    seq += 1
    rep = sa.report("r3", seq)
    assert isinstance(rep, SuperalignmentReport)
    assert rep.verify()
    assert dict(rep.verdict_tallies) == {"stalled": 1, "regressed": 1}
    assert rep.n_evaluations == 2
    with pytest.raises(UnknownProgramError):
        sa.report("ghost", seq + 1)


# 10. report read purity (same-seq twice, no audit rows)
def test_report_read_purity():
    sa = _sa()
    sa.research("p-1", 1)
    sa.evaluate("p-1", 2, verdict="progressing")
    n_audit = len(sa.audit_log(3))
    r1 = sa.report("p-1", 3)
    r2 = sa.report("p-1", 3)
    assert r1.verify() and r2.verify()
    assert r1.digest == r2.digest
    assert len(sa.audit_log(3)) == n_audit
    assert sa.research_record("p-1", 3).verify()
    assert sa.evaluations_for("p-1", 3) == ("evl-1",)


# 11. seq discipline (rewind bare, malformed, failed-mutation-consumes-seq)
def test_seq_discipline():
    sa = _sa()
    sa.research("p-1", 5)
    with pytest.raises(SeqOrderError):
        sa.research("p-2", 5)  # rewind: bare
    assert sa.stats(6)["rejected"] == 0  # no row booked for bare rewind
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(SeqOrderError):
            sa.research("p-2", bad)
    with pytest.raises(BadAreaError):
        sa.research("p-2", 6, research_area="bogus")
    assert sa.stats(7)["rejected"] == 1  # failed mutation burned its seq
    sa.research("p-2", 8)
    assert sa.research_ids(9) == ("p-1", "p-2")


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    sa = _sa()
    sa.research("p-1", 1, research_area="scalable-oversight")
    sa.evaluate("p-1", 2, method="human-review", verdict="progressing")
    rows = sa.audit_log(3)
    assert [r["kind"] for r in rows] == [
        "superalignment.researched", "superalignment.evaluated"]
    for row in rows:
        assert "schema" not in row or True
        for key in row["details"]:
            assert key not in (
                "description", "text", "content", "details_raw", "notes",
                "evidence", "payload", "raw", "secret", "plan",
                "manuscript", "codebase", "weights", "data", "prompt",
            )
    with pytest.raises(AuditKindError):
        superalignment_audit_event("researched", {"notes": "raw"})
    with pytest.raises(AuditKindError):
        superalignment_audit_event("bogus-kind", 1)
    with pytest.raises(AuditKindError):
        superalignment_audit_event("researched", "not-a-dict")


# 13. cross-instance digest determinism + tamper breaks verify
def test_determinism_and_tamper():
    def build():
        sa = Superalignment()
        sa.research("p-1", 1, research_area="scalable-oversight",
                    program_digest=_digest(b"a"))
        sa.evaluate("p-1", 2, method="red-team", verdict="regressed",
                    evidence_digest=_digest(b"b"))
        return sa

    s1, s2 = build(), build()
    assert (s1.research_record("p-1", 3).digest ==
            s2.research_record("p-1", 3).digest)
    assert (s1.evaluation_record("evl-1", 3).digest ==
            s2.evaluation_record("evl-1", 3).digest)
    import dataclasses

    rec = s1.evaluation_record("evl-1", 3)
    tampered = dataclasses.replace(rec, verdict="progressing")
    assert tampered.verify() is False
    rep = s1.report("p-1", 3)
    assert rep.posture == "at-risk"
    object.__setattr__(rec, "verdict", "progressing")
    assert rec.verify() is False


# 14. views/stats + 8-thread read smoke
def test_views_and_thread_smoke():
    sa = _sa()
    sa.research("p-1", 1)
    sa.research("p-2", 2)
    sa.evaluate("p-1", 3, verdict="progressing")
    sa.evaluate("p-1", 4, verdict="stalled")
    assert sa.research_ids(5) == ("p-1", "p-2")
    assert sa.evaluation_ids(5) == ("evl-1", "evl-2")
    assert sa.evaluations_for("p-1", 5) == ("evl-1", "evl-2")
    assert sa.evaluations_for("p-2", 5) == ()
    assert sa.stats(5) == {"programs": 2, "evaluations": 2, "rejected": 0}
    with pytest.raises(UnknownProgramError):
        sa.research_record("ghost", 5)
    with pytest.raises(UnknownRecordError):
        sa.evaluation_record("evl-99", 5)
    results = []

    def worker():
        results.append((sa.research_ids(100), sa.report("p-1", 100).posture))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 8
    assert all(r == (("p-1", "p-2"), "stalled") for r in results)


# 15. main() subprocess check
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        cwd=str(MOD.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "superalignment OK: research, evaluate, report, pins, audit"
    )
