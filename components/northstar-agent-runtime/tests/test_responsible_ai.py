"""Tests for responsible_ai (responsible-AI governance decision ledger, Simulated)."""

import ast
import hashlib
import subprocess
import sys
import threading

import pytest

from responsible_ai import (
    RESPONSIBLE_AI_VERSION,
    RESPONSIBLE_AI_SCHEMA,
    AUDIT_SCHEMA,
    KIND_ASSESSED,
    KIND_REJECTED,
    DIM_SAFETY,
    DIM_FAIRNESS,
    DIM_PRIVACY,
    DIM_TRANSPARENCY,
    DIM_ACCOUNTABILITY,
    DIM_HUMAN_OVERSIGHT,
    DIM_ROBUSTNESS,
    DIM_SUSTAINABILITY,
    FINDING_MEETS,
    FINDING_GAP,
    FINDING_NONCOMPLIANT,
    FINDING_MITIGATED,
    FINDING_IN_PROGRESS,
    FINDING_NOT_ASSESSED,
    POSTURE_UNASSESSED,
    POSTURE_NONCOMPLIANT,
    POSTURE_GAP_OPEN,
    POSTURE_IN_PROGRESS,
    POSTURE_MEETS,
    VERDICT_VERIFIED,
    VERDICT_TAMPERED,
    ResponsibleAIError,
    BadSystemError,
    BadDimensionError,
    BadFindingError,
    BadDigestError,
    UnknownSystemError,
    UnknownAssessmentError,
    SeqOrderError,
    AuditKindError,
    AssessmentRecord,
    VerificationReport,
    EvaluationReport,
    ResponsibleAI,
    responsible_ai_audit_event,
    stdlib_only,
)

_DIGEST = "sha256:" + "a" * 64


def _ledger():
    return ResponsibleAI()


# 1. version / schema / vocabulary pins
def test_pins():
    assert RESPONSIBLE_AI_VERSION == "responsible-ai.v1"
    assert RESPONSIBLE_AI_SCHEMA == "northstar.responsible-ai.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert KIND_ASSESSED == "responsible-ai.assessed"
    assert KIND_REJECTED == "responsible-ai.rejected"
    assert (DIM_SAFETY, DIM_FAIRNESS, DIM_PRIVACY, DIM_TRANSPARENCY,
            DIM_ACCOUNTABILITY, DIM_HUMAN_OVERSIGHT, DIM_ROBUSTNESS,
            DIM_SUSTAINABILITY) == (
        "safety", "fairness", "privacy", "transparency",
        "accountability", "human-oversight", "robustness", "sustainability",
    )
    assert (FINDING_MEETS, FINDING_GAP, FINDING_NONCOMPLIANT,
            FINDING_MITIGATED, FINDING_IN_PROGRESS,
            FINDING_NOT_ASSESSED) == (
        "meets-requirements", "gap-identified", "noncompliant",
        "mitigated", "in-progress", "not-assessed",
    )
    assert (POSTURE_UNASSESSED, POSTURE_NONCOMPLIANT, POSTURE_GAP_OPEN,
            POSTURE_IN_PROGRESS, POSTURE_MEETS) == (
        "unassessed", "noncompliant", "gap-open", "in-progress",
        "meets-requirements",
    )
    assert (VERDICT_VERIFIED, VERDICT_TAMPERED) == ("verified", "tampered")


# 2. stdlib-only AST self-check
def test_stdlib_only():
    assert stdlib_only() is True
    tree = ast.parse(open("responsible_ai.py", encoding="utf-8").read())
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            mods.add((node.module or "").split(".")[0])
    assert mods <= {"__future__", "ast", "canonical_json", "dataclasses", "hashlib",
                    "json", "pathlib", "threading", "typing"}


# 3. assess roundtrip + verify + frozen-ness
def test_assess_roundtrip_verify_frozen():
    ra = _ledger()
    rec = ra.assess("system-a", 1, dimension="safety",
                    finding="meets-requirements", assessment_digest=_DIGEST)
    assert isinstance(rec, AssessmentRecord)
    assert rec.assessment_id == "asm-1"
    assert rec.system_id == "system-a"
    assert rec.schema == RESPONSIBLE_AI_SCHEMA
    assert rec.verify() is True
    got = ra.assessment_record("asm-1", 2)
    assert got == rec
    assert ra.system_ids(3) == ("system-a",)
    assert ra.assessment_ids(4) == ("asm-1",)
    assert ra.assessments_for("system-a", 5) == (rec,)
    with pytest.raises(Exception):
        rec.finding = "noncompliant"  # frozen dataclass


# 4. assess bad-input table + seq-burn + rejected-row accounting
def test_assess_bad_inputs_burn_seq():
    ra = _ledger()
    seq = 1
    bad = [
        ({"system_id": ""}, BadSystemError),
        ({"system_id": 123}, BadSystemError),
        ({"system_id": "x" * 300}, BadSystemError),
        ({"system_id": "sys", "dimension": "ethics"}, BadDimensionError),
        ({"system_id": "sys", "dimension": 42}, BadDimensionError),
        ({"system_id": "sys", "finding": "awesome"}, BadFindingError),
        ({"system_id": "sys", "finding": True}, BadFindingError),
        ({"system_id": "sys", "assessment_digest": "no-prefix"}, BadDigestError),
        ({"system_id": "sys", "assessment_digest": 7}, BadDigestError),
    ]
    for kwargs, exc in bad:
        with pytest.raises(exc):
            ra.assess(seq=seq, **kwargs)
        seq += 1
    rejected = [e for e in ra.audit_log() if e["kind"] == KIND_REJECTED]
    assert len(rejected) == len(bad)
    # seq was consumed by the failures: next claim must be strictly greater
    with pytest.raises(SeqOrderError):
        ra.assess("sys", seq - 1)
    rec = ra.assess("sys", seq)
    assert rec.assessment_id == "asm-1"


# 5. full 8-dimension vocabulary acceptance
def test_all_dimensions_accepted():
    ra = _ledger()
    dims = ["safety", "fairness", "privacy", "transparency", "accountability",
            "human-oversight", "robustness", "sustainability"]
    for i, dim in enumerate(dims):
        rec = ra.assess("sys", i + 1, dimension=dim)
        assert rec.dimension == dim
        assert rec.verify() is True
    assert ra.stats(9)["assessments"] == 8
    assert ra.system_ids(9) == ("sys",)


# 6. full 6-finding vocabulary acceptance
def test_all_findings_accepted():
    ra = _ledger()
    findings = ["meets-requirements", "gap-identified", "noncompliant",
                "mitigated", "in-progress", "not-assessed"]
    for i, finding in enumerate(findings):
        rec = ra.assess("sys", i + 1, finding=finding)
        assert rec.finding == finding
        assert rec.verify() is True
    ev = ra.evaluate(7, "sys")
    assert ev.posture == "noncompliant"  # outranks all others
    assert dict(ev.by_finding) == {f: 1 for f in findings}


# 7. verify roundtrip + tamper-as-data + unknown refusal
def test_verify_roundtrip_tamper_unknown():
    ra = _ledger()
    rec = ra.assess("sys", 1, finding="meets-requirements",
                    assessment_digest=_DIGEST)
    report = ra.verify("asm-1", 2)
    assert isinstance(report, VerificationReport)
    assert report.verdict == "verified"
    assert report.verify() is True
    # tamper with the record: reported as data, never raised
    object.__setattr__(rec, "finding", "noncompliant")
    assert rec.verify() is False
    report2 = ra.verify("asm-1", 3)
    assert report2.verdict == "tampered"
    assert report2.verify() is True
    ev = ra.evaluate(4, "sys")
    assert ev.integrity_ok is False
    with pytest.raises(UnknownAssessmentError):
        ra.verify("asm-99", 5)


# 8. verify read purity: same seq twice, no audit rows
def test_verify_read_purity():
    ra = _ledger()
    ra.assess("sys", 1, finding="mitigated")
    n_before = len(ra.audit_log())
    r1 = ra.verify("asm-1", 2)
    r2 = ra.verify("asm-1", 2)  # same seq again: reads do not consume seqs
    assert r1.verdict == "verified" == r2.verdict
    assert len(ra.audit_log()) == n_before
    # reads do not advance the ledger's last seq
    assert ra.stats(2)["last_seq"] == 1


# 9. evaluate posture math: all 5 postures + precedence
def test_evaluate_posture_math():
    ra = _ledger()
    # meets-requirements / mitigated -> meets-requirements
    ra.assess("s1", 1, dimension="safety", finding="meets-requirements")
    ra.assess("s1", 2, dimension="fairness", finding="mitigated")
    assert ra.evaluate(3, "s1").posture == "meets-requirements"
    # in-progress joins -> in-progress
    ra.assess("s2", 4, dimension="privacy", finding="meets-requirements")
    ra.assess("s2", 5, dimension="robustness", finding="in-progress")
    assert ra.evaluate(6, "s2").posture == "in-progress"
    # gap joins -> gap-open outranks in-progress
    ra.assess("s3", 7, dimension="transparency", finding="in-progress")
    ra.assess("s3", 8, dimension="accountability", finding="gap-identified")
    assert ra.evaluate(9, "s3").posture == "gap-open"
    # noncompliant joins -> noncompliant outranks gap-open
    ra.assess("s4", 10, dimension="human-oversight", finding="gap-identified")
    ra.assess("s4", 11, dimension="sustainability", finding="noncompliant")
    assert ra.evaluate(12, "s4").posture == "noncompliant"
    # whole-ledger: noncompliant wins globally
    whole = ra.evaluate(13)
    assert whole.posture == "noncompliant"
    assert whole.verify() is True
    assert whole.n_assessments == 8
    assert dict(whole.by_dimension)["privacy"] == 1


# 10. evaluate on empty ledger / all not-assessed -> unassessed
def test_evaluate_unassessed():
    ra = _ledger()
    ev = ra.evaluate(1)
    assert ev.posture == "unassessed"
    assert ev.n_assessments == 0
    assert ev.integrity_ok is True
    assert ev.verify() is True
    ra.assess("s9", 2, dimension="safety", finding="not-assessed")
    ev2 = ra.evaluate(3, "s9")
    assert ev2.posture == "unassessed"
    assert ev2.n_assessments == 1


# 11. evaluate unknown system refusal (fail-closed, pure read: no rejected row)
def test_evaluate_unknown_system():
    ra = _ledger()
    ra.assess("sys", 1, finding="meets-requirements")
    n_before = len(ra.audit_log())
    with pytest.raises(UnknownSystemError):
        ra.evaluate(2, "ghost")
    assert len(ra.audit_log()) == n_before
    ev = ra.evaluate(2, "sys")
    assert ev.system_scope == "sys"
    assert ev.posture == "meets-requirements"


# 12. evaluate read purity: same seq twice, no rows, no seq consumption
def test_evaluate_read_purity():
    ra = _ledger()
    ra.assess("sys", 1, finding="meets-requirements")
    n_before = len(ra.audit_log())
    e1 = ra.evaluate(2, "sys")
    e2 = ra.evaluate(2, "sys")
    assert e1 == e2
    assert e1.verify() is True
    assert len(ra.audit_log()) == n_before
    assert ra.stats(2)["last_seq"] == 1


# 13. seq discipline: rewind bare, malformed seqs, failed mutations consume
def test_seq_discipline():
    ra = _ledger()
    with pytest.raises(SeqOrderError):
        ra.assess("sys", 0)  # genesis rewind: bare, zero rows
    assert len(ra.audit_log()) == 0
    for bad_seq in [True, 1.5, "3", None, -2**70]:
        if isinstance(bad_seq, bool) or not isinstance(bad_seq, int):
            with pytest.raises(SeqOrderError):
                ra.evaluate(bad_seq)
    ra.assess("sys", 1, finding="meets-requirements")
    with pytest.raises(SeqOrderError):
        ra.assess("sys", 1)  # rewind on a mutation: bare, no rows
    assert len([e for e in ra.audit_log() if e["kind"] == KIND_REJECTED]) == 0
    with pytest.raises(BadDimensionError):
        ra.assess("sys", 2, dimension="ethics")  # failed mutation burns seq
    assert ra.stats(3)["last_seq"] == 2
    rejected = [e for e in ra.audit_log() if e["kind"] == KIND_REJECTED]
    assert len(rejected) == 1
    assert rejected[0]["detail"]["error"] == "BadDimensionError"
    rec = ra.assess("sys", 3)
    assert rec.assessment_id == "asm-2"


# 14. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    ra = _ledger()
    ra.assess("sys", 1, dimension="privacy", finding="gap-identified",
              assessment_digest=_DIGEST)
    events = ra.audit_log()
    assert len(events) == 1
    ev = events[0]
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["module"] == "responsible-ai"
    assert ev["kind"] == "responsible-ai.assessed"
    assert ev["seq"] == 1
    assert ev["detail"]["dimension"] == "privacy"  # pinned vocab may cross
    assert ev["detail"]["assessment_digest"] == _DIGEST  # pins only
    assert "digest" in ev
    with pytest.raises(AuditKindError):
        responsible_ai_audit_event("responsible-ai.assessed", 2,
                                   rationale="secret text")
    with pytest.raises(AuditKindError):
        responsible_ai_audit_event("responsible-ai.assessed", 2,
                                   evidence="raw evidence")
    with pytest.raises(AuditKindError):
        responsible_ai_audit_event("responsible-ai.nonsense", 2)


# 15. cross-instance determinism + 8-thread read smoke + main() subprocess
def test_determinism_concurrency_main():
    def build():
        ra = _ledger()
        ra.assess("sys", 1, dimension="safety",
                  finding="meets-requirements", assessment_digest=_DIGEST)
        ra.assess("sys", 2, dimension="fairness", finding="mitigated")
        return ra

    ra1, ra2 = build(), build()
    assert ra1.assessment_record("asm-1", 3).digest == \
        ra2.assessment_record("asm-1", 3).digest
    assert ra1.evaluate(3, "sys").digest == ra2.evaluate(3, "sys").digest
    ra = ra1
    assert ra.stats(3) == {"systems": 1, "assessments": 2,
                           "rejected": 0, "last_seq": 2}
    results = []

    def worker():
        results.append(ra.assessment_ids(50))
        results.append(ra.evaluate(50, "sys").posture)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r == ("asm-1", "asm-2") or r == "meets-requirements"
               for r in results)
    assert ra.assessment_record("nope", 60) is None
    assert ra.assessments_for("unknown-sys", 60) == ()
    proc = subprocess.run(
        [sys.executable, "responsible_ai.py"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "responsible-ai OK: assess, verify, evaluate, pins"
    )
