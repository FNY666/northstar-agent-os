"""Tests for reflection.py (self-critique / revise / score bookkeeping ledger)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import reflection as rf
from reflection import (
    Reflection,
    reflection_audit_event,
    REFLECTION_VERSION,
    REFLECTION_SCHEMA,
    AUDIT_SCHEMA,
    KIND_SUBMITTED,
    KIND_CRITIQUE,
    KIND_REVISION,
    KIND_SCORE,
    KIND_REJECTED,
    ReflectionError,
    BadDraftError,
    DuplicateDraftError,
    UnknownDraftError,
    BadDigestError,
    BadIssueError,
    BadVerdictError,
    UnknownCritiqueError,
    BadRevisionError,
    BadScoreError,
    SeqOrderError,
    AuditKindError,
)

MODULE = Path(rf.__file__)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def fresh():
    return Reflection()


def ledger_with_draft():
    m = fresh()
    m.submit("draft-1", DIGEST_A, 1)
    return m


# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert REFLECTION_VERSION == "reflection.v1"
    assert REFLECTION_SCHEMA == "northstar.reflection.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "fractions",
        "__future__",
        "canonical_json",
        "json",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= allowed, f"non-stdlib imports: {imports - allowed}"


def test_submit_roundtrip():
    m = fresh()
    rec = m.submit("draft-1", DIGEST_A, 1)
    assert rec.draft_id == "draft-1"
    assert rec.output_digest == DIGEST_A
    assert rec.digest.startswith("sha256:")
    assert rec.seq == 1
    assert rec.verify()
    assert rec.schema == REFLECTION_SCHEMA
    assert m.draft_ids(1) == ("draft-1",)
    assert m.draft("draft-1", 1) == rec
    assert m.draft("nope", 1) is None
    with pytest.raises(Exception):
        rec.draft_id = "x"  # frozen


def test_submit_bad_inputs():
    m = fresh()
    for bad in ("", 123, None, True, "x" * 300):
        with pytest.raises(ReflectionError):
            m.submit(bad, DIGEST_A, m._seq + 1)
    for bad_digest in ("", "abc", "md5:deadbeef", None, 42, True):
        with pytest.raises(ReflectionError):
            m.submit("draft-x", bad_digest, m._seq + 1)
    # each failed mutation consumed its seq and booked a rejected audit row
    rejected = [e for e in m.audit_log() if e["kind"] == KIND_REJECTED]
    assert len(rejected) == 11
    m.submit("draft-1", DIGEST_A, m._seq + 1)
    with pytest.raises(DuplicateDraftError):
        m.submit("draft-1", DIGEST_A, m._seq + 1)


def test_critique_roundtrip():
    m = ledger_with_draft()
    rec = m.critique(
        "draft-1",
        2,
        issues=("hallucination", "formatting"),
        feedback_digest=DIGEST_B,
        verdict="needs-revision",
    )
    assert rec.critique_id == "crit-1"
    assert rec.draft_id == "draft-1"
    assert rec.issues == ("formatting", "hallucination")  # sorted
    assert rec.feedback_digest == DIGEST_B
    assert rec.verdict == "needs-revision"
    assert rec.verify()
    assert m.critiques_for("draft-1", 2) == (rec,)
    assert m.critiques_for("unknown", 2) == ()


def test_critique_bad_issues():
    m = ledger_with_draft()
    for bad in ("hallucination", 42, None, True, [None], ["nope"], ["hallucination", "hallucination"]):
        with pytest.raises(ReflectionError):
            m.critique("draft-1", m._seq + 1, issues=bad)
    with pytest.raises(UnknownDraftError):
        m.critique("nope", m._seq + 1, issues=("incomplete",))
    # empty issues must accept; non-empty issues may not accept
    with pytest.raises(BadVerdictError):
        m.critique("draft-1", m._seq + 1, issues=(), verdict="needs-revision")
    with pytest.raises(BadVerdictError):
        m.critique("draft-1", m._seq + 1, issues=("off-task",), verdict="accept")
    with pytest.raises(BadVerdictError):
        m.critique("draft-1", m._seq + 1, issues=(), verdict="maybe")
    ok = m.critique("draft-1", m._seq + 1, issues=(), verdict="accept")
    assert ok.verify() and ok.verdict == "accept"


def test_revise_roundtrip_and_linkage():
    m = ledger_with_draft()
    crit = m.critique("draft-1", 2, issues=("reasoning-gap",), verdict="needs-revision")
    rev = m.revise("draft-1", 3, revision_digest=DIGEST_C, parent_critique_id=crit.critique_id)
    assert rev.revision_id == "rev-1"
    assert rev.parent_critique_id == crit.critique_id
    assert rev.verify()
    assert m.revisions_for("draft-1", 3) == (rev,)
    rev2 = m.revise("draft-1", 4, revision_digest=DIGEST_A, parent_critique_id=crit.critique_id)
    assert rev2.revision_id == "rev-2"


def test_revise_bad_inputs():
    m = ledger_with_draft()
    crit = m.critique("draft-1", 2, issues=("formatting",), verdict="reject")
    with pytest.raises(UnknownDraftError):
        m.revise("nope", m._seq + 1, revision_digest=DIGEST_C, parent_critique_id=crit.critique_id)
    with pytest.raises(UnknownCritiqueError):
        m.revise("draft-1", m._seq + 1, revision_digest=DIGEST_C, parent_critique_id="crit-99")
    with pytest.raises(BadRevisionError):
        m.revise("draft-1", m._seq + 1, revision_digest=DIGEST_C, parent_critique_id="")
    # parent critique from another draft is refused
    m.submit("draft-2", DIGEST_B, m._seq + 1)
    with pytest.raises(UnknownCritiqueError):
        m.revise("draft-2", m._seq + 1, revision_digest=DIGEST_C, parent_critique_id=crit.critique_id)
    with pytest.raises(BadDigestError):
        m.revise("draft-1", m._seq + 1, revision_digest="not-a-digest", parent_critique_id=crit.critique_id)
    with pytest.raises(BadRevisionError):
        m.revise("draft-1", m._seq + 1, revision_digest=DIGEST_C, parent_critique_id=None)


def test_score_roundtrip_and_math():
    m = ledger_with_draft()
    rec = m.score("draft-1", 2, 90, 80, 70)
    assert rec.score_id == "score-1"
    # (5*90 + 3*80 + 2*70)/10 = 83 exactly
    assert rec.composite_text == "83/1"
    assert rec.composite_floor == 83
    assert rec.verdict == "acceptable"
    assert rec.verify()
    strong = m.score("draft-1", 3, 100, 100, 100)
    assert strong.composite_text == "100/1" and strong.verdict == "strong"
    weak = m.score("draft-1", 4, 0, 0, 0)
    assert weak.composite_text == "0/1" and weak.verdict == "weak"
    frac = m.score("draft-1", 5, 91, 82, 73)
    # (455 + 246 + 146)/10 = 847/10
    assert frac.composite_text == "847/10" and frac.composite_floor == 84
    assert frac.verdict == "acceptable"
    assert m.score_history("draft-1", 5) == (rec, strong, weak, frac)


def test_score_bad_components():
    m = ledger_with_draft()
    for bad in (True, 101, -1, 50.5, "90", None):
        with pytest.raises(BadScoreError):
            m.score("draft-1", m._seq + 1, bad, 80, 70)
        with pytest.raises(BadScoreError):
            m.score("draft-1", m._seq + 1, 90, bad, 70)
        with pytest.raises(BadScoreError):
            m.score("draft-1", m._seq + 1, 90, 80, bad)
    with pytest.raises(UnknownDraftError):
        m.score("nope", m._seq + 1, 90, 80, 70)


def test_seq_ordering_and_failed_mutation_consumes_seq():
    m = fresh()
    m.submit("d1", DIGEST_A, 5)
    for bad in (5, 4, 0, -1, "6", 6.0, None, True):
        with pytest.raises(SeqOrderError):
            m.submit("dx", DIGEST_A, bad)
    # seq not consumed by malformed/rewind attempts
    assert m._seq == 5
    m.submit("d2", DIGEST_A, 6)
    assert m._seq == 6
    # failed mutation consumes the seq and books a rejected row
    with pytest.raises(DuplicateDraftError):
        m.submit("d2", DIGEST_A, 7)
    assert m._seq == 7
    rejected = [e for e in m.audit_log() if e["kind"] == KIND_REJECTED]
    assert len(rejected) == 1
    assert rejected[0]["seq"] == 7
    assert rejected[0]["detail"]["error"] == "DuplicateDraftError"


def test_views_are_pure_reads():
    m = ledger_with_draft()
    before = len(m.audit_log())
    last = m._seq
    m.draft("draft-1", last)
    m.draft_ids(last)
    m.critiques_for("draft-1", last)
    m.revisions_for("draft-1", last)
    m.score_history("draft-1", last)
    stats = m.stats(last)
    assert stats == {"drafts": 1, "critiques": 0, "revisions": 0, "scores": 0, "last_seq": last}
    assert len(m.audit_log()) == before  # no audit rows, no seq consumed
    assert m._seq == last
    with pytest.raises(SeqOrderError):
        m.stats("bad")


def test_audit_shapes_and_leak_ban():
    m = ledger_with_draft()
    m.critique("draft-1", 2, issues=("incomplete",), verdict="reject")
    log = m.audit_log()
    kinds = [e["kind"] for e in log]
    assert kinds == [KIND_SUBMITTED, KIND_CRITIQUE]
    for e in log:
        assert e["schema"] == AUDIT_SCHEMA
        assert e["module"] == "reflection"
        assert e["digest"].startswith("sha256:")
        detail = e["detail"]
        for banned in ("output", "feedback", "text", "content", "payload", "raw", "body",
                       "value", "message", "revision", "draft", "review"):
            assert banned not in detail, f"leak: {banned}"
    # banned keys refused at the builder boundary
    with pytest.raises(AuditKindError):
        reflection_audit_event(KIND_SUBMITTED, 1, output="secret")
    with pytest.raises(AuditKindError):
        reflection_audit_event(KIND_CRITIQUE, 1, feedback="secret")
    with pytest.raises(AuditKindError):
        reflection_audit_event("nope.kind", 1)
    # raw texts never cross the audit boundary: full pipeline
    m.critique("draft-1", 3, issues=("off-task",), feedback_digest=DIGEST_B, verdict="needs-revision")
    crit = m.critique("draft-1", 4, issues=("formatting",), verdict="needs-revision")
    m.revise("draft-1", 5, revision_digest=DIGEST_C, parent_critique_id=crit.critique_id)
    m.score("draft-1", 6, 80, 70, 60)
    blob = repr(m.audit_log())
    # issue names stay in records (digest-pinned); the audit boundary carries
    # issue_count only — even issue names do not cross it
    assert "incomplete" not in blob and "off-task" not in blob
    assert "secret" not in blob


def test_cross_instance_determinism():
    def run():
        m = Reflection()
        m.submit("draft-1", DIGEST_A, 1)
        c = m.critique("draft-1", 2, issues=("hallucination",), verdict="reject")
        m.revise("draft-1", 3, revision_digest=DIGEST_B, parent_critique_id=c.critique_id)
        m.score("draft-1", 4, 88, 77, 66)
        return m

    a, b = run(), run()
    assert a.critiques_for("draft-1", 4)[0].digest == b.critiques_for("draft-1", 4)[0].digest
    assert a.revisions_for("draft-1", 4)[0].digest == b.revisions_for("draft-1", 4)[0].digest
    assert a.score_history("draft-1", 4)[0].digest == b.score_history("draft-1", 4)[0].digest
    assert a.audit_log()[0]["digest"] == b.audit_log()[0]["digest"]


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        cwd=str(MODULE.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "reflection OK: submit, critique, revise, score, pins, audit" in proc.stdout
