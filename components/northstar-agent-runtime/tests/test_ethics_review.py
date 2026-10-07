"""Targeted tests for ethics_review.py (15 tests)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ethics_review
from ethics_review import (
    AUDIT_SCHEMA,
    CATEGORIES,
    CATEGORY_AI_SAFETY,
    CATEGORY_PRIVACY,
    DECISION_APPROVED,
    DECISION_CONDITIONAL,
    DECISION_DEFERRED,
    DECISION_REJECTED,
    DECISIONS,
    ETHICS_REVIEW_SCHEMA,
    ETHICS_REVIEW_VERSION,
    KIND_ADJUDICATED,
    KIND_APPEALED,
    KIND_REJECTED,
    KIND_SUBMITTED,
    AuditKindError,
    BadCategoryError,
    BadDecisionError,
    BadDigestError,
    BadIdError,
    DuplicateAdjudicationError,
    DuplicateAppealError,
    DuplicateProposalError,
    EthicsReview,
    NoAdjudicationError,
    SeqOrderError,
    UnknownProposalError,
    ethics_review_audit_event,
)

_HERE = Path(__file__).resolve().parent.parent
_GOOD_DIGEST = "sha256:" + "0" * 64
_OTHER_DIGEST = "sha256:" + "f" * 64

_STDLIB_ALLOW = {
    "hashlib", "re", "threading", "dataclasses", "typing",
    "__future__", "canonical_json", "json",
}


def _fresh(seq_start: int = 1) -> EthicsReview:
    return EthicsReview()


def test_version_and_schema_pins():
    assert ETHICS_REVIEW_VERSION == "ethics-review.v1"
    assert ETHICS_REVIEW_SCHEMA == "northstar.ethics-review.v1"
    assert len(CATEGORIES) == 10
    assert CATEGORY_AI_SAFETY in CATEGORIES
    assert len(DECISIONS) == 4
    assert DECISION_APPROVED in DECISIONS


def test_stdlib_only_ast():
    tree = ast.parse((_HERE / "ethics_review.py").read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    unknown = imported - _STDLIB_ALLOW
    assert not unknown, f"non-stdlib imports: {unknown}"


def test_submit_roundtrip_and_verify():
    er = _fresh()
    rec = er.submit("prop-1", CATEGORY_AI_SAFETY, 1, _GOOD_DIGEST)
    assert rec.proposal_id == "prop-1"
    assert rec.category == CATEGORY_AI_SAFETY
    assert rec.summary_digest == _GOOD_DIGEST
    assert rec.verify("prop-1", CATEGORY_AI_SAFETY, _GOOD_DIGEST)
    assert not rec.verify("prop-1", CATEGORY_PRIVACY, _GOOD_DIGEST)
    assert not rec.verify("prop-1", CATEGORY_AI_SAFETY, _OTHER_DIGEST)
    assert not rec.verify("prop-2", CATEGORY_AI_SAFETY, _GOOD_DIGEST)


def test_submit_empty_digest_ok_and_rewind_raises_bare():
    er = _fresh()
    rec = er.submit("prop-1", CATEGORY_PRIVACY, 1)
    assert rec.summary_digest == ""
    assert rec.verify("prop-1", CATEGORY_PRIVACY, "")
    rows_before = len(er.audit_log())
    with pytest.raises(SeqOrderError):
        er.submit("prop-2", CATEGORY_PRIVACY, 1)
    assert len(er.audit_log()) == rows_before


def test_submit_bad_inputs_seq_burn_and_rejected_rows():
    er = _fresh()
    seq = 1
    bad = [
        ("", CATEGORY_AI_SAFETY),  # empty id
        ("has space", CATEGORY_AI_SAFETY),  # whitespace id
        ("x" * 257, CATEGORY_AI_SAFETY),  # too long
        (123, CATEGORY_AI_SAFETY),  # non-str id
        ("prop-1", "not-a-category"),  # bad category
        ("prop-1", True),  # bool category
        ("prop-1", CATEGORY_AI_SAFETY, "not-a-digest"),  # bad digest
        ("prop-1", CATEGORY_AI_SAFETY, True),  # bool digest
    ]
    for case in bad:
        pid, cat = case[0], case[1]
        kw = {"summary_digest": case[2]} if len(case) == 3 else {}
        try:
            er.submit(pid, cat, seq, **kw)
        except (BadIdError, BadCategoryError, BadDigestError):
            seq += 1
        else:
            raise AssertionError(f"case accepted: {case!r}")
    rejected = [r for r in er.audit_log() if r["kind"] == KIND_REJECTED]
    assert len(rejected) == len(bad)


def test_duplicate_submit_refused():
    er = _fresh()
    er.submit("prop-1", CATEGORY_AI_SAFETY, 1, _GOOD_DIGEST)
    with pytest.raises(DuplicateProposalError):
        er.submit("prop-1", CATEGORY_PRIVACY, 2, _GOOD_DIGEST)
    assert len([r for r in er.audit_log() if r["kind"] == KIND_REJECTED]) == 1


def test_adjudicate_roundtrip_minted_ids_verify():
    er = _fresh()
    er.submit("prop-1", CATEGORY_AI_SAFETY, 1, _GOOD_DIGEST)
    er.submit("prop-2", CATEGORY_PRIVACY, 2, _GOOD_DIGEST)
    adj1 = er.adjudicate("prop-1", DECISION_APPROVED, 3)
    adj2 = er.adjudicate("prop-2", DECISION_REJECTED, 4)
    assert adj1.adjudication_id == "adj-1"
    assert adj2.adjudication_id == "adj-2"
    assert adj1.verify("prop-1", DECISION_APPROVED)
    assert not adj1.verify("prop-1", DECISION_REJECTED)
    assert adj2.verify("prop-2", DECISION_REJECTED)


def test_adjudicate_bad_inputs_and_double_adjudication():
    er = _fresh()
    er.submit("prop-1", CATEGORY_AI_SAFETY, 1, _GOOD_DIGEST)
    with pytest.raises(UnknownProposalError):
        er.adjudicate("ghost", DECISION_APPROVED, 2)
    with pytest.raises(BadDecisionError):
        er.adjudicate("prop-1", "maybe", 3)
    with pytest.raises(BadDecisionError):
        er.adjudicate("prop-1", True, 4)
    er.adjudicate("prop-1", DECISION_DEFERRED, 5)
    with pytest.raises(DuplicateAdjudicationError):
        er.adjudicate("prop-1", DECISION_APPROVED, 6)
    rejected = [r for r in er.audit_log() if r["kind"] == KIND_REJECTED]
    assert len(rejected) == 4


def test_appeal_roundtrip_and_requires_adjudication():
    er = _fresh()
    er.submit("prop-1", CATEGORY_AI_SAFETY, 1, _GOOD_DIGEST)
    er.submit("prop-2", CATEGORY_PRIVACY, 2, _GOOD_DIGEST)
    with pytest.raises(NoAdjudicationError):
        er.appeal("prop-1", 3, _GOOD_DIGEST)
    with pytest.raises(UnknownProposalError):
        er.appeal("ghost", 4, _GOOD_DIGEST)
    er.adjudicate("prop-2", DECISION_REJECTED, 5)
    apl = er.appeal("prop-2", 6, _GOOD_DIGEST)
    assert apl.appeal_id == "apl-1"
    assert apl.verify("prop-2", _GOOD_DIGEST)
    assert not apl.verify("prop-2", _OTHER_DIGEST)
    with pytest.raises(DuplicateAppealError):
        er.appeal("prop-2", 7, _GOOD_DIGEST)


def test_proposal_view_and_read_purity():
    er = _fresh()
    er.submit("prop-1", CATEGORY_AI_SAFETY, 1, _GOOD_DIGEST)
    view = er.proposal("prop-1", 2)
    assert view.decision is None
    assert view.appeal_id is None
    assert view.verify("prop-1", CATEGORY_AI_SAFETY, None)
    er.adjudicate("prop-1", DECISION_CONDITIONAL, 3)
    apl = er.appeal("prop-1", 4, _GOOD_DIGEST)
    rows_before = len(er.audit_log())
    view2 = er.proposal("prop-1", 2)  # same seq reused: read purity
    assert view2.decision == DECISION_CONDITIONAL
    assert view2.appeal_id == apl.appeal_id
    assert len(er.audit_log()) == rows_before
    assert er.proposal_ids(2) == ("prop-1",)
    with pytest.raises(UnknownProposalError):
        er.proposal("ghost", 2)


def test_seq_discipline_malformed_and_rewind():
    er = _fresh()
    for bad in (True, "1", 1.5, None, -1):
        with pytest.raises(SeqOrderError):
            er.submit("p", CATEGORY_AI_SAFETY, bad, _GOOD_DIGEST)
    assert er.stats()["proposals"] == 0
    er.submit("prop-1", CATEGORY_AI_SAFETY, 1, _GOOD_DIGEST)
    with pytest.raises(SeqOrderError):
        er.submit("prop-2", CATEGORY_AI_SAFETY, 1, _GOOD_DIGEST)
    # views validate shape only: same seq legal, no audit rows
    rows_before = len(er.audit_log())
    er.proposal("prop-1", 1)
    assert len(er.audit_log()) == rows_before


def test_audit_shapes_and_leak_ban_and_bad_kind():
    er = _fresh()
    er.submit("prop-1", CATEGORY_AI_SAFETY, 1, _GOOD_DIGEST)
    er.adjudicate("prop-1", DECISION_APPROVED, 2)
    er.appeal("prop-1", 3, _OTHER_DIGEST)
    log = er.audit_log()
    kinds = [r["kind"] for r in log]
    assert kinds == [KIND_SUBMITTED, KIND_ADJUDICATED, KIND_APPEALED]
    for row in log:
        assert row["schema"] == AUDIT_SCHEMA
        assert row["module"] == ETHICS_REVIEW_VERSION
    # no raw text crosses the boundary: digests are pins, content absent
    blob = repr(log)
    assert "secret" not in blob
    with pytest.raises(AuditKindError):
        ethics_review_audit_event("nope", {}, 1)
    with pytest.raises(AuditKindError):
        ethics_review_audit_event(KIND_SUBMITTED, {"text": "raw"}, 1)
    with pytest.raises(AuditKindError):
        ethics_review_audit_event(KIND_ADJUDICATED,
                                  {"summary": "raw"}, 1)
    with pytest.raises(AuditKindError):
        ethics_review_audit_event(KIND_APPEALED,
                                  {"grounds": "raw"}, 1)


def test_frozen_records_and_cross_instance_determinism():
    import dataclasses
    er = _fresh()
    rec = er.submit("prop-1", CATEGORY_AI_SAFETY, 1, _GOOD_DIGEST)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.category = "x"  # type: ignore[misc]
    er2 = EthicsReview()
    rec2 = er2.submit("prop-1", CATEGORY_AI_SAFETY, 1, _GOOD_DIGEST)
    assert rec.digest == rec2.digest
    adj1 = er.adjudicate("prop-1", DECISION_APPROVED, 2)
    adj2 = er2.adjudicate("prop-1", DECISION_APPROVED, 2)
    assert adj1.digest == adj2.digest
    with threading.Lock():
        pass
    done = []
    def read(er_: EthicsReview):
        for _ in range(50):
            er_.proposal("prop-1", 1)
        done.append(True)
    threads = [threading.Thread(target=read, args=(er,)) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(done) == 8


def test_main_subprocess_check():
    r = subprocess.run(
        [sys.executable, str(_HERE / "ethics_review.py")],
        capture_output=True, text=True, cwd=str(_HERE))
    assert r.returncode == 0, r.stderr
    assert "ethics-review OK" in r.stdout


def test_stats_counters():
    er = _fresh()
    assert er.stats() == {"proposals": 0, "adjudications": 0,
                          "appeals": 0, "audit_rows": 0}
    er.submit("prop-1", CATEGORY_AI_SAFETY, 1, _GOOD_DIGEST)
    er.submit("prop-2", CATEGORY_PRIVACY, 2)
    er.adjudicate("prop-1", DECISION_APPROVED, 3)
    er.appeal("prop-1", 4, _GOOD_DIGEST)
    stats = er.stats()
    assert stats["proposals"] == 2
    assert stats["adjudications"] == 1
    assert stats["appeals"] == 1
    assert stats["audit_rows"] == 4
