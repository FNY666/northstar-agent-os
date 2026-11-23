"""Tests for constitutional_ai.py: principle-directed self-critique/revise ledger."""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import constitutional_ai as cai
from constitutional_ai import (
    CAT_HARMLESSNESS,
    CAT_HELPFULNESS,
    CAT_HONESTY,
    CONSTITUTIONAL_AI_SCHEMA,
    CONSTITUTIONAL_AI_VERSION,
    KIND_CRITIQUE,
    KIND_DRAFT,
    KIND_PRINCIPLE,
    KIND_REJECTED,
    KIND_REVISION,
    VERDICT_COMPLIANT,
    VERDICT_NEEDS_REVISION,
    VERDICT_VIOLATION,
    BadCategoryError,
    BadCritiqueError,
    BadDigestError,
    ConstitutionalAI,
    ConstitutionalAIError,
    CrossDraftError,
    DuplicateDraftError,
    DuplicatePrincipleError,
    SeqOrderError,
    UnknownCritiqueError,
    UnknownDraftError,
    UnknownPrincipleError,
    constitutional_ai_audit_event,
)

_HERE = Path(__file__).resolve().parent.parent
_STDLIB_ALLOWLIST = frozenset(
    {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
        "json",
    }
)


def _pin(parts):
    return cai._digest_pin(tuple(parts), "test")


def _new() -> ConstitutionalAI:
    return ConstitutionalAI()


def _seed(ledger: ConstitutionalAI, start: int = 0) -> int:
    """Book one principle + one draft; return next free seq."""
    seq = start
    ledger.principle("p-honesty", CAT_HONESTY, _pin(("statement",)), seq + 1)
    ledger.submit("draft-1", _pin(("output",)), seq + 2)
    return seq + 2


# 1 ------------------------------------------------------------------------


def test_version_and_schema_pins():
    ledger = _new()
    rec = ledger.principle("p1", CAT_HARMLESSNESS, _pin(("s",)), 1)
    assert rec.version == CONSTITUTIONAL_AI_VERSION
    assert rec.schema == CONSTITUTIONAL_AI_SCHEMA
    assert rec.verify()
    d = ledger.submit("d1", _pin(("o",)), 2)
    assert d.version == CONSTITUTIONAL_AI_VERSION and d.schema == CONSTITUTIONAL_AI_SCHEMA
    c = ledger.critique("d1", "p1", 3)
    assert c.version == CONSTITUTIONAL_AI_VERSION and c.schema == CONSTITUTIONAL_AI_SCHEMA
    r = ledger.revise("d1", 4, _pin(("r",)), c.critique_id)
    assert r.version == CONSTITUTIONAL_AI_VERSION and r.schema == CONSTITUTIONAL_AI_SCHEMA


# 2 ------------------------------------------------------------------------


def test_stdlib_only_ast():
    src = (_HERE / "constitutional_ai.py").read_text()
    tree = ast.parse(src)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add((node.module or "").split(".")[0])
    assert imported <= _STDLIB_ALLOWLIST, f"non-stdlib imports: {imported - _STDLIB_ALLOWLIST}"


# 3 ------------------------------------------------------------------------


def test_principle_roundtrip_verify():
    ledger = _new()
    rec = ledger.principle("p-help", CAT_HELPFULNESS, _pin(("st",)), 1)
    assert rec.verify()
    assert ledger.principle_record("p-help", 2) == rec
    assert ledger.principle_ids(3) == ("p-help",)
    tampered = cai.PrincipleRecord(
        principle_id="p-help",
        category=CAT_HARMLESSNESS,  # changed
        statement_digest=rec.statement_digest,
        seq=1,
        digest=rec.digest,
    )
    assert not tampered.verify()


# 4 ------------------------------------------------------------------------


def test_principle_duplicate_and_bad_inputs():
    ledger = _new()
    seq = 0

    def nxt():
        nonlocal seq
        seq += 1
        return seq

    ledger.principle("p1", CAT_HONESTY, _pin(("s",)), nxt())
    with pytest.raises(DuplicatePrincipleError):
        ledger.principle("p1", CAT_HONESTY, _pin(("s",)), nxt())  # dup consumes seq
    bad = ["", 123, True, "x" * 129, None]
    rejected = 0
    for v in bad:
        with pytest.raises(ConstitutionalAIError):
            ledger.principle(v, CAT_HONESTY, _pin(("s",)), nxt())
        rejected += 1
    for v in ["nope", 123, None]:
        with pytest.raises(ConstitutionalAIError):
            ledger.principle(f"p-{v}-{rejected}", v, _pin(("s",)), nxt())
        rejected += 1
    for v in ["plain", "", 123]:
        with pytest.raises(ConstitutionalAIError):
            ledger.principle(f"p-d-{rejected}", CAT_HONESTY, v, nxt())
        rejected += 1
    events = ledger.audit_log(nxt())
    kinds = [e["kind"] for e in events]
    assert kinds.count(KIND_REJECTED) == 1 + rejected
    assert kinds.count(KIND_PRINCIPLE) == 1


# 5 ------------------------------------------------------------------------


def test_category_vocabulary():
    ledger = _new()
    ledger.principle("p1", CAT_HELPFULNESS, _pin(("a",)), 1)
    ledger.principle("p2", CAT_HONESTY, _pin(("b",)), 2)
    ledger.principle("p3", CAT_HARMLESSNESS, _pin(("c",)), 3)
    assert ledger.principle_ids(4) == ("p1", "p2", "p3")
    with pytest.raises(BadCategoryError):
        ledger.principle("p4", "kindness", _pin(("d",)), 5)


# 6 ------------------------------------------------------------------------


def test_submit_draft_roundtrip():
    ledger = _new()
    rec = ledger.submit("draft-1", _pin(("o1",)), 1)
    assert rec.verify()
    assert ledger.draft_record("draft-1", 2) == rec
    with pytest.raises(DuplicateDraftError):
        ledger.submit("draft-1", _pin(("o2",)), 3)
    with pytest.raises(ConstitutionalAIError):
        ledger.submit("", _pin(("o",)), 4)
    with pytest.raises(BadDigestError):
        ledger.submit("draft-2", "not-a-digest", 5)
    assert ledger.stats(6)["drafts"] == 1


# 7 ------------------------------------------------------------------------


def test_critique_roundtrip_verify():
    ledger = _new()
    seq = _seed(ledger)
    c = ledger.critique("draft-1", "p-honesty", seq + 1, verdict=VERDICT_VIOLATION)
    assert c.verify()
    assert c.critique_id == "crit-1"
    assert ledger.critique_record("crit-1", seq + 2) == c
    assert ledger.critiques_for("draft-1", seq + 3) == ("crit-1",)
    c2 = ledger.critique(
        "draft-1", "p-honesty", seq + 4, issue_digest=_pin(("issue",))
    )
    assert c2.critique_id == "crit-2"
    assert c2.verify()


# 8 ------------------------------------------------------------------------


def test_critique_verdict_vocabulary():
    ledger = _new()
    seq = _seed(ledger)
    for i, verdict in enumerate((VERDICT_COMPLIANT, VERDICT_VIOLATION, VERDICT_NEEDS_REVISION)):
        c = ledger.critique("draft-1", "p-honesty", seq + 1 + i, verdict=verdict)
        assert c.verdict == verdict
    with pytest.raises(ConstitutionalAIError):
        ledger.critique("draft-1", "p-honesty", seq + 4, verdict="maybe")
    # default verdict is needs-revision
    c5 = ledger.critique("draft-1", "p-honesty", seq + 5)
    assert c5.verdict == VERDICT_NEEDS_REVISION


# 9 ------------------------------------------------------------------------


def test_critique_unknown_draft_principle_refusals():
    ledger = _new()
    seq = _seed(ledger)
    with pytest.raises(UnknownDraftError):
        ledger.critique("ghost", "p-honesty", seq + 1)
    with pytest.raises(UnknownPrincipleError):
        ledger.critique("draft-1", "p-ghost", seq + 2)
    with pytest.raises(UnknownCritiqueError):
        ledger.critique_record("crit-999", seq + 3)
    with pytest.raises(BadCritiqueError):
        ledger.revise("draft-1", seq + 4, _pin(("r",)), "")
    with pytest.raises(UnknownCritiqueError):
        ledger.revise("draft-1", seq + 5, _pin(("r",)), "crit-999")
    with pytest.raises(UnknownDraftError):
        ledger.revise("ghost", seq + 6, _pin(("r",)), "crit-1")
    events = ledger.audit_log(seq + 7)
    assert [e["kind"] for e in events].count(KIND_REJECTED) == 5


# 10 ------------------------------------------------------------------------


def test_revise_roundtrip_verify():
    ledger = _new()
    seq = _seed(ledger)
    c = ledger.critique("draft-1", "p-honesty", seq + 1)
    r = ledger.revise("draft-1", seq + 2, _pin(("rev",)), c.critique_id)
    assert r.verify()
    assert r.revision_id == "rev-1"
    assert r.parent_critique_id == c.critique_id
    assert ledger.revision_record("rev-1", seq + 3) == r
    assert ledger.revisions_for("draft-1", seq + 4) == ("rev-1",)


# 11 ------------------------------------------------------------------------


def test_revise_cross_draft_refusal():
    ledger = _new()
    seq = _seed(ledger)
    ledger.submit("draft-2", _pin(("o2",)), seq + 1)
    seq += 1
    c = ledger.critique("draft-1", "p-honesty", seq + 1)
    with pytest.raises(CrossDraftError):
        ledger.revise("draft-2", seq + 2, _pin(("rev",)), c.critique_id)
    # same draft works fine
    r = ledger.revise("draft-1", seq + 3, _pin(("rev",)), c.critique_id)
    assert r.verify()


# 12 ------------------------------------------------------------------------


def test_seq_discipline():
    ledger = _new()
    ledger.principle("p1", CAT_HONESTY, _pin(("s",)), 5)
    with pytest.raises(SeqOrderError):
        ledger.principle("p2", CAT_HONESTY, _pin(("s",)), 5)  # rewind: bare, no burn
    for bad in (True, "7", 2.5, None, -1):
        with pytest.raises(SeqOrderError):
            ledger.principle("p3", CAT_HONESTY, _pin(("s",)), bad)
    ledger.principle("p2", CAT_HONESTY, _pin(("s",)), 6)  # still 5 -> 6 OK
    with pytest.raises(DuplicatePrincipleError):
        ledger.principle("p2", CAT_HONESTY, _pin(("s",)), 7)  # failed mutation burns seq
    ledger.principle("p3", CAT_HONESTY, _pin(("s",)), 8)  # next seq accepted
    events = ledger.audit_log(9)
    assert [e["kind"] for e in events].count(KIND_REJECTED) == 1


# 13 ------------------------------------------------------------------------


def test_view_read_purity():
    ledger = _new()
    seq = _seed(ledger)
    ledger.critique("draft-1", "p-honesty", seq + 1)
    audit_before = len(ledger.audit_log(seq + 2))
    # same seq reused for every pure-read view
    ledger.principle_ids(0)
    ledger.principle_record("p-honesty", 0)
    ledger.draft_record("draft-1", 0)
    ledger.critique_record("crit-1", 0)
    ledger.critiques_for("draft-1", 0)
    ledger.stats(0)
    assert len(ledger.audit_log(seq + 2)) == audit_before
    assert ledger.stats(0) == {
        "principles": 1,
        "drafts": 1,
        "critiques": 1,
        "revisions": 0,
        "audit_events": audit_before,
    }


# 14 ------------------------------------------------------------------------


def test_audit_shapes_leak_ban_bad_kind():
    ledger = _new()
    rec = ledger.principle("p1", CAT_HONESTY, _pin(("s",)), 1)
    events = ledger.audit_log(2)
    ev = events[0]
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["module"] == "constitutional-ai"
    assert ev["kind"] == KIND_PRINCIPLE
    assert ev["detail"]["principle_id"] == "p1"
    # banned keys never cross the boundary
    with pytest.raises(Exception):
        constitutional_ai_audit_event(
            KIND_DRAFT, 2, draft_id="d", statement="raw text leak"
        )
    for kind in ("bogus-kind", "constitutional-ai.unknown"):
        with pytest.raises(Exception):
            constitutional_ai_audit_event(kind, 2)
    # full raw-text scan of every emitted event
    blob = json.dumps(events)
    for word in ("statement", "draft", "output", "issue", "revision"):
        assert f'"{word}":' not in blob
    assert KIND_DRAFT in cai._KINDS and KIND_CRITIQUE in cai._KINDS
    assert KIND_REVISION in cai._KINDS and KIND_REJECTED in cai._KINDS
    assert rec.digest.startswith("sha256:")


# 15 ------------------------------------------------------------------------


def test_main_subprocess_check():
    proc = subprocess.run(
        [sys.executable, str(_HERE / "constitutional_ai.py")],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(_HERE),
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().startswith("constitutional-ai OK")
