"""Targeted tests for the debate ledger (15 tests)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import debate as D
from debate import Debate

RUNTIME_DIR = Path(__file__).resolve().parent.parent
TOPIC = "sha256:" + "0" * 64
ARG_PIN = "sha256:" + "a" * 64


def test_version_and_schema_pins():
    assert D.DEBATE_VERSION == "debate.v1"
    assert D.DEBATE_SCHEMA == "northstar.debate.v1"
    assert D.AUDIT_SCHEMA == "audit.ndjson/1"
    assert D.SIDES == ("side-a", "side-b")
    assert set(D.VERDICTS) == {"side-a-wins", "side-b-wins", "tie"}


def test_stdlib_only_imports():
    tree = ast.parse((RUNTIME_DIR / "debate.py").read_text())
    allowed = {"hashlib", "re", "threading", "dataclasses", "typing",
               "__future__", "canonical_json", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_debate_roundtrip_and_verify():
    db = Debate()
    rec = db.debate("db-1", TOPIC, 1)
    assert rec.debate_id == "db-1"
    assert rec.topic_digest == TOPIC
    assert rec.verify("db-1", TOPIC)
    assert not rec.verify("db-1", ARG_PIN)


def test_debate_bad_inputs():
    db = Debate()
    seq = 1
    for kwargs in (
        {"debate_id": "", "topic_digest": TOPIC},
        {"debate_id": "has space", "topic_digest": TOPIC},
        {"debate_id": "x" * 257, "topic_digest": TOPIC},
        {"debate_id": 7, "topic_digest": TOPIC},
        {"debate_id": True, "topic_digest": TOPIC},
        {"debate_id": "db-2", "topic_digest": "not-a-pin"},
        {"debate_id": "db-2", "topic_digest": ""},
        {"debate_id": "db-2", "topic_digest": "sha256:" + "g" * 64},
    ):
        with pytest.raises(D.DebateError):
            db.debate(seq=seq, **kwargs)
        seq += 1
    assert seq - 1 == sum(
        1 for e in db.audit_log() if e["kind"] == "rejected")


def test_duplicate_debate():
    db = Debate()
    db.debate("db-1", TOPIC, 1)
    with pytest.raises(D.DuplicateDebateError):
        db.debate("db-1", TOPIC, 2)


def test_argue_roundtrip_and_verify():
    db = Debate()
    db.debate("db-1", TOPIC, 1)
    rec = db.argue("db-1", "side-a", "arg-1", 2, ARG_PIN)
    assert rec.side == "side-a"
    assert rec.verify("db-1", "side-a", ARG_PIN)
    assert not rec.verify("db-1", "side-b", ARG_PIN)
    rec2 = db.argue("db-1", "side-b", "arg-2", 3)
    assert rec2.argument_digest == ""
    assert rec2.verify("db-1", "side-b", "")


def test_argue_bad_inputs():
    db = Debate()
    db.debate("db-1", TOPIC, 1)
    seq = 2
    cases = [
        ({"debate_id": "nope", "side": "side-a", "argument_id": "arg-1"},
         D.UnknownDebateError),
        ({"debate_id": "db-1", "side": "side-c", "argument_id": "arg-1"},
         D.BadSideError),
        ({"debate_id": "db-1", "side": 7, "argument_id": "arg-1"},
         D.BadSideError),
        ({"debate_id": "db-1", "side": True, "argument_id": "arg-1"},
         D.BadSideError),
        ({"debate_id": "db-1", "side": "side-a", "argument_id": ""},
         D.BadIdError),
        ({"debate_id": "db-1", "side": "side-a", "argument_id": "arg-1",
          "argument_digest": "bad-pin"}, D.BadDigestError),
    ]
    for kwargs, exc in cases:
        with pytest.raises(exc):
            db.argue(seq=seq, **kwargs)
        seq += 1
    rejected = [e for e in db.audit_log() if e["kind"] == "rejected"]
    assert len(rejected) == len(cases)


def test_duplicate_argument():
    db = Debate()
    db.debate("db-1", TOPIC, 1)
    db.argue("db-1", "side-a", "arg-1", 2)
    with pytest.raises(D.DuplicateArgumentError):
        db.argue("db-1", "side-b", "arg-1", 3)


def test_judge_roundtrip_verdict_as_data():
    db = Debate()
    db.debate("db-1", TOPIC, 1)
    db.argue("db-1", "side-a", "arg-1", 2)
    db.argue("db-1", "side-b", "arg-2", 3)
    rec = db.judge("db-1", "tie", 4)
    assert rec.verdict == "tie"
    assert rec.side_a_arguments == 1
    assert rec.side_b_arguments == 1
    assert rec.verify("db-1", "tie", (1, 1))
    assert not rec.verify("db-1", "side-a-wins", (1, 1))


def test_judge_refusals():
    db = Debate()
    db.debate("db-1", TOPIC, 1)
    db.debate("db-empty", TOPIC, 2)
    db.argue("db-1", "side-a", "arg-1", 3)
    with pytest.raises(D.NoArgumentsError):
        db.judge("db-empty", "tie", 4)
    with pytest.raises(D.UnknownDebateError):
        db.judge("nope", "tie", 5)
    with pytest.raises(D.BadVerdictError):
        db.judge("db-1", "side-a", 6)
    with pytest.raises(D.BadVerdictError):
        db.judge("db-1", True, 7)
    db.judge("db-1", "side-a-wins", 8)
    with pytest.raises(D.AlreadyJudgedError):
        db.judge("db-1", "tie", 9)


def test_transcript_pure_read():
    db = Debate()
    db.debate("db-1", TOPIC, 1)
    db.argue("db-1", "side-b", "arg-1", 2, ARG_PIN)
    db.argue("db-1", "side-a", "arg-2", 3)
    before = len(db.audit_log())
    t = db.transcript("db-1", 3)  # seq reuse legal on reads
    t2 = db.transcript("db-1", 3)
    assert t.arguments[0].side == "side-b"
    assert t.arguments[1].side == "side-a"
    assert t.verdict is None
    assert t.verify("db-1", TOPIC, ("arg-1", "arg-2"), None)
    assert t.digest == t2.digest
    assert len(db.audit_log()) == before  # no audit rows from reads
    db.judge("db-1", "side-b-wins", 4)
    t3 = db.transcript("db-1", 4)
    assert t3.verdict == "side-b-wins"
    with pytest.raises(D.UnknownDebateError):
        db.transcript("nope", 4)


def test_seq_discipline():
    db = Debate()
    db.debate("db-1", TOPIC, 1)
    with pytest.raises(D.SeqOrderError):
        db.debate("db-2", TOPIC, 1)  # rewind: bare, no consumption
    with pytest.raises(D.SeqOrderError):
        db.debate("db-2", TOPIC, True)
    with pytest.raises(D.SeqOrderError):
        db.debate("db-2", TOPIC, -1)
    with pytest.raises(D.SeqOrderError):
        db.debate("db-2", TOPIC, "2")
    assert db.debate("db-2", TOPIC, 2).debate_id == "db-2"
    assert not any(e["kind"] == "rejected" for e in db.audit_log())


def test_failed_mutation_consumes_seq_and_books_rejected():
    db = Debate()
    db.debate("db-1", TOPIC, 1)
    with pytest.raises(D.DuplicateDebateError):
        db.debate("db-1", TOPIC, 2)
    rejected = [e for e in db.audit_log() if e["kind"] == "rejected"]
    assert len(rejected) == 1
    assert rejected[0]["seq"] == 2
    # seq 2 was consumed: next claim must exceed it.
    with pytest.raises(D.SeqOrderError):
        db.debate("db-2", TOPIC, 2)
    assert db.debate("db-2", TOPIC, 3).debate_id == "db-2"


def test_audit_shapes_and_leak_ban():
    db = Debate()
    db.debate("db-1", TOPIC, 1)
    db.argue("db-1", "side-a", "arg-1", 2, ARG_PIN)
    db.judge("db-1", "side-a-wins", 3)
    kinds = [e["kind"] for e in db.audit_log()]
    assert kinds == ["debate-opened", "argued", "judged"]
    for event in db.audit_log():
        assert event["schema"] == "audit.ndjson/1"
        assert event["module"] == "debate.v1"
        for banned in ("topic", "argument", "content", "text", "payload",
                       "transcript"):
            assert banned not in event["detail"]
    with pytest.raises(D.AuditKindError):
        D.debate_audit_event("nope", {}, 9)
    with pytest.raises(D.AuditKindError):
        D.debate_audit_event("argued", {"topic": "leak"}, 9)


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, str(RUNTIME_DIR / "debate.py")],
        capture_output=True, text=True, cwd=str(RUNTIME_DIR), timeout=60)
    assert result.returncode == 0, result.stderr
    assert "debate OK" in result.stdout
