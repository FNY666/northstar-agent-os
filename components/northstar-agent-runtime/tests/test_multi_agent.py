"""Tests for multi_agent.py (multi-agent run collaboration ledger)."""

import ast
import dataclasses
import subprocess
import sys
from pathlib import Path

import pytest

import multi_agent as _ma
from multi_agent import (
    MULTI_AGENT_SCHEMA,
    MULTI_AGENT_VERSION,
    AgentRecord,
    BadAgentError,
    BadDigestError,
    BadParticipantsError,
    BadRoleError,
    BadRunError,
    CoordinationRecord,
    DuplicateAgentError,
    DuplicateRoundError,
    MergeRecord,
    MultiAgent,
    MultiAgentError,
    ROUND_MERGED,
    ROUND_OPEN,
    ROLES,
    RoundStateError,
    SeqOrderError,
    UnknownAgentError,
    UnknownRoundError,
    multi_agent_audit_event,
)

MODULE_PATH = Path(_ma.__file__)


# 1. version / schema pins -----------------------------------------------------


def test_version_and_schema_pins():
    assert MULTI_AGENT_VERSION == "multi-agent.v1"
    assert MULTI_AGENT_SCHEMA == "northstar.multi-agent.v1"
    text = MODULE_PATH.read_text()
    assert "multi-agent.v1" in text
    assert "northstar.multi-agent.v1" in text
    assert "audit.ndjson/1" in text


# 2. stdlib-only AST check ------------------------------------------------------


def test_stdlib_only_ast():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "__future__",
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "canonical_json",  # sibling JCS helper, try/except import only
        "json",  # used inside the fallback canonicalizer
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3. spawn roundtrip / verify / as_dict -----------------------------------------


def test_spawn_roundtrip_verify_as_dict():
    run = MultiAgent("run-1")
    rec = run.spawn("alice", "planner", 1)
    assert isinstance(rec, AgentRecord)
    assert rec.run_id == "run-1"
    assert rec.agent_id == "alice"
    assert rec.role == "planner"
    assert rec.seq == 1
    assert rec.verify()
    d = rec.as_dict()
    assert d["schema"] == MULTI_AGENT_SCHEMA
    assert d["digest"] == rec.digest
    # frozen
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.role = "worker"  # type: ignore[misc]
    # tamper detection
    object.__setattr__(rec, "role", "worker")
    assert not rec.verify()


# 4. duplicate spawn burns seq + books rejected row ------------------------------


def test_duplicate_spawn_consumes_seq_and_books_rejected():
    run = MultiAgent("run-1")
    run.spawn("alice", "planner", 1)
    with pytest.raises(DuplicateAgentError):
        run.spawn("alice", "worker", 2)
    kinds = [row["kind"] for row in run.audit_log()]
    assert kinds == ["multi-agent.spawned", "multi-agent.rejected"]
    # seq 2 was consumed: the next mutation must exceed it
    with pytest.raises(SeqOrderError):
        run.spawn("bob", "worker", 2)
    rec = run.spawn("bob", "worker", 3)
    assert rec.agent_id == "bob"


# 5. bad inputs ------------------------------------------------------------------


def test_spawn_bad_inputs():
    seq = 0
    for bad in ("", "   ", 123, None, b"alice", True, "a" * 129):
        seq += 1
        run = MultiAgent("run-1")  # fresh ledger per bad input
        with pytest.raises(BadAgentError):
            run.spawn(bad, "planner", seq)
    with pytest.raises(BadRunError):
        MultiAgent("")
    with pytest.raises(BadRunError):
        MultiAgent(None)


def test_bad_role_vocabulary():
    for bad in ("admin", "PLANNER", "", None, 42, True):
        run = MultiAgent("run-1")  # fresh ledger per bad input
        with pytest.raises(BadRoleError):
            run.spawn("alice", bad, 1)
    for role in sorted(ROLES):
        r = MultiAgent("r")
        assert r.spawn("a1", role, 1).role == role


# 6. coordinate -------------------------------------------------------------------


def test_coordinate_roundtrip_and_deterministic_pin():
    task_pin = "sha256:" + "ab" * 32
    run = MultiAgent("run-1")
    run.spawn("bob", "worker", 1)
    run.spawn("alice", "planner", 2)
    rec = run.coordinate("r1", ["bob", "alice"], 3, task_digest=task_pin)
    assert isinstance(rec, CoordinationRecord)
    assert rec.participants == ("alice", "bob")  # sorted for the pin
    assert rec.task_digest == task_pin
    assert rec.verify()
    # cross-instance determinism: same declarations -> same pin
    run2 = MultiAgent("run-1")
    run2.spawn("alice", "planner", 1)
    run2.spawn("bob", "worker", 2)
    rec2 = run2.coordinate("r1", ["alice", "bob"], 3, task_digest=task_pin)
    assert rec2.digest == rec.digest
    assert run.round_state("r1") == ROUND_OPEN
    assert run.stats()["rounds_open"] == 1


def test_coordinate_unknown_agent_refused():
    run = MultiAgent("run-1")
    run.spawn("alice", "planner", 1)
    with pytest.raises(UnknownAgentError):
        run.coordinate("r1", ["alice", "mallory"], 2)
    assert run.audit_log()[-1]["kind"] == "multi-agent.rejected"


def test_coordinate_bad_participants():
    run = MultiAgent("run-1")
    run.spawn("alice", "planner", 1)
    with pytest.raises(BadParticipantsError):
        run.coordinate("r1", [], 2)
    with pytest.raises(BadParticipantsError):
        run.coordinate("r1", ["alice", "alice"], 3)
    with pytest.raises(BadParticipantsError):
        run.coordinate("r1", "alice", 4)  # a bare string is not a sequence
    with pytest.raises(BadAgentError):
        run.coordinate("r1", [""], 5)
    with pytest.raises(BadDigestError):
        run.coordinate("r1", ["alice"], 6, task_digest="not-a-pin")


def test_duplicate_round_refused():
    run = MultiAgent("run-1")
    run.spawn("alice", "planner", 1)
    run.coordinate("r1", ["alice"], 2)
    with pytest.raises(DuplicateRoundError):
        run.coordinate("r1", ["alice"], 3)
    assert run.round_ids() == ("r1",)


# 7. merge ------------------------------------------------------------------------


def test_merge_roundtrip_verify():
    outcome_pin = "sha256:" + "cd" * 32
    run = MultiAgent("run-1")
    run.spawn("alice", "planner", 1)
    run.coordinate("r1", ["alice"], 2)
    rec = run.merge("r1", outcome_pin, 3)
    assert isinstance(rec, MergeRecord)
    assert rec.outcome_digest == outcome_pin
    assert rec.verify()
    assert run.round_state("r1") == ROUND_MERGED
    assert run.merge_record("r1").digest == rec.digest
    assert run.stats()["rounds_merged"] == 1
    assert run.stats()["rounds_open"] == 0


def test_merge_unknown_round_and_double_merge():
    run = MultiAgent("run-1")
    run.spawn("alice", "planner", 1)
    with pytest.raises(UnknownRoundError):
        run.merge("nope", "sha256:" + "ef" * 32, 2)
    run.coordinate("r1", ["alice"], 3)
    with pytest.raises(BadDigestError):
        run.merge("r1", "bogus", 4)
    run.merge("r1", "sha256:" + "ef" * 32, 5)
    with pytest.raises(RoundStateError):
        run.merge("r1", "sha256:" + "ef" * 32, 6)
    # round is still merged, not corrupted by the refusals
    assert run.round_state("r1") == ROUND_MERGED
    # merged rounds cannot be re-coordinated either (id never recycled)
    with pytest.raises(DuplicateRoundError):
        run.coordinate("r1", ["alice"], 7)


# 8. seq discipline ---------------------------------------------------------------


def test_seq_discipline_rewind_bare_and_malformed():
    run = MultiAgent("run-1")
    before = len(run.audit_log())
    for bad in (True, "1", 1.0, None, -1):
        with pytest.raises(SeqOrderError):
            run.spawn("alice", "planner", bad)
    # malformed seqs consume nothing: no audit rows booked
    assert len(run.audit_log()) == before
    run.spawn("alice", "planner", 1)
    with pytest.raises(SeqOrderError):
        run.spawn("bob", "worker", 1)  # rewind raises bare
    assert len(run.audit_log()) == before + 1  # only the success row
    # failed mutation consumes seq: audit row booked, seq burned
    with pytest.raises(DuplicateAgentError):
        run.spawn("alice", "worker", 2)
    assert run.audit_log()[-1]["kind"] == "multi-agent.rejected"
    with pytest.raises(SeqOrderError):
        run.spawn("bob", "worker", 2)


# 9. audit shapes / bans / kinds ---------------------------------------------------


def test_audit_shapes_banned_keys_and_bad_kind():
    ev = multi_agent_audit_event("multi-agent.spawned", 1, agent_id="alice")
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["module"] == "multi-agent"
    assert ev["module_version"] == MULTI_AGENT_VERSION
    for banned in ("task", "outcome", "payload", "result", "bytes", "value", "data"):
        with pytest.raises(MultiAgentError):
            multi_agent_audit_event("multi-agent.spawned", 2, **{banned: "x"})
    with pytest.raises(MultiAgentError):
        multi_agent_audit_event("multi-agent.hacked", 3)
    with pytest.raises(SeqOrderError):
        multi_agent_audit_event("multi-agent.spawned", "x")


# 10. views read-purity + main ------------------------------------------------------


def test_views_are_pure_reads():
    run = MultiAgent("run-1")
    run.spawn("alice", "planner", 1)
    run.spawn("bob", "worker", 2)
    run.coordinate("r1", ["alice", "bob"], 3)
    rows_before = run.stats()["audit_rows"]
    assert run.agent("alice").agent_id == "alice"
    assert run.agent("nobody") is None
    assert run.agent_ids() == ("alice", "bob")
    assert run.round("r1").round_id == "r1"
    assert run.round("nope") is None
    assert run.merge_record("r1") is None  # not merged yet
    assert run.round_state("nope") is None
    assert run.stats()["agents"] == 2
    assert run.stats()["schema"] == MULTI_AGENT_SCHEMA
    assert len(run.audit_log()) == rows_before  # views wrote nothing
    # views validate id shape but consume no seq
    with pytest.raises(BadAgentError):
        run.agent("")


def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "multi-agent OK" in result.stdout
