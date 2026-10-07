"""Tests for timeout_management: deterministic deadline propagation."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from timeout_management import (
    AUDIT_SCHEMA,
    KIND_CANCELLED,
    KIND_DEADLINE_SET,
    KIND_PROPAGATED,
    KIND_REJECTED,
    TIMEOUT_MANAGEMENT_SCHEMA,
    TIMEOUT_MANAGEMENT_VERSION,
    BadDeadlineError,
    BadScopeError,
    CancelledScopeError,
    DeadlineExceedsParentError,
    DeadlineRecord,
    DuplicateScopeError,
    SeqOrderError,
    TimeoutManagement,
    TimeoutManagementError,
    UnknownScopeError,
    timeout_management_audit_event,
)

MODULE = Path(__file__).resolve().parent.parent / "timeout_management.py"


def test_version_and_schema_pins():
    assert TIMEOUT_MANAGEMENT_VERSION == "timeout-management.v1"
    assert TIMEOUT_MANAGEMENT_SCHEMA == "northstar.timeout-management.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only_ast():
    tree = ast.parse(MODULE.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.asname or a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add((node.names[0].asname or node.module.split(".")[0]))
    allowed = {
        "hashlib", "threading", "dataclass", "dataclasses", "typing",
        "Any", "Dict", "List", "Mapping", "Optional", "Tuple", "__future__",
        "annotations", "canonical_json", "json", "northstar_agent_runtime",
    }
    assert imported <= allowed, f"unexpected imports: {imported - allowed}"


def test_deadline_roundtrip():
    tm = TimeoutManagement()
    rec = tm.deadline("root", 1, 100)
    assert isinstance(rec, DeadlineRecord)
    assert rec.expiry_seq == 101
    assert rec.parent_scope_id == ""
    assert rec.verify()
    assert tm.scope("root") == rec
    assert tm.scope_ids() == ("root",)


def test_deadline_duplicate_refused():
    tm = TimeoutManagement()
    tm.deadline("root", 1, 10)
    with pytest.raises(DuplicateScopeError):
        tm.deadline("root", 2, 10)


def test_deadline_bad_inputs():
    tm = TimeoutManagement()
    seq = 0
    # each case gets a fresh seq (failed mutations consume seqs)
    cases = [
        (("",), BadScopeError),
        (("   ",), BadScopeError),
        (("a b",), BadScopeError),
        (("x" * 257,), BadScopeError),
    ]
    for (sid,), exc in cases:
        seq += 1
        with pytest.raises(exc):
            tm.deadline(sid, seq, 10)
    ttl_cases = [
        (0, BadDeadlineError),
        (-5, BadDeadlineError),
        (True, BadDeadlineError),
        (1.5, BadDeadlineError),
    ]
    for i, (ttl, exc) in enumerate(ttl_cases):
        seq += 1
        with pytest.raises(exc):
            tm.deadline(f"s{i}", seq, ttl)


def test_seq_ordering_and_failed_mutation_consumes_seq():
    tm = TimeoutManagement()
    tm.deadline("a", 1, 10)
    with pytest.raises(SeqOrderError):
        tm.deadline("b", 1, 10)
    with pytest.raises(SeqOrderError):
        tm.deadline("b", 0, 10)
    with pytest.raises(SeqOrderError):
        tm.deadline("b", True, 10)
    # failed duplicate consumes its seq: next fresh seq must be > 2
    with pytest.raises(DuplicateScopeError):
        tm.deadline("a", 2, 10)
    with pytest.raises(SeqOrderError):
        tm.deadline("b", 2, 10)
    tm.deadline("b", 3, 10)


def test_deadline_tighten_only_with_parent():
    tm = TimeoutManagement()
    tm.deadline("root", 1, 100)          # expiry 101
    child = tm.deadline("c1", 2, 10, parent_scope_id="root")  # expiry 12
    assert child.parent_scope_id == "root"
    assert child.expiry_seq == 12
    with pytest.raises(DeadlineExceedsParentError):
        tm.deadline("c2", 3, 200, parent_scope_id="root")  # expiry 203 > 101
    with pytest.raises(UnknownScopeError):
        tm.deadline("c3", 4, 10, parent_scope_id="nope")


def test_propagate_roundtrip_and_tighten():
    tm = TimeoutManagement()
    tm.deadline("root", 1, 100)          # expiry 101
    p = tm.propagate("root", "child", 2, ttl_seqs=10)
    assert p.expiry_seq == 12 and p.tightened
    assert p.verify()
    q = tm.propagate("root", "child2", 3)  # inherit verbatim
    assert q.expiry_seq == 101 and not q.tightened
    # tighten-only clamp: requested ttl looser than parent -> parent wins
    r = tm.propagate("root", "child3", 4, ttl_seqs=1000)
    assert r.expiry_seq == 101 and not r.tightened
    with pytest.raises(UnknownScopeError):
        tm.propagate("nope", "x", 5)
    with pytest.raises(DuplicateScopeError):
        tm.propagate("root", "child", 6)


def test_propagate_from_cancelled_parent_refused():
    tm = TimeoutManagement()
    tm.deadline("root", 1, 100)
    tm.cancel("root", 2)
    with pytest.raises(CancelledScopeError):
        tm.propagate("root", "child", 3)


def test_cancel_terminal_and_views():
    tm = TimeoutManagement()
    tm.deadline("root", 1, 100)
    rec = tm.cancel("root", 2, "operator")
    assert rec.verify()
    assert tm.cancelled("root")
    assert tm.cancelled_ids() == ("root",)
    with pytest.raises(CancelledScopeError):
        tm.cancel("root", 3)
    with pytest.raises(UnknownScopeError):
        tm.cancel("ghost", 4)


def test_remaining_and_expired_are_pure_views():
    tm = TimeoutManagement()
    tm.deadline("root", 1, 10)           # expiry 11
    rep = tm.remaining("root", 5)
    assert rep.remaining == 6 and not rep.expired and rep.verify()
    assert not tm.expired("root", 10)
    rep2 = tm.remaining("root", 11)
    assert rep2.remaining == 0 and rep2.expired
    assert tm.expired("root", 99)
    # pure view: seq shape validated but not consumed
    tm.remaining("root", 5)
    tm.deadline("other", 5, 10)          # seq 5 still free -> ok
    with pytest.raises(UnknownScopeError):
        tm.remaining("ghost", 6)


def test_audit_shapes_and_bad_kind():
    tm = TimeoutManagement()
    tm.deadline("root", 1, 10)
    tm.cancel("root", 2)
    kinds = [e["kind"] for e in tm.audit_log()]
    assert KIND_DEADLINE_SET in kinds
    assert KIND_CANCELLED in kinds
    for e in tm.audit_log():
        assert e["schema"] == AUDIT_SCHEMA
        assert e["module"] == TIMEOUT_MANAGEMENT_VERSION
    with pytest.raises(TimeoutManagementError):
        timeout_management_audit_event("bogus.kind", {}, 3)
    with pytest.raises(TimeoutManagementError):
        timeout_management_audit_event(
            KIND_DEADLINE_SET, {"payload": "x"}, 3
        )
    ev = timeout_management_audit_event(
        KIND_PROPAGATED, {"child_scope_id": "c"}, 3
    )
    assert ev["schema"] == AUDIT_SCHEMA


def test_stats_and_as_dict():
    tm = TimeoutManagement()
    tm.deadline("root", 1, 10)
    tm.propagate("root", "child", 2)
    tm.cancel("child", 3)
    s = tm.stats()
    assert s["scopes"] == 2 and s["propagations"] == 1
    assert s["cancellations"] == 1 and s["last_seq"] == 3
    snap = tm.as_dict()
    assert snap["version"] == TIMEOUT_MANAGEMENT_VERSION


def test_cross_instance_digest_determinism():
    a, b = TimeoutManagement(), TimeoutManagement()
    ra = a.deadline("root", 1, 50)
    rb = b.deadline("root", 1, 50)
    assert ra.digest == rb.digest


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "timeout-management OK" in result.stdout
