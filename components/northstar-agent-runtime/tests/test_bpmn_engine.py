"""Tests for bpmn_engine.py (Camunda-shaped deployment/task bookkeeping)."""

import ast
import subprocess
import sys
from pathlib import Path

import bpmn_engine
from bpmn_engine import (
    AUDIT_SCHEMA,
    BPMNEngine,
    BPMNEngineError,
    BPMN_ENGINE_SCHEMA,
    BPMN_ENGINE_VERSION,
    BadDefinitionError,
    BadInstanceError,
    BadOutcomeError,
    BadTaskSpecError,
    DuplicateDefinitionError,
    DuplicateInstanceError,
    SeqOrderError,
    TaskStateError,
    UnknownDefinitionError,
    UnknownInstanceError,
    UnknownTaskError,
    bpmn_engine_audit_event,
)


def _digest(tag: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(tag.encode()).hexdigest()


# ---------------------------------------------------------------------------
# 1. version / schema pins
# ---------------------------------------------------------------------------


def test_version_pins():
    assert BPMN_ENGINE_VERSION == "bpmn-engine.v1"
    assert BPMN_ENGINE_SCHEMA == "northstar.bpmn-engine.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert bpmn_engine.KIND_DEPLOYED == "bpmn.deployed"
    assert bpmn_engine.KIND_REJECTED == "bpmn.rejected"


# ---------------------------------------------------------------------------
# 2. stdlib-only
# ---------------------------------------------------------------------------


def test_stdlib_only():
    tree = ast.parse(Path(bpmn_engine.__file__).read_text())
    allowed = {"__future__", "hashlib", "threading", "dataclasses", "typing",
               "json", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# 3. deploy roundtrip
# ---------------------------------------------------------------------------


def test_deploy_roundtrip():
    engine = BPMNEngine()
    rec = engine.deploy(
        "proc-1", _digest("model"), 1, (("approve", "user"), ("charge", "service"))
    )
    assert rec.definition_id == "proc-1"
    assert rec.tasks == (("approve", "user"), ("charge", "service"))
    assert rec.verify()
    spec = engine.deployment_spec("proc-1")
    assert spec is not None and spec[0] == _digest("model")
    assert engine.definition_ids() == ("proc-1",)


# ---------------------------------------------------------------------------
# 4. deploy bad inputs
# ---------------------------------------------------------------------------


def test_deploy_bad_inputs():
    engine = BPMNEngine()
    for bad_id in ("", "   ", "x" * 257, 123, None, True):
        try:
            engine.deploy(bad_id, _digest("m"), 1)
        except BadDefinitionError:
            break
    else:
        raise AssertionError("bad definition id not refused")
    try:
        engine.deploy("p", "not-a-digest", 2)
    except BadDefinitionError:
        pass
    else:
        raise AssertionError("bad digest not refused")
    try:
        engine.deploy("p", _digest("m"), 3, (("t", "unknown-kind"),))
    except BadTaskSpecError:
        pass
    else:
        raise AssertionError("bad task kind not refused")
    # failed mutations consumed their seqs: rewind to 2 must raise
    try:
        engine.deploy("q", _digest("m"), 2)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("failed-mutation seq burn not enforced")
    kinds = [row["kind"] for row in engine.audit_log()]
    assert kinds.count("bpmn.rejected") == 3


# ---------------------------------------------------------------------------
# 5. deploy duplicate
# ---------------------------------------------------------------------------


def test_deploy_duplicate():
    engine = BPMNEngine()
    engine.deploy("proc-1", _digest("m"), 1)
    try:
        engine.deploy("proc-1", _digest("m"), 2)
    except DuplicateDefinitionError:
        pass
    else:
        raise AssertionError("duplicate definition not refused")


# ---------------------------------------------------------------------------
# 6. start roundtrip
# ---------------------------------------------------------------------------


def test_start_roundtrip():
    engine = BPMNEngine()
    engine.deploy("proc-1", _digest("m"), 1)
    rec = engine.start("inst-1", "proc-1", 2)
    assert rec.instance_id == "inst-1" and rec.verify()
    view = engine.instance("inst-1")
    assert view is not None and view.state == "active"
    assert view.definition_id == "proc-1"
    assert engine.instance_ids() == ("inst-1",)


# ---------------------------------------------------------------------------
# 7. start unknown definition / duplicate instance
# ---------------------------------------------------------------------------


def test_start_failures():
    engine = BPMNEngine()
    try:
        engine.start("inst-1", "missing", 1)
    except UnknownDefinitionError:
        pass
    else:
        raise AssertionError("unknown definition not refused")
    engine.deploy("proc-1", _digest("m"), 2)
    engine.start("inst-1", "proc-1", 3)
    try:
        engine.start("inst-1", "proc-1", 4)
    except DuplicateInstanceError:
        pass
    else:
        raise AssertionError("duplicate instance not refused")


# ---------------------------------------------------------------------------
# 8. task roundtrip
# ---------------------------------------------------------------------------


def test_task_roundtrip():
    engine = BPMNEngine()
    engine.deploy("proc-1", _digest("m"), 1, (("approve", "user"),))
    engine.start("inst-1", "proc-1", 2)
    rec = engine.task("inst-1", "approve", 3)
    assert rec.outcome == "completed" and rec.task_kind == "user"
    assert rec.verify()
    view = engine.instance("inst-1")
    assert view.state == "completed"
    assert view.completed_tasks == ("approve",)
    assert engine.pending_tasks("inst-1") == ()


# ---------------------------------------------------------------------------
# 9. task failures
# ---------------------------------------------------------------------------


def test_task_failures():
    engine = BPMNEngine()
    try:
        engine.task("no-inst", "t", 1)
    except UnknownInstanceError:
        pass
    else:
        raise AssertionError("unknown instance not refused")
    engine.deploy("proc-1", _digest("m"), 2, (("approve", "user"),))
    engine.start("inst-1", "proc-1", 3)
    try:
        engine.task("inst-1", "missing", 4)
    except UnknownTaskError:
        pass
    else:
        raise AssertionError("unknown task not refused")
    engine.task("inst-1", "approve", 5)
    # instance is terminal now
    try:
        engine.task("inst-1", "approve", 6)
    except TaskStateError:
        pass
    else:
        raise AssertionError("task on completed instance not refused")


# ---------------------------------------------------------------------------
# 10. task duplicate before completion
# ---------------------------------------------------------------------------


def test_task_duplicate_before_completion():
    engine = BPMNEngine()
    engine.deploy("proc-1", _digest("m"), 1,
                  (("approve", "user"), ("charge", "service")))
    engine.start("inst-1", "proc-1", 2)
    engine.task("inst-1", "approve", 3)
    try:
        engine.task("inst-1", "approve", 4)
    except TaskStateError:
        pass
    else:
        raise AssertionError("double task booking not refused")
    view = engine.instance("inst-1")
    assert view.state == "active"
    assert view.pending_tasks == ("charge",)


# ---------------------------------------------------------------------------
# 11. outcome vocabulary
# ---------------------------------------------------------------------------


def test_outcome_vocabulary():
    engine = BPMNEngine()
    engine.deploy("proc-1", _digest("m"), 1,
                  (("approve", "user"), ("charge", "service")))
    engine.start("inst-1", "proc-1", 2)
    rec = engine.task("inst-1", "approve", 3, outcome="skipped")
    assert rec.outcome == "skipped" and rec.verify()
    try:
        engine.task("inst-1", "charge", 4, outcome="exploded")
    except BadOutcomeError:
        pass
    else:
        raise AssertionError("bad outcome not refused")


# ---------------------------------------------------------------------------
# 12. seq ordering
# ---------------------------------------------------------------------------


def test_seq_ordering():
    engine = BPMNEngine()
    engine.deploy("proc-1", _digest("m"), 1)
    for bad in (1, True, -1, "2", 1.5):
        try:
            engine.deploy("other", _digest("m"), bad)
        except SeqOrderError:
            pass
        else:
            raise AssertionError(f"bad seq {bad!r} not refused")
    # pure views do not consume seq
    engine.instance("missing")
    engine.stats()
    engine.deploy("other", _digest("m"), 2)  # would have been burned by view use


# ---------------------------------------------------------------------------
# 13. audit shapes and boundary
# ---------------------------------------------------------------------------


def test_audit_shapes():
    engine = BPMNEngine()
    engine.deploy("proc-1", _digest("m"), 1, (("approve", "user"),))
    engine.start("inst-1", "proc-1", 2)
    engine.task("inst-1", "approve", 3)
    rows = engine.audit_log()
    kinds = [row["kind"] for row in rows]
    assert kinds == [
        "bpmn.deployed", "bpmn.started", "bpmn.task-completed", "bpmn.completed"
    ]
    for row in rows:
        assert row["schema"] == AUDIT_SCHEMA
        assert row["module"] == BPMN_ENGINE_VERSION
        for banned in ("bpmn_xml", "payload", "xml", "bytes", "value", "raw"):
            assert banned not in row["detail"]
    try:
        bpmn_engine_audit_event("bogus", {}, 9)
    except bpmn_engine.AuditKindError:
        pass
    else:
        raise AssertionError("bad audit kind not refused")
    try:
        bpmn_engine_audit_event("bpmn.deployed", {"bpmn_xml": "<xml/>"}, 9)
    except bpmn_engine.AuditKindError:
        pass
    else:
        raise AssertionError("banned audit key not refused")


# ---------------------------------------------------------------------------
# 14. views and stats
# ---------------------------------------------------------------------------


def test_views_and_stats():
    engine = BPMNEngine()
    assert engine.stats().definitions == 0
    engine.deploy("proc-1", _digest("m"), 1, (("a", "user"),))
    engine.deploy("proc-2", _digest("n"), 2, (("b", "service"),))
    engine.start("inst-1", "proc-1", 3)
    engine.start("inst-2", "proc-2", 4)
    engine.task("inst-1", "a", 5)
    stats = engine.stats()
    assert stats.definitions == 2 and stats.instances == 2
    assert stats.completed_instances == 1 and stats.tasks_completed == 1
    assert engine.instance("nope") is None
    assert engine.deployment_spec("nope") is None
    assert engine.definition_ids() == ("proc-1", "proc-2")


# ---------------------------------------------------------------------------
# 15. main() self-check
# ---------------------------------------------------------------------------


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, bpmn_engine.__file__],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "bpmn-engine OK" in result.stdout
