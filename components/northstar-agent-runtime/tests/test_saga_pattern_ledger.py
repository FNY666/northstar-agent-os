"""Tests for the additive ``SagaPattern`` ledger in ``saga_pattern.py``.

The pre-existing ``Saga`` orchestration tests live in
``test_saga_pattern.py``; this file covers only the new declarative
ledger API: ``step()`` / ``compensate()`` / ``complete()``.
"""

from __future__ import annotations

import ast
import dataclasses
import subprocess
import sys
from pathlib import Path

import pytest

import saga_pattern
from saga_pattern import (
    SCHEMA_PIN,
    SAGA_PATTERN_VERSION,
    BadStepError,
    DuplicateCompensationError,
    DuplicateStepError,
    EmptySagaError,
    SagaError,
    SagaPattern,
    SeqOrderError,
    TerminalSagaError,
    UnknownStepError,
    saga_pattern_audit_event,
)

MODULE = Path(saga_pattern.__file__)


def test_version_pins():
    assert SAGA_PATTERN_VERSION == "saga-pattern.v1"
    assert SCHEMA_PIN == "northstar.saga-pattern.v1"


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    allowed = {
        "__future__",
        "dataclasses",
        "typing",
        "hashlib",
        "threading",
        "json",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_step_roundtrip():
    sp = SagaPattern("s1")
    rec = sp.step("a", "first step", 0)
    assert rec.step_id == "a"
    assert rec.description == "first step"
    assert rec.seq == 0
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    as_dict = rec.as_dict()
    assert as_dict["schema"] == SCHEMA_PIN
    assert as_dict["step_id"] == "a"
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.step_id = "b"  # type: ignore
    # cross-instance determinism: same inputs, same pin
    sp2 = SagaPattern("other")
    rec2 = sp2.step("a", "first step", 0)
    assert rec2.digest == rec.digest


def test_step_duplicate():
    sp = SagaPattern("s1")
    sp.step("a", "first", 0)
    with pytest.raises(DuplicateStepError):
        sp.step("a", "again", 1)
    # failed mutation consumed its seq and booked a rejection row
    assert sp.stats()["last_seq"] == 1
    kinds = [row["kind"] for row in sp.audit_log()]
    assert kinds[-1] == "saga-pattern.rejected"
    assert sp.audit_log()[-1]["detail"]["reason"]
    assert sp.step_ids() == ("a",)


def test_step_bad_inputs():
    sp = SagaPattern("s1")
    for bad_id in ("", True, 123, None, "x" * 257):
        with pytest.raises(BadStepError):
            sp.step(bad_id, "desc", 0)
    for bad_desc in ("", True, 5, None, "x" * 1025):
        with pytest.raises(BadStepError):
            sp.step("ok", bad_desc, 0)
    for bad_seq in ("1", 1.0, True, -1):
        with pytest.raises(SagaError):
            sp.step("ok", "desc", bad_seq)
    # malformed inputs never consumed a seq
    assert sp.stats()["last_seq"] == -1
    assert sp.step_ids() == ()


def test_seq_ordering():
    sp = SagaPattern("s1")
    sp.step("a", "x", 5)
    with pytest.raises(SeqOrderError):
        sp.step("b", "y", 5)  # rewind/equal raises bare, consumes nothing
    assert sp.stats()["last_seq"] == 5
    assert sp.step_ids() == ("a",)
    sp.step("b", "y", 6)
    assert sp.step_ids() == ("a", "b")


def test_compensate_roundtrip():
    sp = SagaPattern("s1")
    sp.step("a", "first", 0)
    rec = sp.compensate("a", 1)
    assert rec.step_id == "a"
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    assert sp.compensated_ids() == ("a",)
    assert sp.compensation_record("a").digest == rec.digest
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.seq = 9  # type: ignore


def test_compensate_unknown():
    sp = SagaPattern("s1")
    sp.step("a", "first", 0)
    with pytest.raises(UnknownStepError):
        sp.compensate("nope", 1)
    kinds = [row["kind"] for row in sp.audit_log()]
    assert kinds[-1] == "saga-pattern.rejected"
    assert sp.stats()["last_seq"] == 1
    with pytest.raises(UnknownStepError):
        sp.compensation_record("nope")


def test_compensate_duplicate():
    sp = SagaPattern("s1")
    sp.step("a", "first", 0)
    sp.compensate("a", 1)
    with pytest.raises(DuplicateCompensationError):
        sp.compensate("a", 2)
    assert sp.compensated_ids() == ("a",)
    assert sp.stats()["last_seq"] == 2


def test_complete_completed():
    sp = SagaPattern("s1")
    sp.step("b", "second", 0)
    sp.step("a", "first", 1)
    done = sp.complete(2)
    assert done.status == "completed"
    assert done.saga_id == "s1"
    assert done.step_ids == ("a", "b")  # sorted, deterministic
    assert done.compensated_step_ids == ()
    assert done.verify()
    assert done.as_dict()["schema"] == SCHEMA_PIN
    assert sp.completion() is done
    assert sp.stats()["completed"] is True


def test_complete_compensated():
    sp = SagaPattern("s1")
    sp.step("a", "first", 0)
    sp.step("b", "second", 1)
    sp.compensate("b", 2)
    done = sp.complete(3)
    assert done.status == "compensated"
    assert done.step_ids == ("a", "b")
    assert done.compensated_step_ids == ("b",)
    assert done.verify()
    row = sp.audit_log()[-1]
    assert row["kind"] == "saga-pattern.completed"
    assert row["detail"]["status"] == "compensated"
    assert row["detail"]["compensated"] == 1


def test_complete_empty():
    sp = SagaPattern("empty")
    with pytest.raises(EmptySagaError):
        sp.complete(0)
    assert sp.completion() is None
    assert sp.audit_log()[-1]["kind"] == "saga-pattern.rejected"


def test_terminal():
    sp = SagaPattern("s1")
    sp.step("a", "first", 0)
    sp.complete(1)
    with pytest.raises(TerminalSagaError):
        sp.step("b", "late", 2)
    with pytest.raises(TerminalSagaError):
        sp.compensate("a", 3)
    with pytest.raises(TerminalSagaError):
        sp.complete(4)
    # terminal failures also consume seqs and book rejections
    assert sp.stats()["last_seq"] == 4
    kinds = [row["kind"] for row in sp.audit_log()]
    assert kinds.count("saga-pattern.rejected") == 3
    # completion record is unchanged
    assert sp.completion().status == "completed"


def test_audit_shapes():
    sp = SagaPattern("s1")
    sp.step("a", "label text must not leak", 0)
    rows = sp.audit_log()
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["kind"] == "saga-pattern.step-registered"
    assert rows[0]["module"] == "saga-pattern"
    assert rows[0]["module_version"] == "saga-pattern.v1"
    assert "description" not in rows[0]["detail"]
    with pytest.raises(SagaError):
        saga_pattern_audit_event("bogus-kind", 0)
    with pytest.raises(SagaError):
        saga_pattern_audit_event(
            "saga-pattern.step-registered", 0, description="banned"
        )
    with pytest.raises(SagaError):
        saga_pattern_audit_event("saga-pattern.completed", -1)


def test_views_and_stats():
    sp = SagaPattern("s1")
    assert sp.completion() is None
    sp.step("b", "second", 0)
    sp.step("a", "first", 1)
    assert sp.step_ids() == ("a", "b")
    assert sp.step_record("a").description == "first"
    with pytest.raises(UnknownStepError):
        sp.step_record("nope")
    stats = sp.stats()
    assert stats["steps"] == 2
    assert stats["compensations"] == 0
    assert stats["completed"] is False
    assert stats["audit_rows"] == 2
    assert stats["last_seq"] == 1
    assert isinstance(sp.audit_log(), tuple)


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("saga-pattern OK")
    assert "ledger" in result.stdout
