"""Spec-API tests for the RecursiveReward noun facade (model/evaluate/recurse).

Additive companion to tests/test_recursive_reward.py (35 tests): covers the
spec's ``RecursiveReward`` / ``model()`` / ``evaluate()`` / ``recurse()``
API only. Zero changes to existing behavior — the pre-existing suite must
stay green.
"""

from __future__ import annotations

import ast
import dataclasses
import subprocess
import sys
from pathlib import Path

import pytest

from recursive_reward import (
    RECURSIVE_REWARD_VERSION,
    REWARD_SCHEMA,
    ActionFeatures,
    DecompositionEstimate,
    HumanFeedback,
    RecursionRecord,
    RecursiveReward,
    RewardError,
    RewardModel,
    reward_audit_event,
)

_HERE = Path(__file__).resolve()
_MODULE = _HERE.parent.parent / "recursive_reward.py"

FA = ActionFeatures({"helpful": 1.0, "risky": 0.0})
FB = ActionFeatures({"helpful": 0.0, "risky": 1.0})


def _trained_facade() -> RecursiveReward:
    facade = RecursiveReward()
    facade.model().train_step(HumanFeedback("fb-1", 1, preferred=FA, other=FB))
    facade.model().train_step(HumanFeedback("fb-2", 2, preferred=FA, other=FB))
    return facade


def test_version_and_schema_pins() -> None:
    assert RECURSIVE_REWARD_VERSION == "recursive-reward.v1"
    assert REWARD_SCHEMA == "northstar.recursive-reward.v1"
    record = RecursionRecord(task_id="t", subtasks=("a",))
    assert record.schema == REWARD_SCHEMA
    assert record.as_dict()["schema"] == REWARD_SCHEMA


def test_stdlib_only() -> None:
    tree = ast.parse(_MODULE.read_text())
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(n.name.split(".")[0] for n in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module.split(".")[0])
    assert mods <= {"__future__", "dataclasses", "math", "typing"}, mods


def test_model_returns_reward_model() -> None:
    facade = RecursiveReward()
    model = facade.model()
    assert isinstance(model, RewardModel)
    assert facade.model() is model  # stable identity


def test_model_accepts_pretrained() -> None:
    model = RewardModel()
    model.train_step(HumanFeedback("fb-9", 9, preferred=FA, other=FB))
    facade = RecursiveReward(model)
    assert facade.model() is model
    assert facade.model().weights()["helpful"] > 0.0


def test_model_rejects_non_model() -> None:
    with pytest.raises(RewardError):
        RecursiveReward(model=object())  # type: ignore[arg-type]


def test_recurse_books_frozen_record() -> None:
    facade = RecursiveReward()
    record = facade.recurse("root", ("a", "b"), {"a": FA, "b": FB})
    assert isinstance(record, RecursionRecord)
    assert record.task_id == "root"
    assert record.subtasks == ("a", "b")
    assert record.as_dict() == {
        "task_id": "root",
        "subtasks": ["a", "b"],
        "schema": REWARD_SCHEMA,
    }
    assert facade.bound_leaf_ids() == ("a", "b")
    assert facade.composite_ids() == ("root",)
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.task_id = "x"  # type: ignore[misc]


def test_recurse_bad_inputs() -> None:
    facade = RecursiveReward()
    with pytest.raises(RewardError):
        facade.recurse("", ("a",))                      # empty task id
    with pytest.raises(RewardError):
        facade.recurse("t", ())                         # no subtasks
    with pytest.raises(RewardError):
        facade.recurse("t", "ab")                       # bare string, not a sequence
    with pytest.raises(RewardError):
        facade.recurse("t", ("a", "a"))                 # duplicate subtasks
    with pytest.raises(RewardError):
        facade.recurse("t", ("t",))                     # self-decomposition
    with pytest.raises(RewardError):
        facade.recurse("t", ("a",), {"b": FA})          # leaf id not a subtask
    with pytest.raises(RewardError):
        facade.recurse("t", ("a",), {"a": "nope"})      # not ActionFeatures
    with pytest.raises(RewardError):
        facade.recurse("t", ("a",), ["not", "mapping"])  # type: ignore[arg-type]


def test_recurse_duplicate_task_refused() -> None:
    facade = RecursiveReward()
    facade.recurse("root", ("a", "b"), {"a": FA, "b": FB})
    with pytest.raises(RewardError):
        facade.recurse("root", ("a", "b"))  # already a composite
    with pytest.raises(RewardError):
        facade.recurse("a", ("c",))         # already a bound leaf


def test_recurse_cycle_refused() -> None:
    facade = RecursiveReward()
    facade.recurse("x", ("y",))
    with pytest.raises(RewardError):
        facade.recurse("y", ("x",))  # would close a cycle


def test_evaluate_leaf_matches_model() -> None:
    facade = _trained_facade()
    facade.recurse("root", ("leaf",), {"leaf": FA})
    estimate = facade.evaluate("leaf")
    assert isinstance(estimate, DecompositionEstimate)
    assert estimate.leaf is True
    assert estimate.task_id == "leaf"
    prediction = facade.model().predict_reward(FA)
    assert estimate.score == prediction.score
    assert estimate.confidence == prediction.confidence


def test_evaluate_composite_mean_and_min_confidence() -> None:
    facade = _trained_facade()
    facade.recurse("root", ("l1", "l2"), {"l1": FA, "l2": FB})
    estimate = facade.evaluate("root")
    assert estimate.leaf is False
    e1 = facade.evaluate("l1")
    e2 = facade.evaluate("l2")
    assert estimate.score == pytest.approx((e1.score + e2.score) / 2)
    assert estimate.confidence == min(e1.confidence, e2.confidence)


def test_evaluate_unknown_refused() -> None:
    facade = RecursiveReward()
    with pytest.raises(RewardError):
        facade.evaluate("no-such-task")
    with pytest.raises(RewardError):
        facade.evaluate("")


def test_evaluate_untrained_leaf_zero_confidence() -> None:
    facade = RecursiveReward()  # no training at all
    facade.recurse("root", ("leaf",), {"leaf": FA})
    estimate = facade.evaluate("leaf")
    assert estimate.confidence == 0.0  # no coverage: extrapolating, flagged
    assert facade.model().predict_reward(FA).extrapolating is True


def test_full_spec_flow_with_audit() -> None:
    facade = _trained_facade()
    facade.recurse(
        "handle-inbox",
        ("write", "send"),
        {"write": FA, "send": FB},
    )
    estimate = facade.evaluate("handle-inbox")
    write_est = facade.evaluate("write")
    send_est = facade.evaluate("send")
    assert write_est.score > send_est.score  # preferred features win after training
    assert estimate.score == pytest.approx((write_est.score + send_est.score) / 2)
    event = reward_audit_event(
        "evaluate", estimate.task_id, estimate.score, estimate.confidence, 3
    )
    assert event["kind"] == "reward.evaluate"
    assert event["module"] == RECURSIVE_REWARD_VERSION


def test_main_subprocess() -> None:
    proc = subprocess.run(
        [sys.executable, str(_MODULE)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "recursive-reward OK" in proc.stdout
