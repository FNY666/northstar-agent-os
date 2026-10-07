"""Tests for task_router.py: deterministic task->route->worker binding."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import task_router
from task_router import (
    TASK_ROUTER_VERSION,
    SCHEMA_PIN,
    POLICIES,
    TaskRouter,
    TaskRouterError,
    NoAvailableWorkerError,
    SeqOrderError,
    task_router_audit_event,
)

MODULE = Path(task_router.__file__)
FRESH = "sha256:" + "0" * 64


def _digest():
    import hashlib

    return "sha256:" + hashlib.sha256(b"task-router").hexdigest()


def _basic_router():
    r = TaskRouter()
    r.register_worker("w1", seq=1, capacity=2)
    r.register_worker("w2", seq=2, capacity=2)
    r.register_route("jobs", seq=3)
    return r


def test_version_and_schema_pins():
    assert TASK_ROUTER_VERSION == "task-router.v1"
    assert SCHEMA_PIN == "northstar.task-router.v1"
    assert "round-robin" in POLICIES and "least-loaded" in POLICIES


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    allowed = {"hashlib", "threading", "dataclasses", "typing", "__future__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_register_worker_roundtrip_and_verify():
    r = TaskRouter()
    rec = r.register_worker("w1", seq=1, capacity=3)
    assert rec.verify()
    assert rec.capacity == 3 and rec.healthy
    assert r.worker("w1") is rec
    assert r.worker_ids() == ("w1",)
    assert r.inflight("w1") == 0


def test_register_worker_bad_inputs():
    r = TaskRouter()
    for bad in ("", "has space", "x" * 257):
        with pytest.raises(TaskRouterError):
            r.register_worker(bad, seq=1)
    r2 = TaskRouter()
    for cap in (0, -1, True, "2", 1.5):
        with pytest.raises(TaskRouterError):
            r2.register_worker("w", seq=1, capacity=cap)


def test_register_worker_duplicate_consumes_seq_and_rejects():
    r = TaskRouter()
    r.register_worker("w1", seq=1)
    with pytest.raises(TaskRouterError):
        r.register_worker("w1", seq=2)
    audit = r.audit_log()
    assert audit[-1]["event"] == "rejected"
    # failed mutation consumed seq 2: next fresh seq is 3
    r.register_route("jobs", seq=3)
    with pytest.raises(SeqOrderError):
        r.route("t", "jobs", seq=2)


def test_register_route_and_bad_policy():
    r = TaskRouter()
    rec = r.register_route("jobs", seq=1, policy="least-loaded")
    assert rec.verify() and rec.policy == "least-loaded"
    assert r.route_ids() == ("jobs",)
    with pytest.raises(TaskRouterError):
        r.register_route("other", seq=2, policy="magic")
    with pytest.raises(TaskRouterError):
        r.register_route("jobs", seq=3)


def test_route_booking_and_duplicate():
    r = _basic_router()
    rec = r.route("t1", "jobs", seq=4)
    assert rec.verify()
    assert r.task("t1") is rec
    assert r.task_ids() == ("t1",)
    with pytest.raises(TaskRouterError):
        r.route("t1", "jobs", seq=5)
    with pytest.raises(TaskRouterError):
        r.route("t2", "nope", seq=6)


def test_dispatch_round_robin_rotation():
    r = _basic_router()
    r.route("t1", "jobs", seq=4)
    r.route("t2", "jobs", seq=5)
    d1 = r.dispatch("t1", seq=6)
    d2 = r.dispatch("t2", seq=7)
    assert d1.verify() and d2.verify()
    assert d1.worker_id == "w1"
    assert d2.worker_id == "w2"  # RR advanced
    assert d1.policy == "round-robin"
    assert r.inflight("w1") == 1 and r.inflight("w2") == 1
    assert r.tasks_for_worker("w2") == ("t2",)
    audit = r.audit_log()
    assert audit[-1]["event"] == "task-dispatched"


def test_dispatch_least_loaded():
    r = TaskRouter()
    r.register_worker("big", seq=1, capacity=10)
    r.register_worker("small", seq=2, capacity=10)
    r.register_route("fast", seq=3, policy="least-loaded")
    for i in (1, 2, 3):
        r.route(f"t{i}", "fast", seq=3 + i)
    r.dispatch("t1", seq=7)  # tie -> registration order -> big
    d2 = r.dispatch("t2", seq=8)
    d3 = r.dispatch("t3", seq=9)
    assert d2.worker_id == "small" and d3.worker_id == "big"


def test_dispatch_fail_closed_no_eligible_worker():
    r = TaskRouter()
    r.register_worker("w1", seq=1, capacity=1)
    r.register_route("jobs", seq=2)
    r.worker_health("w1", False, seq=3)
    r.route("t1", "jobs", seq=4)
    with pytest.raises(NoAvailableWorkerError):
        r.dispatch("t1", seq=5)
    # capacity exhaustion is also a closed door
    r2 = _basic_router()
    r2.register_route("tiny", seq=4)
    r2.worker_health("w1", False, seq=5)
    r2.worker_health("w2", False, seq=6)
    r2.route("t1", "tiny", seq=7)
    with pytest.raises(NoAvailableWorkerError):
        r2.dispatch("t1", seq=8)


def test_dispatch_capacity_exhaustion_and_unhealthy_skip():
    r = _basic_router()
    r.route("t1", "jobs", seq=4)
    r.route("t2", "jobs", seq=5)
    r.route("t3", "jobs", seq=6)
    r.dispatch("t1", seq=7)  # w1
    r.dispatch("t2", seq=8)  # w2
    # mark w2 unhealthy: t3 must land on w1 (still has a free slot)
    r.worker_health("w2", False, seq=9)
    d3 = r.dispatch("t3", seq=10)
    assert d3.worker_id == "w1"


def test_complete_frees_slot_and_terminality():
    r = _basic_router()
    r.route("t1", "jobs", seq=4)
    d = r.dispatch("t1", seq=5)
    rec = r.complete("t1", seq=6)
    assert rec.verify()
    assert r.inflight(d.worker_id) == 0
    assert r.tasks_for_worker(d.worker_id) == ()
    with pytest.raises(TaskRouterError):
        r.complete("t1", seq=7)
    with pytest.raises(TaskRouterError):
        r.complete("ghost", seq=8)


def test_balance_plan_and_unplaceable():
    r = _basic_router()
    r.route("t1", "jobs", seq=4)
    r.route("t2", "jobs", seq=5)
    r.route("t3", "jobs", seq=6)
    report = r.balance(seq=7)
    assert report.verify()
    assert len(report.targets) == 3
    assert report.unplaceable == ()
    # RR over the plan cycles workers, moves nothing
    assert {t.worker_id for t in report.targets} == {"w1", "w2"}
    assert r.queued_tasks() == ("t1", "t2", "t3")
    # starved pass: all unhealthy -> everything unplaceable, as data
    r.worker_health("w1", False, seq=8)
    r.worker_health("w2", False, seq=9)
    report2 = r.balance(seq=10)
    assert report2.unplaceable == ("t1", "t2", "t3")
    assert report2.targets == ()


def test_seq_discipline_rewind_and_bool():
    r = _basic_router()
    r.route("t1", "jobs", seq=4)
    with pytest.raises(SeqOrderError):
        r.route("t2", "jobs", seq=4)
    with pytest.raises(SeqOrderError):
        r.route("t2", "jobs", seq=True)
    with pytest.raises(SeqOrderError):
        r.route("t2", "jobs", seq="5")
    # failed mutation consumed seq 4; a rewind is bare with no audit row
    before = len(r.audit_log())
    with pytest.raises(SeqOrderError):
        r.route("t3", "jobs", seq=3)
    assert len(r.audit_log()) == before


def test_audit_shapes_and_bad_kind():
    r = _basic_router()
    r.route("t1", "jobs", seq=4)
    d = r.dispatch("t1", seq=5)
    kinds = [row["event"] for row in r.audit_log()]
    assert kinds == [
        "worker-registered",
        "worker-registered",
        "route-registered",
        "task-routed",
        "task-dispatched",
    ]
    ev = task_router_audit_event("task-dispatched", 9, task_id="t1", worker_id="w1")
    assert ev["schema"] == "northstar.audit.ndjson/1"
    assert ev["module"] == TASK_ROUTER_VERSION
    assert ev["task_id"] == "t1"
    with pytest.raises(TaskRouterError):
        task_router_audit_event("nope", 1)


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "task-router OK" in result.stdout
