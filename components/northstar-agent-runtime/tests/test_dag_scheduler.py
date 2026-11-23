"""Tests for dag_scheduler: Airflow-shaped DAG bookkeeping."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import dag_scheduler
from dag_scheduler import (
    KIND_ADDED,
    KIND_REJECTED,
    KIND_RETRIED,
    KIND_RUN,
    SCHEMA,
    VERSION,
    BadTaskError,
    DAGError,
    DAGScheduler,
    DuplicateRunError,
    DuplicateTaskError,
    RetryRecord,
    RunRecord,
    SeqOrderError,
    SelfDependencyError,
    TaskAttempt,
    TaskInUseError,
    TaskNotFailedError,
    TaskRecord,
    UnknownDependencyError,
    UnknownRunError,
    UnknownTaskError,
    dag_scheduler_audit_event,
)


# ---------------------------------------------------------------------------
# 1. pins, stdlib, main
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert VERSION == "dag-scheduler.v1"
    assert SCHEMA == "northstar.dag-scheduler.v1"
    assert VERSION in SCHEMA.replace("northstar.", "dag-scheduler")


def test_stdlib_only():
    tree = ast.parse(Path(dag_scheduler.__file__).read_text())
    allowed = {"__future__", "hashlib", "threading", "dataclasses", "typing",
               "json", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, dag_scheduler.__file__],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "dag-scheduler OK" in proc.stdout


# ---------------------------------------------------------------------------
# 2. add / remove
# ---------------------------------------------------------------------------


def test_add_roundtrip_and_verify():
    s = DAGScheduler()
    rec = s.add("extract", 1)
    assert isinstance(rec, TaskRecord)
    assert rec.depends_on == ()
    assert rec.verify()
    assert s.task_record("extract") is rec
    assert s.task_ids() == ("extract",)


def test_add_with_dependencies_sorted_deduped():
    s = DAGScheduler()
    s.add("a", 1)
    s.add("b", 2)
    rec = s.add("c", 3, depends_on=("b", "a", "b"))
    assert rec.depends_on == ("a", "b")
    assert rec.verify()


def test_add_bad_inputs_fail_closed():
    s = DAGScheduler()
    for bad in ("", "has space", "x" * 257, 123, None, True):
        with pytest.raises(DAGError):
            s.add(bad, 1)  # type: ignore[arg-type]


def test_add_duplicate_and_retired_refused():
    s = DAGScheduler()
    s.add("a", 1)
    s.add("leaf", 2)
    with pytest.raises(DuplicateTaskError):
        s.add("a", 3)
    s.remove("leaf", 4)
    with pytest.raises(DuplicateTaskError):
        s.add("leaf", 5)


def test_add_unknown_dependency_refused():
    s = DAGScheduler()
    with pytest.raises(UnknownDependencyError):
        s.add("a", 1, depends_on=("ghost",))


def test_add_self_dependency_refused():
    s = DAGScheduler()
    s.add("a", 1)
    with pytest.raises(SelfDependencyError):
        s.add("e", 2, depends_on=("a", "e"))
    with pytest.raises(SelfDependencyError):
        s.add("e", 3, depends_on=("e",))


def test_remove_leaf_and_retirement():
    s = DAGScheduler()
    s.add("a", 1)
    s.add("b", 2, depends_on=("a",))
    with pytest.raises(TaskInUseError):
        s.remove("a", 3)
    s.remove("b", 4)
    assert s.task_ids() == ("a",)
    s.remove("a", 5)
    assert s.task_ids() == ()
    with pytest.raises(UnknownTaskError):
        s.remove("a", 6)


# ---------------------------------------------------------------------------
# 3. ordering + run
# ---------------------------------------------------------------------------


def test_topological_order_diamond():
    s = DAGScheduler()
    s.add("a", 1)
    s.add("b", 2, depends_on=("a",))
    s.add("c", 3, depends_on=("a",))
    s.add("d", 4, depends_on=("b", "c"))
    assert s.topological_order(0) == ("a", "b", "c", "d")


def test_topological_order_deterministic_across_instances():
    def build():
        s = DAGScheduler()
        s.add("z", 1)
        s.add("m", 2, depends_on=("z",))
        s.add("q", 3, depends_on=("z",))
        s.add("w", 4, depends_on=("m", "q"))
        return s.topological_order(0)

    assert build() == build() == ("z", "m", "q", "w")


def test_topological_order_is_pure_read():
    s = DAGScheduler()
    s.add("a", 5)
    before = s.stats(0)["last_seq"]
    assert s.topological_order(5) == ("a",)
    assert s.topological_order(4) == ("a",)  # rewind allowed on views
    assert s.stats(0)["last_seq"] == before


def test_run_books_attempts_in_order():
    s = DAGScheduler()
    s.add("a", 1)
    s.add("b", 2, depends_on=("a",))
    run = s.run("r1", 3, failures=("b",))
    assert isinstance(run, RunRecord)
    assert run.verify()
    assert run.order == ("a", "b")
    got = {a.task_id: (a.status, a.attempt) for a in run.attempts}
    assert got == {"a": ("success", 1), "b": ("failed", 1)}
    assert all(a.verify() for a in run.attempts)


def test_run_duplicate_and_unknown_failure_refused():
    s = DAGScheduler()
    s.add("a", 1)
    s.run("r1", 2)
    with pytest.raises(DuplicateRunError):
        s.run("r1", 3)
    with pytest.raises(UnknownTaskError):
        s.run("r2", 4, failures=("ghost",))


def test_run_on_empty_graph():
    s = DAGScheduler()
    run = s.run("r1", 1)
    assert run.order == ()
    assert run.attempts == ()
    assert run.verify()


# ---------------------------------------------------------------------------
# 4. retry
# ---------------------------------------------------------------------------


def test_retry_failed_task_books_success():
    s = DAGScheduler()
    s.add("a", 1)
    s.add("b", 2, depends_on=("a",))
    s.run("r1", 3, failures=("b",))
    rec = s.retry("r1", "b", 4)
    assert isinstance(rec, RetryRecord)
    assert rec.attempt == 2
    assert rec.verify()
    assert s.retries_for("r1") == (rec,)


def test_retry_nonfailed_refused():
    s = DAGScheduler()
    s.add("a", 1)
    s.run("r1", 2)
    with pytest.raises(TaskNotFailedError):
        s.retry("r1", "a", 3)
    # After a successful retry the task is no longer failed.
    s2 = DAGScheduler()
    s2.add("a", 1)
    s2.run("r1", 2, failures=("a",))
    s2.retry("r1", "a", 3)
    with pytest.raises(TaskNotFailedError):
        s2.retry("r1", "a", 4)


def test_retry_unknown_run_or_task_refused():
    s = DAGScheduler()
    s.add("a", 1)
    s.run("r1", 2, failures=("a",))
    with pytest.raises(UnknownRunError):
        s.retry("nope", "a", 3)
    with pytest.raises(UnknownTaskError):
        s.retry("r1", "ghost", 4)


# ---------------------------------------------------------------------------
# 5. seq discipline, audit, views
# ---------------------------------------------------------------------------


def test_seq_ordering_and_failed_mutation_consumes_seq():
    s = DAGScheduler()
    s.add("a", 1)
    with pytest.raises(SeqOrderError):
        s.add("b", 1)  # rewind: bare raise, nothing booked
    assert s.task_record("b") is None
    with pytest.raises(UnknownDependencyError):
        s.add("b", 2, depends_on=("ghost",))  # failed mutation burns seq 2
    assert s.audit_log()[-1]["kind"] == KIND_REJECTED
    with pytest.raises(SeqOrderError):
        s.add("b", 2)  # seq 2 was consumed
    rec = s.add("b", 3)
    assert rec.verify()
    for bad in (True, -1, "3", 3.0, None):
        with pytest.raises(SeqOrderError):
            s.add("x", bad)  # type: ignore[arg-type]


def test_audit_shapes_and_banned_keys():
    s = DAGScheduler()
    s.add("a", 1)
    s.run("r1", 2, failures=("a",))
    s.retry("r1", "a", 3)
    kinds = [row["kind"] for row in s.audit_log()]
    assert kinds == [KIND_ADDED, KIND_RUN, KIND_RETRIED]
    for row in s.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == VERSION
        assert isinstance(row["seq"], int)
    with pytest.raises(dag_scheduler.AuditKindError):
        dag_scheduler_audit_event("nope", {}, 1)
    with pytest.raises(dag_scheduler.AuditKindError):
        dag_scheduler_audit_event(KIND_ADDED, {"payload": "x"}, 1)


def test_stats_and_views():
    s = DAGScheduler()
    s.add("a", 1)
    s.add("b", 2, depends_on=("a",))
    s.run("r1", 3)
    stats = s.stats(0)
    assert stats == {"tasks": 2, "retired": 0, "runs": 1,
                     "retries": 0, "last_seq": 3}
    assert s.run_ids() == ("r1",)
    assert isinstance(s.run_record("r1"), RunRecord)
    assert s.run_record("nope") is None
    assert s.task_record("nope") is None


def test_concurrent_add_thread_safe():
    s = DAGScheduler()
    errors = []

    def worker(i):
        try:
            s.add(f"t{i}", 1000 + i)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len(s.task_ids()) == 8


def test_frozen_records_immutable():
    s = DAGScheduler()
    rec = s.add("a", 1)
    with pytest.raises(Exception):
        rec.task_id = "b"  # type: ignore[misc]
    run = s.run("r1", 2)
    with pytest.raises(Exception):
        run.order = ()  # type: ignore[misc]
    att = TaskAttempt(task_id="a", status="success", attempt=1)
    assert att.verify()
