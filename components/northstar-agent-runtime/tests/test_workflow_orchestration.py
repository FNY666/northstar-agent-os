"""Tests for workflow_orchestration (15 tests)."""

import ast
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, "..")

import workflow_orchestration as wo
from workflow_orchestration import WorkflowOrchestration


def _orch():
    return WorkflowOrchestration()


def _tasks(**kw):
    base = {"extract": {"max_retries": 2, "backoff_seq": 10},
            "transform": {"max_retries": 1},
            "load": {}}
    base.update(kw)
    return base


_DEPS = [["extract", "transform"], ["transform", "load"]]


def test_version_and_schema_pins():
    assert wo.WORKFLOW_ORCHESTRATION_VERSION == "workflow-orchestration.v1"
    assert wo.WORKFLOW_ORCHESTRATION_SCHEMA == (
        "northstar.workflow-orchestration.v1"
    )
    assert wo.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(open(wo.__file__).read())
    allowed = {"hashlib", "json", "dataclasses", "threading", "typing",
               "__future__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_dag_roundtrip_verify_and_topo():
    orch = _orch()
    dag = orch.dag("etl", 1, _tasks(), _DEPS)
    assert dag.record_id == "dag-1"
    assert dag.topo_order == ("extract", "transform", "load")
    assert dag.verify()
    assert dag.retry_policy("extract") == (2, 10)
    assert dag.retry_policy("load") == (0, 0)


def test_dag_duplicate_and_bad_inputs():
    orch = _orch()
    orch.dag("etl", 1, _tasks(), _DEPS)
    with pytest.raises(wo.DuplicateDAGError):
        orch.dag("etl", 2, _tasks(), _DEPS)
    # empty dag id
    with pytest.raises(wo.WorkflowOrchestrationError):
        orch.dag("", 3, _tasks(), _DEPS)
    # empty tasks mapping
    with pytest.raises(wo.WorkflowOrchestrationError):
        orch.dag("x", 4, {}, [])
    # self-loop
    with pytest.raises(wo.WorkflowOrchestrationError):
        orch.dag("y", 5, _tasks(), [["extract", "extract"]])
    # unknown endpoint
    with pytest.raises(wo.WorkflowOrchestrationError):
        orch.dag("z", 6, _tasks(), [["extract", "nope"]])
    # cycle
    with pytest.raises(wo.WorkflowOrchestrationError):
        orch.dag("w", 7, _tasks(),
                 [["extract", "transform"], ["transform", "extract"]])


def test_failed_mutation_consumes_seq():
    orch = _orch()
    orch.dag("etl", 1, _tasks(), _DEPS)
    with pytest.raises(wo.DuplicateDAGError):
        orch.dag("etl", 2, _tasks(), _DEPS)  # fails, but burns seq 2
    with pytest.raises(wo.SeqOrderError):
        orch.dag("etl2", 2, _tasks(), _DEPS)  # rewind refused
    dag = orch.dag("etl2", 3, _tasks(), _DEPS)
    assert dag.record_id == "dag-2"
    kinds = [e["kind"] for e in orch.audit_log()]
    assert kinds == [wo.KIND_DAG_REGISTERED, wo.KIND_REJECTED,
                    wo.KIND_DAG_REGISTERED], kinds


def test_execute_roundtrip():
    orch = _orch()
    orch.dag("etl", 1, _tasks(), _DEPS)
    run = orch.execute("etl", 2)
    assert run.run_id == "run-1" and run.verify()
    insts = orch.task_instances(run.run_id)
    assert [i.task_id for i in insts] == ["extract", "transform", "load"]
    assert all(i.state == "pending" and i.verify() for i in insts)
    assert orch.run_status(run.run_id) == "running"
    with pytest.raises(wo.UnknownDAGError):
        orch.execute("nope", 3)


def test_complete_task_in_order():
    orch = _orch()
    orch.dag("etl", 1, _tasks(), _DEPS)
    run = orch.execute("etl", 2)
    orch.complete_task(run.run_id, "extract", 3, True)
    orch.complete_task(run.run_id, "transform", 4, True)
    orch.complete_task(run.run_id, "load", 5, True,
                       result_digest="sha256:" + "cd" * 32)
    assert orch.run_status(run.run_id) == "succeeded"
    insts = {i.task_id: i for i in orch.task_instances(run.run_id)}
    assert insts["load"].last_result_digest == "sha256:" + "cd" * 32


def test_complete_task_readiness_and_bad_inputs():
    orch = _orch()
    orch.dag("etl", 1, _tasks(), _DEPS)
    run = orch.execute("etl", 2)
    # out of order: transform before extract
    with pytest.raises(wo.TaskNotReadyError):
        orch.complete_task(run.run_id, "transform", 3, True)
    # unknown task
    with pytest.raises(wo.UnknownTaskError):
        orch.complete_task(run.run_id, "nope", 4, True)
    # non-bool ok
    with pytest.raises(wo.BadCompletionError):
        orch.complete_task(run.run_id, "extract", 5, 1)
    # double completion
    orch.complete_task(run.run_id, "extract", 6, True)
    with pytest.raises(wo.BadCompletionError):
        orch.complete_task(run.run_id, "extract", 7, True)
    # bad digest shape
    with pytest.raises(wo.BadCompletionError):
        orch.complete_task(run.run_id, "transform", 8, True,
                           result_digest="not-a-digest")


def test_failure_is_data_and_retry_cycle():
    orch = _orch()
    orch.dag("etl", 1, _tasks(), _DEPS)
    run = orch.execute("etl", 2)
    orch.complete_task(run.run_id, "extract", 3, True)
    orch.complete_task(run.run_id, "transform", 4, False)
    assert orch.run_status(run.run_id) == "failed"
    ret = orch.retry(run.run_id, "transform", 5)
    assert ret.retry_id == "retry-1" and ret.verify()
    assert ret.backoff_until_seq == 5  # seq 5 + backoff_seq 0 (default)
    inst = [i for i in orch.task_instances(run.run_id)
            if i.task_id == "transform"][0]
    assert inst.state == "pending" and inst.attempts == 1
    orch.complete_task(run.run_id, "transform", 6, True)
    orch.complete_task(run.run_id, "load", 7, True)
    assert orch.run_status(run.run_id) == "succeeded"


def test_retry_exhaustion_and_refusals():
    orch = _orch()
    orch.dag("etl", 1, _tasks(), _DEPS)
    run = orch.execute("etl", 2)
    orch.complete_task(run.run_id, "extract", 3, True)
    orch.complete_task(run.run_id, "transform", 4, False)
    orch.retry(run.run_id, "transform", 5)   # retry #1 (max_retries=1)
    orch.complete_task(run.run_id, "transform", 6, False)
    with pytest.raises(wo.MaxAttemptsError):
        orch.retry(run.run_id, "transform", 7)  # budget exhausted
    # retry a succeeded task
    with pytest.raises(wo.BadRetryError):
        orch.retry(run.run_id, "extract", 8)
    # retry unknown run
    with pytest.raises(wo.UnknownRunError):
        orch.retry("run-9", "transform", 9)
    # load (max_retries=0) fails once -> no retry at all: fresh orch so the
    # terminally-failed transform above does not block the load check
    orch2 = _orch()
    orch2.dag("etl2", 1, _tasks(), _DEPS)
    run2 = orch2.execute("etl2", 2)
    orch2.complete_task(run2.run_id, "extract", 3, True)
    orch2.complete_task(run2.run_id, "transform", 4, True)
    orch2.complete_task(run2.run_id, "load", 5, False)
    with pytest.raises(wo.MaxAttemptsError):
        orch2.retry(run2.run_id, "load", 6)


def test_cancel_run_terminal():
    orch = _orch()
    orch.dag("etl", 1, _tasks(), _DEPS)
    run = orch.execute("etl", 2)
    orch.complete_task(run.run_id, "extract", 3, True)
    orch.cancel_run(run.run_id, 4, reason="operator stop")
    assert orch.run_status(run.run_id) == "cancelled"
    with pytest.raises(wo.TerminalRunError):
        orch.complete_task(run.run_id, "transform", 5, True)
    with pytest.raises(wo.TerminalRunError):
        orch.cancel_run(run.run_id, 6)


def test_seq_ordering_and_bool_refusal():
    orch = _orch()
    orch.dag("etl", 1, _tasks(), _DEPS)
    with pytest.raises(wo.SeqOrderError):
        orch.dag("etl2", 1, _tasks(), _DEPS)   # not strictly greater
    with pytest.raises(wo.SeqOrderError):
        orch.dag("etl2", True, _tasks(), _DEPS)  # bool is not int
    with pytest.raises(wo.SeqOrderError):
        orch.dag("etl2", -1, _tasks(), _DEPS)  # negative


def test_audit_shapes_and_banned_keys():
    orch = _orch()
    orch.dag("etl", 1, _tasks(), _DEPS)
    run = orch.execute("etl", 2)
    for ev in orch.audit_log():
        assert ev["schema"] == "audit.ndjson/1"
        assert ev["module"] == "workflow_orchestration"
        assert ev["module_version"] == wo.WORKFLOW_ORCHESTRATION_VERSION
        for k in ev["detail"]:
            assert k not in wo._BANNED_AUDIT_KEYS, k
    assert orch.stats() == {"dags": 1, "runs": 1, "task_instances": 3,
                            "retries": 0, "audit_events": 2}
    with pytest.raises(wo.WorkflowOrchestrationError):
        wo.workflow_orchestration_audit_event("bogus", 3)


def test_concurrency():
    orch = _orch()
    orch.dag("etl", 1, _tasks(), _DEPS)
    run = orch.execute("etl", 2)
    errors = []

    def worker(i):
        try:
            orch.complete_task(run.run_id, "extract", 3 + i, True)
        except wo.WorkflowOrchestrationError:
            pass
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    inst = [i for i in orch.task_instances(run.run_id)
            if i.task_id == "extract"][0]
    assert inst.state == "succeeded" and inst.attempts == 1


def test_main_self_check():
    r = subprocess.run([sys.executable, wo.__file__],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "workflow-orchestration OK" in r.stdout
