"""Tests for activity_worker.py (Temporal-activities-shaped ledger)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import activity_worker as _aw
from activity_worker import (
    ACTIVITY_WORKER_SCHEMA,
    ACTIVITY_WORKER_VERSION,
    ActivityWorker,
    ActivityWorkerError,
    BadDigestError,
    BadErrorTypeError,
    DuplicateActivityError,
    DuplicateTaskError,
    HeartbeatRecord,
    SeqOrderError,
    TaskStateError,
    UnknownActivityError,
    UnknownTaskError,
    activity_worker_audit_event,
)


@pytest.fixture
def worker():
    return ActivityWorker("worker-1", "default")


@pytest.fixture
def ready_worker():
    w = ActivityWorker("worker-1", "default")
    w.register_activity("send-email", 1)
    return w


def _digest(s):
    import hashlib

    return "sha256:" + hashlib.sha256(s.encode()).hexdigest()


# 1. version pins
def test_version_pins():
    assert ACTIVITY_WORKER_VERSION == "activity-worker.v1"
    assert ACTIVITY_WORKER_SCHEMA == "northstar.activity-worker.v1"


# 2. stdlib-only AST check
def test_stdlib_only():
    src = Path(_aw.__file__).read_text()
    tree = ast.parse(src)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                imports.add(node.module.split(".")[0])
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "json",
        "canonical_json",
    }
    assert imports <= allowed, f"non-stdlib imports: {imports - allowed}"


# 3. register_activity roundtrip
def test_register_activity(worker):
    rec = worker.register_activity("send-email", 1)
    assert rec.verify()
    assert worker.activity_type("send-email") is rec
    assert worker.activity_types() == ("send-email",)


# 4. duplicate registration refused + rejected audit row
def test_register_duplicate(worker):
    worker.register_activity("send-email", 1)
    with pytest.raises(DuplicateActivityError):
        worker.register_activity("send-email", 2)
    kinds = [r["kind"] for r in worker.audit_log()]
    assert "activity-worker.rejected" in kinds


# 5. execute roundtrip + status running
def test_execute(ready_worker):
    rec = ready_worker.execute("tok-1", "send-email", 2, _digest("args"))
    assert rec.verify()
    assert ready_worker.status("tok-1") == "running"
    assert ready_worker.execution("tok-1") is rec


# 6. execute unknown activity type refused
def test_execute_unknown_activity(worker):
    with pytest.raises(UnknownActivityError):
        worker.execute("tok-1", "nope", 1)
    with pytest.raises(UnknownTaskError):
        worker.execution("tok-1")


# 7. heartbeat books + heartbeat_seq counts
def test_heartbeat(ready_worker):
    ready_worker.execute("tok-1", "send-email", 2)
    h1 = ready_worker.heartbeat("tok-1", 3, _digest("half"))
    h2 = ready_worker.heartbeat("tok-1", 4)
    assert isinstance(h1, HeartbeatRecord)
    assert (h1.heartbeat_seq, h2.heartbeat_seq) == (1, 2)
    assert h1.verify()
    beats = ready_worker.heartbeats("tok-1")
    assert [b.heartbeat_seq for b in beats] == [1, 2]


# 8. complete terminal + later mutations refused
def test_complete_terminal(ready_worker):
    ready_worker.execute("tok-1", "send-email", 2)
    rec = ready_worker.complete("tok-1", 3, _digest("result"))
    assert rec.verify()
    assert ready_worker.status("tok-1") == "completed"
    with pytest.raises(TaskStateError):
        ready_worker.heartbeat("tok-1", 4)
    with pytest.raises(TaskStateError):
        ready_worker.fail("tok-1", 5, "application")


# 9. fail + cancel terminal
def test_fail_and_cancel(ready_worker):
    ready_worker.execute("tok-a", "send-email", 2)
    f = ready_worker.fail("tok-a", 3, "timeout")
    assert f.error_type == "timeout"
    assert f.verify()
    ready_worker.execute("tok-b", "send-email", 4)
    c = ready_worker.cancel("tok-b", 5, reason="workflow-cancel")
    assert c.reason == "workflow-cancel"
    assert c.verify()
    assert ready_worker.status("tok-b") == "cancelled"


# 10. seq discipline: malformed / rewind raise; failed claims burn nothing
def test_seq_discipline(worker):
    with pytest.raises(SeqOrderError):
        worker.register_activity("x", True)
    with pytest.raises(SeqOrderError):
        worker.register_activity("x", -1)
    worker.register_activity("x", 1)
    with pytest.raises(SeqOrderError):
        worker.register_activity("y", 1)  # rewind raises bare, consumes nothing
    worker.register_activity("y", 2)  # fresh seq works
    assert worker.activity_types() == ("x", "y")


# 11. bad digest + bad error-type refused
def test_bad_inputs(ready_worker):
    with pytest.raises(BadDigestError):
        ready_worker.execute("tok-1", "send-email", 2, "not-a-digest")
    ready_worker.execute("tok-1", "send-email", 3)
    with pytest.raises(BadErrorTypeError):
        ready_worker.fail("tok-1", 4, "exploded")


# 12. audit shapes + banned keys + bad kind
def test_audit_shapes(ready_worker):
    ready_worker.execute("tok-1", "send-email", 2, _digest("args"))
    ev = ready_worker.audit_log()[1]
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["kind"] == "activity-worker.started"
    assert ev["module_version"] == "activity-worker.v1"
    assert "payload" not in ev["detail"]
    with pytest.raises(ActivityWorkerError):
        activity_worker_audit_event(
            "activity-worker.started", 1, payload="raw-bytes"
        )
    with pytest.raises(ActivityWorkerError):
        activity_worker_audit_event("nope", 1)


# 13. views are pure (no seq consumption, no audit rows)
def test_views_pure(ready_worker):
    ready_worker.execute("tok-1", "send-email", 2)
    n_before = len(ready_worker.audit_log())
    ready_worker.stats(3)
    ready_worker.executions()
    ready_worker.status("tok-1")
    assert len(ready_worker.audit_log()) == n_before
    stats = ready_worker.stats(2)  # rewound seq allowed on pure read
    assert stats["executions"] == 1
    assert stats["heartbeats"] == 0


# 14. unknown task refuses on all paths
def test_unknown_task(ready_worker):
    with pytest.raises(UnknownTaskError):
        ready_worker.heartbeat("ghost", 2)
    with pytest.raises(UnknownTaskError):
        ready_worker.complete("ghost", 3)
    with pytest.raises(UnknownTaskError):
        ready_worker.fail("ghost", 4, "application")


# 15. main() self-check via subprocess
def test_main_self_check():
    path = Path(_aw.__file__)
    out = subprocess.run(
        [sys.executable, str(path)], capture_output=True, text=True
    )
    assert out.returncode == 0, out.stderr
    assert "activity-worker OK" in out.stdout
