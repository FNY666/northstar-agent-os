"""Tests for batch_processing (Spark/Airflow-shaped batch job bookkeeping)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from batch_processing import (  # noqa: E402
    BATCH_PROCESSING_SCHEMA,
    BATCH_PROCESSING_VERSION,
    AUDIT_SCHEMA,
    BadJobError,
    BadPipelineError,
    BadTaskError,
    BatchProcessing,
    BatchProcessingError,
    DuplicateJobError,
    DuplicatePipelineError,
    JobStateError,
    MaxAttemptsError,
    NothingToRetryError,
    SeqOrderError,
    UnknownJobError,
    UnknownPipelineError,
    batch_processing_audit_event,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "batch_processing.py"


def _fresh(**kwargs):
    bp = BatchProcessing(**kwargs)
    return bp


# 1. version / schema pins -------------------------------------------------


def test_version_and_schema_pins():
    assert BATCH_PROCESSING_VERSION == "batch-processing.v1"
    assert BATCH_PROCESSING_SCHEMA == "northstar.batch-processing.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


# 2. stdlib-only ------------------------------------------------------------


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "json",
        "canonical_json", "__future__", "subprocess", "sys", "pathlib",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top in allowed, f"non-stdlib import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or node.module.split(".")[0] in allowed, (
                f"non-stdlib import: {node.module}"
            )


# 3. submit roundtrip / duplicate / bad inputs -------------------------------


def test_submit_roundtrip_and_duplicate():
    bp = _fresh()
    job = bp.submit_job("job-1", "nightly etl", 1,
                        stages=("extract", "transform", "load"),
                        partitions=4, max_attempts=5)
    assert job.verify()
    assert job.job_id == "job-1"
    assert job.stages == ("extract", "transform", "load")
    assert job.partitions == 4
    assert job.max_attempts == 5
    assert bp.job_ids() == ("job-1",)
    with pytest.raises(DuplicateJobError):
        bp.submit_job("job-1", "other", 2)


def test_submit_bad_inputs():
    bp = _fresh()
    with pytest.raises(BatchProcessingError):
        bp.submit_job("", "x", 1)
    with pytest.raises(BatchProcessingError):
        bp.submit_job("ok-id", "", 2)
    with pytest.raises(BadJobError):
        bp.submit_job("ok-id", "x", 3, stages=())
    with pytest.raises(BadJobError):
        bp.submit_job("ok-id", "x", 4, stages=("a", "a"))
    with pytest.raises(BadJobError):
        bp.submit_job("ok-id", "x", 5, partitions=0)
    with pytest.raises(BadJobError):
        bp.submit_job("ok-id", "x", 6, partitions=1025)
    with pytest.raises(BadJobError):
        bp.submit_job("ok-id", "x", 7, max_attempts=11)
    with pytest.raises(BatchProcessingError):
        bp.submit_job("ok-id", "x", 8, partitions=True)


# 4. seq ordering + failed mutations consume seq -----------------------------


def test_seq_ordering_and_failed_mutation_consumes_seq():
    bp = _fresh()
    bp.submit_job("job-1", "etl", 1)
    with pytest.raises(SeqOrderError):
        bp.submit_job("job-2", "etl", 1)  # rewind
    with pytest.raises(SeqOrderError):
        bp.submit_job("job-2", "etl", True)  # bool refused
    with pytest.raises(SeqOrderError):
        bp.submit_job("job-2", "etl", -1)  # negative refused
    # failed mutation (duplicate) consumes its seq: next must be > 2
    with pytest.raises(DuplicateJobError):
        bp.submit_job("job-1", "etl", 2)
    with pytest.raises(SeqOrderError):
        bp.submit_job("job-2", "etl", 2)
    job2 = bp.submit_job("job-2", "etl", 3)
    assert job2.verify()


# 5. start lifecycle ----------------------------------------------------------


def test_start_lifecycle():
    bp = _fresh()
    bp.submit_job("job-1", "etl", 1)
    assert bp.job("job-1", 2).status == "pending"  # read view, seq not consumed
    started = bp.start_job("job-1", 3)
    assert started.verify()
    assert bp.job("job-1", 4).status == "running"
    with pytest.raises(JobStateError):
        bp.start_job("job-1", 5)  # double start
    with pytest.raises(UnknownJobError):
        bp.start_job("nope", 6)


# 6. complete_task happy path + bad inputs ------------------------------------


def test_complete_task_happy_and_bad_inputs():
    bp = _fresh()
    bp.submit_job("job-1", "etl", 1, stages=("map", "reduce"), partitions=2)
    bp.start_job("job-1", 2)
    task = bp.complete_task("job-1", "map", 1, 3, True, "sha256:" + "b" * 64)
    assert task.verify()
    assert task.attempt == 1 and task.ok is True
    assert task.prev_task_id == ""
    with pytest.raises(BadTaskError):
        bp.complete_task("job-1", "bogus-stage", 0, 4, True)
    with pytest.raises(BadTaskError):
        bp.complete_task("job-1", "map", 2, 5, True)  # partition out of range
    with pytest.raises(BadTaskError):
        bp.complete_task("job-1", "map", 0, 6, "yes")  # ok not bool
    with pytest.raises(BadTaskError):
        bp.complete_task("job-1", "map", 0, 7, True, "not-a-digest")
    with pytest.raises(UnknownJobError):
        bp.complete_task("nope", "map", 0, 8, True)


def test_complete_task_requires_start():
    bp = _fresh()
    bp.submit_job("job-1", "etl", 1)
    with pytest.raises(JobStateError):
        bp.complete_task("job-1", "extract", 0, 2, True)


# 7. failure as data + retry chain + max attempts -----------------------------


def test_failure_is_data_and_retry_chain():
    bp = _fresh()
    bp.submit_job("job-1", "etl", 1, stages=("extract",), partitions=1,
                  max_attempts=3)
    bp.start_job("job-1", 2)
    fail = bp.complete_task("job-1", "extract", 0, 3, False)
    assert fail.ok is False  # failure is data, not raised
    intent = bp.retry_task("job-1", "extract", 0, 4)
    assert intent.verify()
    assert intent.next_attempt == 2
    ok = bp.complete_task("job-1", "extract", 0, 5, True)
    assert ok.attempt == 2
    assert ok.prev_task_id == fail.task_id
    assert bp.job("job-1", 6).status == "succeeded"


def test_max_attempts_exhaustion():
    bp = _fresh()
    bp.submit_job("job-1", "etl", 1, stages=("extract",), partitions=1,
                  max_attempts=2)
    bp.start_job("job-1", 2)
    bp.complete_task("job-1", "extract", 0, 3, False)
    bp.complete_task("job-1", "extract", 0, 4, False)
    with pytest.raises(MaxAttemptsError):
        bp.retry_task("job-1", "extract", 0, 5)
    with pytest.raises(MaxAttemptsError):
        bp.complete_task("job-1", "extract", 0, 6, True)
    summary = bp.job("job-1", 7)
    assert summary.status == "failed"
    assert summary.failed_units == 1


# 8. retry refusals ------------------------------------------------------------


def test_retry_refusals():
    bp = _fresh()
    bp.submit_job("job-1", "etl", 1, stages=("extract",), partitions=1)
    bp.start_job("job-1", 2)
    with pytest.raises(NothingToRetryError):
        bp.retry_task("job-1", "extract", 0, 3)  # nothing recorded yet
    bp.complete_task("job-1", "extract", 0, 4, True)
    with pytest.raises(NothingToRetryError):
        bp.retry_task("job-1", "extract", 0, 5)  # latest already ok
    with pytest.raises(BadTaskError):
        bp.retry_task("job-1", "bogus", 0, 6)


# 9. job summary status derivation ----------------------------------------------


def test_job_summary_status_derivation():
    bp = _fresh()
    bp.submit_job("job-1", "etl", 1, stages=("a", "b"), partitions=2)
    summary = bp.job("job-1", 2)
    assert summary.verify()
    assert summary.status == "pending"
    assert summary.total_units == 4
    bp.start_job("job-1", 3)
    bp.complete_task("job-1", "a", 0, 4, True)
    bp.complete_task("job-1", "a", 1, 5, True)
    running = bp.job("job-1", 6)
    assert running.status == "running"
    assert running.completed_units == 2
    bp.complete_task("job-1", "b", 0, 7, True)
    bp.complete_task("job-1", "b", 1, 8, True)
    done = bp.job("job-1", 9)
    assert done.status == "succeeded"
    assert done.completed_units == 4
    assert done.failed_units == 0


# 10. cancel terminal ------------------------------------------------------------


def test_cancel_terminal():
    bp = _fresh()
    bp.submit_job("job-1", "etl", 1)
    bp.start_job("job-1", 2)
    cancelled = bp.cancel_job("job-1", 3, "superseded")
    assert cancelled.verify()
    assert bp.job("job-1", 4).status == "cancelled"
    with pytest.raises(JobStateError):
        bp.cancel_job("job-1", 5)  # double cancel
    with pytest.raises(JobStateError):
        bp.start_job("job-1", 6)  # start after cancel
    with pytest.raises(JobStateError):
        bp.complete_task("job-1", "extract", 0, 7, True)
    with pytest.raises(UnknownJobError):
        bp.cancel_job("nope", 8)


# 11. schedule pipeline ------------------------------------------------------------


def test_schedule_pipeline_roundtrip_and_bad_inputs():
    bp = _fresh()
    pipe = bp.schedule("pipe-1", "nightly-etl", 1,
                       stages=("extract", "load"), partitions=2,
                       period_seq=100, max_attempts=4)
    assert pipe.verify()
    assert pipe.last_fire_seq == -1
    assert bp.pipeline_ids() == ("pipe-1",)
    with pytest.raises(DuplicatePipelineError):
        bp.schedule("pipe-1", "x", 2)
    with pytest.raises(BadPipelineError):
        bp.schedule("pipe-2", "x", 3, period_seq=0)
    with pytest.raises(BadPipelineError):
        bp.schedule("pipe-2", "", 4)
    with pytest.raises(BatchProcessingError):
        bp.schedule("", "x", 5)


# 12. due fires and advances -------------------------------------------------------


def test_due_fires_and_advances():
    bp = _fresh()
    bp.schedule("pipe-a", "etl-a", 1, period_seq=10)
    bp.schedule("pipe-b", "etl-b", 2, period_seq=100)
    first = bp.due(3)
    assert first.verify()
    assert first.pipeline_ids == ("pipe-a", "pipe-b")
    early = bp.due(4)
    assert early.pipeline_ids == ()  # neither period elapsed
    later = bp.due(13)
    assert later.pipeline_ids == ("pipe-a",)  # only 10-unit period elapsed
    much_later = bp.due(103)
    assert much_later.pipeline_ids == ("pipe-a", "pipe-b")
    # due consumes seq: rewind refused
    with pytest.raises(SeqOrderError):
        bp.due(103)


# 13. audit shapes + banned keys + bad kind -------------------------------------------


def test_audit_shapes_and_banned_keys():
    bp = _fresh()
    bp.submit_job("job-1", "etl", 1)
    bp.start_job("job-1", 2)
    bp.complete_task("job-1", "extract", 0, 3, True)
    bp.schedule("pipe-1", "etl", 4, period_seq=5)
    bp.due(5)
    log = bp.audit_log()
    kinds = [e["kind"] for e in log]
    assert kinds == [
        "batch.job-submitted",
        "batch.job-started",
        "batch.task-completed",
        "batch.pipeline-scheduled",
        "batch.pipelines-due",
    ]
    for event in log:
        assert event["schema"] == "audit.ndjson/1"
        assert event["module"] == "batch_processing"
        assert "output" not in event["detail"]
        assert "payload" not in event["detail"]
    # banned keys refused
    with pytest.raises(BatchProcessingError):
        batch_processing_audit_event("batch.job-submitted", 9, output="x")
    # bad kind refused
    with pytest.raises(BatchProcessingError):
        batch_processing_audit_event("batch.bogus", 9)
    # rejected rows are booked on refusal
    with pytest.raises(DuplicateJobError):
        bp.submit_job("job-1", "etl", 6)
    assert bp.audit_log()[-1]["kind"] == "batch.rejected"


# 14. views ----------------------------------------------------------------------------


def test_views_tasks_for_and_stats():
    bp = _fresh()
    bp.submit_job("job-1", "etl", 1, stages=("extract",), partitions=1)
    bp.start_job("job-1", 2)
    t1 = bp.complete_task("job-1", "extract", 0, 3, False)
    intent = bp.retry_task("job-1", "extract", 0, 4)
    t2 = bp.complete_task("job-1", "extract", 0, 5, True)
    tasks = bp.tasks_for("job-1")
    assert [t.task_id for t in tasks] == [t1.task_id, t2.task_id]
    assert bp.task_record(t2.task_id).attempt == 2
    assert intent.next_attempt == 2
    with pytest.raises(BadTaskError):
        bp.task_record("task-999")
    with pytest.raises(UnknownJobError):
        bp.tasks_for("nope")
    stats = bp.stats()
    assert stats == {
        "jobs": 1, "started": 1, "cancelled": 0,
        "tasks": 2, "pipelines": 0, "audit_events": len(bp.audit_log()),
    }


# 15. main() self-check + concurrency -----------------------------------------------------


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "batch-processing OK" in result.stdout


def test_concurrent_submit_threadsafe():
    bp = _fresh()
    errors = []
    seq_lock = threading.Lock()
    seq_box = [0]

    def next_seq():
        with seq_lock:
            seq_box[0] += 1
            return seq_box[0]

    def worker(i):
        # Genuine contention: threads race into the module and back off
        # on SeqOrderError with a fresher seq until their job lands.
        seq = next_seq()
        for _ in range(64):
            try:
                bp.submit_job(f"job-{i}", "etl", seq)
                return
            except SeqOrderError:
                seq = next_seq()
            except BatchProcessingError as exc:  # noqa: BLE001
                errors.append(exc)
                return
        errors.append(RuntimeError(f"worker {i} never landed"))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len(bp.job_ids()) == 8
