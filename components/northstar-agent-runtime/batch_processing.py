"""Batch processing: Spark/Airflow-shaped batch data-job bookkeeping.

Research motivation: batch jobs decide *what* untrusted compute runs
over *which* data, in *what order*. In an agent runtime the batch
ledger is part of the policy surface -- a job that silently drops a
stage bypasses validation, a task whose outcome the module cannot pin
is a confused deputy, and a pipeline that fires twice double-writes
downstream tables. This module is the *bookkeeping* half of batch
processing: it pins job definitions, books host-reported task outcomes
as data, derives job status deterministically, and answers "which
recurring pipelines are due at logical seq S". It never executes
anything, never spawns threads, never reads the clock -- the host
applies due-sets and runs tasks through its own executor, reporting
outcomes back as data.

This is deliberately distinct from ``job_scheduler`` (cron-style
*when*-to-fire scheduling of payloads): batch processing is
Spark-shaped *data* jobs (stages x partitions, map/shuffle/reduce or
extract/transform/load) plus Airflow-shaped recurring *pipelines*
(period-based, e.g. "every N logical units").

Public API:

- ``BatchProcessing`` -- RLock-guarded registry.
  ``submit_job(job_id, name, seq, stages=(), partitions=1,
  max_attempts=3)`` pins a job definition; ``start_job(job_id, seq)``
  moves pending -> running; ``complete_task(job_id, stage, partition,
  seq, ok, output_digest="")`` books a host-reported task outcome
  (failures are *data*, never raised); ``retry_task(job_id, stage,
  partition, seq)`` returns a frozen ``RetryIntent`` authorizing the
  next attempt -- the *decision* to retry is audited and
  budget-checked, the outcome still arrives via ``complete_task``;
  ``cancel_job(job_id, seq, reason="")`` is terminal.
  ``job(job_id)`` returns a pure ``JobSummary`` view whose status is
  derived from booked task records (never stored).
  ``schedule(pipeline_id, job_name, seq, stages=(), partitions=1,
  period_seq=1, max_attempts=3)`` pins a recurring pipeline;
  ``due(seq)`` returns the frozen set of pipelines due at logical
  seq and advances their last-fire markers (consumes seq).
- ``batch_processing_audit_event(kind, seq, **detail)`` --
  ``audit.ndjson/1`` records with a fixed kind vocabulary; raw
  outputs/payloads never cross the audit boundary (ids + digest
  pins only).

House style: frozen dataclasses, caller-supplied strictly increasing
int seqs (no wall-clock), RLock-guarded, fail-closed taxonomy,
stdlib-only plus the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, ``audit.ndjson/1`` events, version pin
``batch-processing.v1``, schema pin
``northstar.batch-processing.v1``, ``main()`` self-check.

Honest scope: this module books *host-reported* task outcomes --
an "ok" task means the host reported success, never that the data is
correct; it cannot detect unreported tasks, verify output bytes
(digests are pinned but never inspected), or prove a pipeline fired
exactly once downstream. Task verdicts are data; status derivation is
deterministic over the booked ledger only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
BATCH_PROCESSING_VERSION = "batch-processing.v1"

#: Schema pin carried by records and audit events.
BATCH_PROCESSING_SCHEMA = "northstar.batch-processing.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

_GENESIS = "genesis"

# Bounds.
_MAX_STAGES = 16
_MAX_STAGE_LEN = 64
_MAX_PARTITIONS = 1024
_MAX_ATTEMPTS = 10
_MAX_JOB_ID_LEN = 128
_MAX_NAME_LEN = 256


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class BatchProcessingError(ValueError):
    """Base for all batch-processing structural problems and refused transitions."""


class BadJobError(BatchProcessingError):
    """Job definition is malformed (bad id, name, stages, partitions)."""


class DuplicateJobError(BatchProcessingError):
    """A job id is already registered."""


class UnknownJobError(BatchProcessingError):
    """No job is pinned for the requested id."""


class JobStateError(BatchProcessingError):
    """The job is in a state that refuses this transition."""


class BadTaskError(BatchProcessingError):
    """Task booking is malformed (bad stage, partition, digest, outcome)."""


class NothingToRetryError(BatchProcessingError):
    """The latest task attempt succeeded; there is nothing to retry."""


class MaxAttemptsError(BatchProcessingError):
    """The task already exhausted its attempt budget."""


class BadPipelineError(BatchProcessingError):
    """Pipeline definition is malformed (bad id, period, job template)."""


class DuplicatePipelineError(BatchProcessingError):
    """A pipeline id is already registered."""


class UnknownPipelineError(BatchProcessingError):
    """No pipeline is pinned for the requested id."""


class SeqOrderError(BatchProcessingError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_id(value: Any, name: str, max_len: int = _MAX_JOB_ID_LEN) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BatchProcessingError(f"{name} must be a non-empty string")
    cleaned = value.strip()
    if len(cleaned) > max_len:
        raise BatchProcessingError(f"{name} exceeds {max_len} chars")
    if any(ch.isspace() or ord(ch) < 32 for ch in cleaned):
        raise BatchProcessingError(f"{name} must not contain whitespace/control chars")
    return cleaned


def _check_stages(value: Any) -> Tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or not value:
        raise BadJobError("stages must be a non-empty tuple/list of names")
    if len(value) > _MAX_STAGES:
        raise BadJobError(f"at most {_MAX_STAGES} stages")
    stages: List[str] = []
    for s in value:
        if not isinstance(s, str) or not s.strip():
            raise BadJobError("each stage must be a non-empty string")
        name = s.strip()
        if len(name) > _MAX_STAGE_LEN:
            raise BadJobError(f"stage name exceeds {_MAX_STAGE_LEN} chars")
        stages.append(name)
    if len(set(stages)) != len(stages):
        raise BadJobError("stage names must be unique")
    return tuple(stages)


def _check_positive_int(value: Any, name: str, cap: int, exc: type) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise exc(f"{name} must be an int")
    if value < 1 or value > cap:
        raise exc(f"{name} must be in [1, {cap}]")
    return value


def _check_digest(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise BadTaskError(f"{name} must be a string")
    if value == "":
        return ""
    if not value.startswith("sha256:") or len(value) != 7 + 64:
        raise BadTaskError(f"{name} must be '' or 'sha256:' + 64 hex chars")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadTaskError(f"{name} must be '' or 'sha256:' + 64 hex chars")
    return value


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([BATCH_PROCESSING_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JobRecord:
    """One pinned batch-job definition (frozen)."""

    job_id: str
    name: str
    stages: Tuple[str, ...]
    partitions: int
    max_attempts: int
    seq: int
    digest: str
    schema: str = BATCH_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "job", self.job_id, self.name, list(self.stages),
            self.partitions, self.max_attempts, self.seq,
        )


@dataclass(frozen=True)
class JobStartedRecord:
    """One job start (frozen)."""

    job_id: str
    seq: int
    digest: str
    schema: str = BATCH_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("start", self.job_id, self.seq)


@dataclass(frozen=True)
class TaskRecord:
    """One booked task outcome (frozen). ``ok=False`` is data."""

    task_id: str
    job_id: str
    stage: str
    partition: int
    attempt: int
    ok: bool
    output_digest: str
    prev_task_id: str
    seq: int
    digest: str
    schema: str = BATCH_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "task", self.task_id, self.job_id, self.stage, self.partition,
            self.attempt, self.ok, self.output_digest, self.prev_task_id,
            self.seq,
        )


@dataclass(frozen=True)
class RetryIntent:
    """An authorized retry slot (frozen). Not a task outcome.

    The host reports the retried attempt's real outcome through
    ``complete_task``, which mints attempt ``next_attempt`` from the
    chain. The intent exists so the *decision* to retry is auditable
    and budget-checked, separate from the outcome booking.
    """

    job_id: str
    stage: str
    partition: int
    next_attempt: int
    seq: int
    digest: str
    schema: str = BATCH_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "retry-intent", self.job_id, self.stage, self.partition,
            self.next_attempt, self.seq,
        )


@dataclass(frozen=True)
class JobCancelRecord:
    """One terminal job cancellation (frozen)."""

    job_id: str
    reason: str
    seq: int
    digest: str
    schema: str = BATCH_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("cancel", self.job_id, self.reason, self.seq)


@dataclass(frozen=True)
class PipelineRecord:
    """One pinned recurring batch pipeline (frozen)."""

    pipeline_id: str
    job_name: str
    stages: Tuple[str, ...]
    partitions: int
    max_attempts: int
    period_seq: int
    last_fire_seq: int  # -1 until the first due() fires it
    seq: int
    digest: str
    schema: str = BATCH_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "pipeline", self.pipeline_id, self.job_name, list(self.stages),
            self.partitions, self.max_attempts, self.period_seq, self.seq,
        )


@dataclass(frozen=True)
class DueReport:
    """Pipelines due at a logical seq (frozen, pure data)."""

    pipeline_ids: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = BATCH_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("due", list(self.pipeline_ids), self.seq)


@dataclass(frozen=True)
class JobSummary:
    """Derived job status view (frozen). Status is computed, never stored."""

    job_id: str
    status: str  # pending | running | succeeded | failed | cancelled
    stages: Tuple[str, ...]
    partitions: int
    max_attempts: int
    total_units: int
    completed_units: int
    failed_units: int
    seq: int
    digest: str
    schema: str = BATCH_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "summary", self.job_id, self.status, list(self.stages),
            self.partitions, self.max_attempts, self.total_units,
            self.completed_units, self.failed_units, self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_JOB_SUBMITTED = "batch.job-submitted"
KIND_JOB_STARTED = "batch.job-started"
KIND_TASK_COMPLETED = "batch.task-completed"
KIND_TASK_RETRIED = "batch.task-retried"
KIND_JOB_CANCELLED = "batch.job-cancelled"
KIND_PIPELINE_SCHEDULED = "batch.pipeline-scheduled"
KIND_PIPELINES_DUE = "batch.pipelines-due"
KIND_REJECTED = "batch.rejected"
_KINDS = (
    KIND_JOB_SUBMITTED, KIND_JOB_STARTED, KIND_TASK_COMPLETED,
    KIND_TASK_RETRIED, KIND_JOB_CANCELLED, KIND_PIPELINE_SCHEDULED,
    KIND_PIPELINES_DUE, KIND_REJECTED,
)

# Raw outputs/payloads never cross the audit boundary.
_BANNED_DETAIL_KEYS = {"output", "data", "payload", "bytes", "content"}


def batch_processing_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for batch processing."""
    if kind not in _KINDS:
        raise BatchProcessingError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if any(k in detail for k in _BANNED_DETAIL_KEYS):
        raise BatchProcessingError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "batch_processing",
        "module_version": BATCH_PROCESSING_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class BatchProcessing:
    """Deterministic batch-job bookkeeping (Spark/Airflow-shaped).

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position). Read views
    validate the seq shape, consume nothing, and write no audit rows.
    """

    def __init__(self, seed: str = "") -> None:
        self._lock = threading.RLock()
        self._seed = seed
        self._last_seq = -1
        self._jobs: Dict[str, JobRecord] = {}
        self._started: Dict[str, JobStartedRecord] = {}
        self._cancelled: Dict[str, JobCancelRecord] = {}
        self._tasks: Dict[str, TaskRecord] = {}
        # latest task id per (job_id, stage, partition)
        self._latest: Dict[Tuple[str, str, int], str] = {}
        self._pipelines: Dict[str, PipelineRecord] = {}
        self._task_counter = 0
        self._audit_log: List[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(
            batch_processing_audit_event(kind, seq, **detail)
        )

    def _reject(self, seq: int, reason: str) -> None:
        # Seq already consumed by _next_seq; only book the refusal.
        self._emit(KIND_REJECTED, seq, reason=reason)

    def _require_job(self, job_id: str) -> JobRecord:
        job_id = _check_id(job_id, "job_id")
        job = self._jobs.get(job_id)
        if job is None:
            raise UnknownJobError(f"unknown job: {job_id!r}")
        return job

    def _require_live_job(self, job_id: str) -> JobRecord:
        job = self._require_job(job_id)
        if job_id in self._cancelled:
            raise JobStateError(f"job is cancelled: {job_id!r}")
        return job

    # -- jobs ----------------------------------------------------------

    def submit_job(
        self,
        job_id: str,
        name: str,
        seq: int,
        stages: Tuple[str, ...] = ("extract", "transform", "load"),
        partitions: int = 1,
        max_attempts: int = 3,
    ) -> JobRecord:
        """Pin a batch-job definition."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                job_id = _check_id(job_id, "job_id")
                if not isinstance(name, str) or not name.strip():
                    raise BadJobError("name must be a non-empty string")
                clean_name = name.strip()
                if len(clean_name) > _MAX_NAME_LEN:
                    raise BadJobError(f"name exceeds {_MAX_NAME_LEN} chars")
                stage_tuple = _check_stages(stages)
                partitions = _check_positive_int(
                    partitions, "partitions", _MAX_PARTITIONS, BadJobError
                )
                max_attempts = _check_positive_int(
                    max_attempts, "max_attempts", _MAX_ATTEMPTS, BadJobError
                )
                if job_id in self._jobs:
                    raise DuplicateJobError(f"job already registered: {job_id!r}")
            except BatchProcessingError as exc:
                self._reject(seq, str(exc))
                raise
            digest = _pin(
                "job", job_id, clean_name, list(stage_tuple), partitions,
                max_attempts, seq,
            )
            record = JobRecord(
                job_id=job_id, name=clean_name, stages=stage_tuple,
                partitions=partitions, max_attempts=max_attempts, seq=seq,
                digest=digest,
            )
            self._jobs[job_id] = record
            self._emit(
                KIND_JOB_SUBMITTED, seq, job_id=job_id,
                stages=list(stage_tuple), partitions=partitions,
                max_attempts=max_attempts, digest=digest,
            )
            return record

    def start_job(self, job_id: str, seq: int) -> JobStartedRecord:
        """Move a job from pending to running."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                job = self._require_live_job(job_id)
                if job.job_id in self._started:
                    raise JobStateError(f"job already started: {job.job_id!r}")
            except BatchProcessingError as exc:
                self._reject(seq, str(exc))
                raise
            digest = _pin("start", job.job_id, seq)
            record = JobStartedRecord(job_id=job.job_id, seq=seq, digest=digest)
            self._started[job.job_id] = record
            self._emit(KIND_JOB_STARTED, seq, job_id=job.job_id, digest=digest)
            return record

    def complete_task(
        self,
        job_id: str,
        stage: str,
        partition: int,
        seq: int,
        ok: bool,
        output_digest: str = "",
    ) -> TaskRecord:
        """Book a host-reported task outcome. ``ok=False`` is data."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                job = self._require_live_job(job_id)
                if job.job_id not in self._started:
                    raise JobStateError(f"job not started: {job.job_id!r}")
                if not isinstance(stage, str) or stage.strip() not in job.stages:
                    raise BadTaskError(
                        f"unknown stage {stage!r} for job {job.job_id!r}"
                    )
                clean_stage = stage.strip()
                if isinstance(partition, bool) or not isinstance(partition, int):
                    raise BadTaskError("partition must be an int")
                if partition < 0 or partition >= job.partitions:
                    raise BadTaskError(
                        f"partition must be in [0, {job.partitions})"
                    )
                if not isinstance(ok, bool):
                    raise BadTaskError("ok must be a bool")
                clean_digest = _check_digest(output_digest, "output_digest")
            except BatchProcessingError as exc:
                self._reject(seq, str(exc))
                raise
            key = (job.job_id, clean_stage, partition)
            prev_id = self._latest.get(key, "")
            prev = self._tasks[prev_id] if prev_id else None
            attempt = (prev.attempt + 1) if prev else 1
            if prev is not None and prev.attempt >= job.max_attempts:
                self._reject(seq, "attempt budget exhausted")
                raise MaxAttemptsError(
                    f"task budget exhausted for {job.job_id}/{clean_stage}/{partition}"
                )
            self._task_counter += 1
            task_id = f"task-{self._task_counter}"
            digest = _pin(
                "task", task_id, job.job_id, clean_stage, partition, attempt,
                ok, clean_digest, prev_id, seq,
            )
            record = TaskRecord(
                task_id=task_id, job_id=job.job_id, stage=clean_stage,
                partition=partition, attempt=attempt, ok=ok,
                output_digest=clean_digest, prev_task_id=prev_id, seq=seq,
                digest=digest,
            )
            self._tasks[task_id] = record
            self._latest[key] = task_id
            self._emit(
                KIND_TASK_COMPLETED, seq, task_id=task_id, job_id=job.job_id,
                stage=clean_stage, partition=partition, attempt=attempt,
                ok=ok, digest=digest,
            )
            return record

    def retry_task(
        self, job_id: str, stage: str, partition: int, seq: int
    ) -> RetryIntent:
        """Authorize a retry slot for a failed task unit.

        Returns a frozen ``RetryIntent`` naming the ``next_attempt``
        the host may report via ``complete_task``. The intent is the
        auditable *decision* to retry; it books no outcome. Refused
        when the latest attempt succeeded (``NothingToRetryError``),
        no task was ever recorded, or the attempt budget is exhausted
        (``MaxAttemptsError``).
        """
        with self._lock:
            seq = self._next_seq(seq)
            try:
                job = self._require_live_job(job_id)
                if job.job_id not in self._started:
                    raise JobStateError(f"job not started: {job.job_id!r}")
                if not isinstance(stage, str) or stage.strip() not in job.stages:
                    raise BadTaskError(
                        f"unknown stage {stage!r} for job {job.job_id!r}"
                    )
                clean_stage = stage.strip()
                if isinstance(partition, bool) or not isinstance(partition, int):
                    raise BadTaskError("partition must be an int")
                if partition < 0 or partition >= job.partitions:
                    raise BadTaskError(
                        f"partition must be in [0, {job.partitions})"
                    )
                key = (job.job_id, clean_stage, partition)
                prev_id = self._latest.get(key)
                if prev_id is None:
                    raise NothingToRetryError(
                        f"no task recorded for {job.job_id}/{clean_stage}/{partition}"
                    )
                prev = self._tasks[prev_id]
                if prev.ok:
                    raise NothingToRetryError(
                        f"latest attempt already succeeded: {prev_id}"
                    )
                next_attempt = prev.attempt + 1
                if next_attempt > job.max_attempts:
                    raise MaxAttemptsError(
                        f"task budget exhausted for {job.job_id}/{clean_stage}/{partition}"
                    )
            except BatchProcessingError as exc:
                self._reject(seq, str(exc))
                raise
            digest = _pin(
                "retry-intent", job.job_id, clean_stage, partition,
                next_attempt, seq,
            )
            intent = RetryIntent(
                job_id=job.job_id, stage=clean_stage, partition=partition,
                next_attempt=next_attempt, seq=seq, digest=digest,
            )
            self._emit(
                KIND_TASK_RETRIED, seq, job_id=job.job_id,
                stage=clean_stage, partition=partition,
                next_attempt=next_attempt, prev_task_id=prev_id,
                digest=digest,
            )
            return intent

    def cancel_job(
        self, job_id: str, seq: int, reason: str = ""
    ) -> JobCancelRecord:
        """Terminally cancel a job. Cancelled jobs refuse all transitions."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                job = self._require_job(job_id)
                if job.job_id in self._cancelled:
                    raise JobStateError(f"job already cancelled: {job.job_id!r}")
                if not isinstance(reason, str):
                    raise BadJobError("reason must be a string")
                clean_reason = reason.strip()
            except BatchProcessingError as exc:
                self._reject(seq, str(exc))
                raise
            digest = _pin("cancel", job.job_id, clean_reason, seq)
            record = JobCancelRecord(
                job_id=job.job_id, reason=clean_reason, seq=seq, digest=digest
            )
            self._cancelled[job.job_id] = record
            self._emit(
                KIND_JOB_CANCELLED, seq, job_id=job.job_id,
                reason=clean_reason, digest=digest,
            )
            return record

    # -- views ---------------------------------------------------------

    def _derive_status(self, job: JobRecord) -> Tuple[str, int, int]:
        if job.job_id in self._cancelled:
            total = len(job.stages) * job.partitions
            return "cancelled", 0, total
        if job.job_id not in self._started:
            total = len(job.stages) * job.partitions
            return "pending", 0, total
        completed = 0
        failed = 0
        exhausted = False
        for stage in job.stages:
            for partition in range(job.partitions):
                latest_id = self._latest.get((job.job_id, stage, partition))
                if latest_id is None:
                    continue
                latest = self._tasks[latest_id]
                if latest.ok:
                    completed += 1
                elif latest.attempt >= job.max_attempts:
                    failed += 1
                    exhausted = True
        total = len(job.stages) * job.partitions
        if exhausted:
            return "failed", completed, failed
        if completed == total:
            return "succeeded", completed, failed
        return "running", completed, failed

    def job(self, job_id: str, seq: int) -> JobSummary:
        """Pure derived status view. Validates seq shape, consumes nothing."""
        with self._lock:
            _check_seq(seq, "seq")
            job = self._require_job(job_id)
            status, completed, failed = self._derive_status(job)
            total = len(job.stages) * job.partitions
            digest = _pin(
                "summary", job.job_id, status, list(job.stages),
                job.partitions, job.max_attempts, total, completed, failed,
                seq,
            )
            return JobSummary(
                job_id=job.job_id, status=status, stages=job.stages,
                partitions=job.partitions, max_attempts=job.max_attempts,
                total_units=total, completed_units=completed,
                failed_units=failed, seq=seq, digest=digest,
            )

    # -- pipelines -----------------------------------------------------

    def schedule(
        self,
        pipeline_id: str,
        job_name: str,
        seq: int,
        stages: Tuple[str, ...] = ("extract", "transform", "load"),
        partitions: int = 1,
        period_seq: int = 1,
        max_attempts: int = 3,
    ) -> PipelineRecord:
        """Pin a recurring batch pipeline (fires every ``period_seq``)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                pipeline_id = _check_id(pipeline_id, "pipeline_id")
                if not isinstance(job_name, str) or not job_name.strip():
                    raise BadPipelineError("job_name must be a non-empty string")
                clean_name = job_name.strip()
                if len(clean_name) > _MAX_NAME_LEN:
                    raise BadPipelineError(
                        f"job_name exceeds {_MAX_NAME_LEN} chars"
                    )
                stage_tuple = _check_stages(stages)
                partitions = _check_positive_int(
                    partitions, "partitions", _MAX_PARTITIONS, BadPipelineError
                )
                period_seq = _check_positive_int(
                    period_seq, "period_seq", 2**31 - 1, BadPipelineError
                )
                max_attempts = _check_positive_int(
                    max_attempts, "max_attempts", _MAX_ATTEMPTS, BadPipelineError
                )
                if pipeline_id in self._pipelines:
                    raise DuplicatePipelineError(
                        f"pipeline already registered: {pipeline_id!r}"
                    )
            except BatchProcessingError as exc:
                self._reject(seq, str(exc))
                raise
            digest = _pin(
                "pipeline", pipeline_id, clean_name, list(stage_tuple),
                partitions, max_attempts, period_seq, seq,
            )
            record = PipelineRecord(
                pipeline_id=pipeline_id, job_name=clean_name,
                stages=stage_tuple, partitions=partitions,
                max_attempts=max_attempts, period_seq=period_seq,
                last_fire_seq=-1, seq=seq, digest=digest,
            )
            self._pipelines[pipeline_id] = record
            self._emit(
                KIND_PIPELINE_SCHEDULED, seq, pipeline_id=pipeline_id,
                period_seq=period_seq, digest=digest,
            )
            return record

    def due(self, seq: int) -> DueReport:
        """Return pipelines due at logical seq; advances last-fire markers."""
        with self._lock:
            seq = self._next_seq(seq)
            due_ids: List[str] = []
            for pid in sorted(self._pipelines):
                pipe = self._pipelines[pid]
                if pipe.last_fire_seq < 0 or seq - pipe.last_fire_seq >= pipe.period_seq:
                    due_ids.append(pid)
                    self._pipelines[pid] = PipelineRecord(
                        pipeline_id=pipe.pipeline_id, job_name=pipe.job_name,
                        stages=pipe.stages, partitions=pipe.partitions,
                        max_attempts=pipe.max_attempts,
                        period_seq=pipe.period_seq, last_fire_seq=seq,
                        seq=pipe.seq, digest=pipe.digest,
                    )
            digest = _pin("due", due_ids, seq)
            report = DueReport(
                pipeline_ids=tuple(due_ids), seq=seq, digest=digest
            )
            self._emit(
                KIND_PIPELINES_DUE, seq,
                pipeline_ids=list(due_ids), digest=digest,
            )
            return report

    # -- more views ----------------------------------------------------

    def job_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._jobs))

    def pipeline_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._pipelines))

    def task_record(self, task_id: str) -> TaskRecord:
        with self._lock:
            if not isinstance(task_id, str):
                raise BadTaskError("task_id must be a string")
            record = self._tasks.get(task_id)
            if record is None:
                raise BadTaskError(f"unknown task: {task_id!r}")
            return record

    def tasks_for(self, job_id: str) -> Tuple[TaskRecord, ...]:
        with self._lock:
            self._require_job(job_id)
            return tuple(
                sorted(
                    (t for t in self._tasks.values() if t.job_id == job_id),
                    key=lambda t: t.seq,
                )
            )

    def stats(self) -> Mapping[str, int]:
        with self._lock:
            return {
                "jobs": len(self._jobs),
                "started": len(self._started),
                "cancelled": len(self._cancelled),
                "tasks": len(self._tasks),
                "pipelines": len(self._pipelines),
                "audit_events": len(self._audit_log),
            }

    def audit_log(self) -> Tuple[Mapping[str, Any], ...]:
        with self._lock:
            return tuple(self._audit_log)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    bp = BatchProcessing()
    job = bp.submit_job("job-1", "nightly-etl", 1,
                        stages=("extract", "transform", "load"),
                        partitions=2, max_attempts=3)
    assert job.verify()
    bp.start_job("job-1", 2)
    t1 = bp.complete_task("job-1", "extract", 0, 3, True, "sha256:" + "a" * 64)
    assert t1.verify() and t1.attempt == 1
    t2 = bp.complete_task("job-1", "extract", 0, 4, False)
    assert t2.attempt == 2
    intent = bp.retry_task("job-1", "extract", 0, 5)
    assert intent.verify() and intent.next_attempt == 3
    t3 = bp.complete_task("job-1", "extract", 0, 6, True)
    assert t3.verify() and t3.attempt == 3
    assert t3.prev_task_id == t2.task_id
    summary = bp.job("job-1", 7)
    assert summary.verify() and summary.status == "running"
    pipe = bp.schedule("pipe-1", "nightly-etl", 8, period_seq=10)
    assert pipe.verify()
    due = bp.due(9)
    assert due.verify() and due.pipeline_ids == ("pipe-1",)
    due2 = bp.due(10)
    assert due2.pipeline_ids == ()  # period not elapsed
    due3 = bp.due(19)
    assert due3.pipeline_ids == ("pipe-1",)
    cancelled = bp.cancel_job("job-1", 20, "superseded")
    assert cancelled.verify()
    assert bp.job("job-1", 21).status == "cancelled"
    # refused transitions consume seq and stay fail-closed
    for bad in (
        lambda: bp.submit_job("job-1", "x", 22),
        lambda: bp.start_job("job-1", 23),
        lambda: bp.retry_task("job-1", "extract", 0, 24),  # latest ok
        lambda: bp.schedule("pipe-1", "x", 25),
    ):
        try:
            bad()
        except BatchProcessingError:
            pass
        else:
            raise AssertionError("expected refusal")
    # budget exhaustion: fail attempts 1..2 with max_attempts=2
    bp2 = BatchProcessing()
    bp2.submit_job("job-2", "etl", 1, stages=("extract",), partitions=1,
                   max_attempts=2)
    bp2.start_job("job-2", 2)
    bp2.complete_task("job-2", "extract", 0, 3, False)
    bp2.complete_task("job-2", "extract", 0, 4, False)
    try:
        bp2.retry_task("job-2", "extract", 0, 5)
    except MaxAttemptsError:
        pass
    else:
        raise AssertionError("expected MaxAttemptsError")
    assert bp2.job("job-2", 6).status == "failed"
    print("batch-processing OK: submit, start, task, retry, summary, pipeline, due, cancel")


if __name__ == "__main__":
    main()
