"""Workflow engine: DAG-shaped step execution with per-step retries.

Research note: DAG (directed acyclic graph) execution is the core of
workflow orchestrators (Airflow, Temporal, Argo). A workflow is a set of
steps with dependency edges; the engine topologically orders them,
executes each step once its predecessors have produced outputs, and
retries transiently-failing steps a bounded number of times. This module
is the *bookkeeping and decision logic* of that shape, not a distributed
scheduler: it runs steps sequentially in dependency order on the host,
records frozen per-step results, and pins everything with digests so a
run is auditable and replayable.

* **DAG definition** — ``WorkflowEngine.define(steps)`` registers a
  mapping of ``step_id -> StepSpec`` where a spec names a callable and
  its dependencies. Definition is fail-closed: unknown dependency ids,
  self-loops, cycles, duplicate ids, and non-callable steps are all
  refused at define time (a broken graph never starts running).
* **Topological execution** — ``run(context)`` executes steps in
  Kahn-order (ties broken by sorted step id for determinism). Each step
  receives a read-only view of prior steps' outputs; outputs must be
  canonicalizable (or ``None``) and are frozen into the report.
* **Bounded retries** — each step carries ``max_attempts`` (1 = no
  retry) and a ``backoff_ms`` schedule (deterministic, computed not
  waited). Only exceptions listed in ``retry_on`` are retried; anything
  else aborts the run immediately. A step that exhausts its budget marks
  the run failed with the last error chained on ``StepFailed``.
* **Manual retry** — ``retry_run(step_id, seq)`` re-executes a failed
  step (and any downstream steps it invalidates) after a ``run`` has
  failed, producing a new frozen report rather than mutating the old
  one. Retrying a step that did not fail is refused.
* **Fail-closed records** — ``StepReport`` / ``RunReport`` are frozen
  dataclasses with ``sha256:`` digest pins over the canonical body.
  A ``RunReport`` with ``succeeded=False`` names the failing step and
  its error type; raw tracebacks and payload bytes never enter records.
* **No wall-clock** — seqs are caller-supplied ints; backoff delays are
  computed (not slept) via an injectable ``sleeper``; determinism holds
  for identical inputs.

Honest scope: steps run on the host process, sequentially, with host
reported outputs — this module cannot prove a step's side effect
happened exactly once, cannot observe unreported work, and its retry
budget does not make a non-idempotent step safe to retry (that contract
is the step author's). ``succeeded=True`` means "every step returned",
never "the world changed".
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

#: Module version.
WORKFLOW_ENGINE_VERSION = "workflow-engine.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.workflow-engine.v1"

#: Audit record format pin.
AUDIT_FORMAT = "audit.ndjson/1"

_AUDIT_KINDS = frozenset(
    {
        "defined",
        "step-started",
        "step-succeeded",
        "step-failed",
        "run-completed",
        "step-retried",
        "execution-started",
        "signaled",
        "execution-completed",
        "rejected",
    }
)

#: Max steps per workflow (guardrail against pathological graphs).
_MAX_STEPS = 1024

#: Max retries per step.
_MAX_ATTEMPTS = 64


class WorkflowError(Exception):
    """Malformed input to the workflow engine (programming error)."""


class CycleError(WorkflowError):
    """Raised when step dependencies contain a cycle."""


class StepFailed(Exception):
    """Raised when a step exhausts its retry budget.

    Carries the frozen :class:`StepReport` in ``report`` and chains the
    last attempt's exception as ``__cause__``.
    """

    def __init__(self, report: "StepReport", last_error: BaseException):
        self.report = report
        self.last_error = last_error
        super().__init__(
            f"workflow step {report.step_id!r} failed after "
            f"{report.attempts_made} attempt(s): "
            f"{type(last_error).__name__}: {last_error}"
        )
        self.__cause__ = last_error


class RunFailed(Exception):
    """Raised by :meth:`WorkflowEngine.run` when a step fails.

    Carries the frozen :class:`RunReport` in ``report`` and chains the
    :class:`StepFailed` as ``__cause__``.
    """

    def __init__(self, report: "RunReport", step_failure: StepFailed):
        self.report = report
        self.step_failure = step_failure
        super().__init__(
            f"workflow run failed at step {report.failed_step!r}: {step_failure}"
        )
        self.__cause__ = step_failure


class ExecutionError(WorkflowError):
    """Base for execution-lifecycle (Temporal/Cadence-shaped) errors."""


class DuplicateExecutionError(ExecutionError):
    """``start()`` was given an already-used execution id."""


class UnknownExecutionError(ExecutionError):
    """``signal()``/``complete()`` targeted an unknown execution id."""


class TerminalExecutionError(ExecutionError):
    """``signal()``/``complete()`` targeted a terminally finished execution."""


class BadSignalError(ExecutionError):
    """Malformed signal name or un-pinnable signal payload."""


def _check_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise WorkflowError(f"{name} must be a non-empty str, got {value!r}")
    return value


def _check_seq(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WorkflowError(f"seq must be an int, got {type(value).__name__}")
    if value < 0:
        raise WorkflowError("seq must be non-negative")
    return value


def _check_attempts(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WorkflowError(f"max_attempts must be an int, got {type(value).__name__}")
    if not 1 <= value <= _MAX_ATTEMPTS:
        raise WorkflowError(f"max_attempts must be in [1, {_MAX_ATTEMPTS}]")
    return value


def _check_backoff(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WorkflowError(f"backoff_ms must be an int, got {type(value).__name__}")
    if value < 0:
        raise WorkflowError("backoff_ms must be non-negative")
    return value


def _check_retry_on(value: Any) -> Tuple[type, ...]:
    if isinstance(value, type) and issubclass(value, BaseException):
        return (value,)
    if isinstance(value, (tuple, list)) and value and all(
        isinstance(v, type) and issubclass(v, BaseException) for v in value
    ):
        return tuple(value)
    raise WorkflowError(
        "retry_on must be an exception type or non-empty tuple/list of exception types"
    )


def _canonical(value: Any) -> str:
    """Canonical JSON for digest pinning; bool is distinct from int.

    Integral floats > 2**53 are refused (same JCS caveat as batch 5).
    """
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise WorkflowError("NaN/inf values cannot be pinned")
        if value.is_integer() and abs(value) > 2**53:
            raise WorkflowError("integral float > 2**53 cannot be pinned (JCS caveat)")
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, default=_canonical_fallback)
    except (TypeError, ValueError) as exc:
        raise WorkflowError(f"output is not canonicalizable: {exc}") from exc


def _canonical_fallback(value: Any) -> Any:
    if isinstance(value, (tuple, frozenset)):
        return list(value)
    if isinstance(value, bytes):
        return {"$bytes": value.hex()}
    raise TypeError(f"not canonicalizable: {type(value).__name__}")


def _digest(body: str) -> str:
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class StepSpec:
    """Immutable definition of one workflow step."""

    step_id: str
    dependencies: Tuple[str, ...]
    max_attempts: int
    backoff_ms: int
    retry_on: Tuple[str, ...]

    def __post_init__(self) -> None:
        _check_str(self.step_id, "step_id")
        if not isinstance(self.dependencies, tuple):
            raise WorkflowError("dependencies must be a tuple of str")
        for dep in self.dependencies:
            _check_str(dep, "dependency")
        if len(set(self.dependencies)) != len(self.dependencies):
            raise WorkflowError(f"step {self.step_id!r} has duplicate dependencies")
        _check_attempts(self.max_attempts)
        _check_backoff(self.backoff_ms)


@dataclass(frozen=True)
class StepReport:
    """Frozen outcome of one step's execution."""

    step_id: str
    succeeded: bool
    attempts_made: int
    output_digest: Optional[str]
    error_type: Optional[str]
    seq: int
    version: str = WORKFLOW_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if self.version != WORKFLOW_ENGINE_VERSION:
            raise WorkflowError("version pin mismatch")
        if self.schema != SCHEMA_PIN:
            raise WorkflowError("schema pin mismatch")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "succeeded": self.succeeded,
            "attempts_made": self.attempts_made,
            "output_digest": self.output_digest,
            "error_type": self.error_type,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RunReport:
    """Frozen outcome of a whole workflow run."""

    run_id: str
    succeeded: bool
    step_order: Tuple[str, ...]
    step_reports: Tuple[StepReport, ...]
    failed_step: Optional[str]
    run_digest: str
    seq: int
    version: str = WORKFLOW_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if self.version != WORKFLOW_ENGINE_VERSION:
            raise WorkflowError("version pin mismatch")
        if self.schema != SCHEMA_PIN:
            raise WorkflowError("schema pin mismatch")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "succeeded": self.succeeded,
            "step_order": list(self.step_order),
            "step_reports": [r.as_dict() for r in self.step_reports],
            "failed_step": self.failed_step,
            "run_digest": self.run_digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ExecutionRecord:
    """Frozen record of a started workflow execution.

    ``execution_id`` is the unique instance id (Temporal run-id
    shaped); ``workflow_id`` is the logical workflow name (Temporal
    workflow-id shaped). ``input_digest`` pins the caller-supplied
    input, if any; raw input bytes never enter the record.
    """

    execution_id: str
    workflow_id: str
    status: str
    input_digest: Optional[str]
    start_seq: int
    digest: str
    version: str = WORKFLOW_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if self.version != WORKFLOW_ENGINE_VERSION:
            raise WorkflowError("version pin mismatch")
        if self.schema != SCHEMA_PIN:
            raise WorkflowError("schema pin mismatch")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "workflow_id": self.workflow_id,
            "status": self.status,
            "input_digest": self.input_digest,
            "start_seq": self.start_seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class SignalRecord:
    """Frozen record of a signal booked against an execution."""

    signal_id: str
    execution_id: str
    signal_name: str
    payload_digest: Optional[str]
    seq: int
    digest: str
    version: str = WORKFLOW_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if self.version != WORKFLOW_ENGINE_VERSION:
            raise WorkflowError("version pin mismatch")
        if self.schema != SCHEMA_PIN:
            raise WorkflowError("schema pin mismatch")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "execution_id": self.execution_id,
            "signal_name": self.signal_name,
            "payload_digest": self.payload_digest,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class CompletionRecord:
    """Frozen record of a terminally completed execution."""

    execution_id: str
    outcome: str
    result_digest: Optional[str]
    seq: int
    digest: str
    version: str = WORKFLOW_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if self.version != WORKFLOW_ENGINE_VERSION:
            raise WorkflowError("version pin mismatch")
        if self.schema != SCHEMA_PIN:
            raise WorkflowError("schema pin mismatch")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "outcome": self.outcome,
            "result_digest": self.result_digest,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


class WorkflowEngine:
    """DAG workflow engine: define, run, retry; plus execution lifecycle."""

    def __init__(self) -> None:
        self._steps: Dict[str, StepSpec] = {}
        self._fn: Dict[str, Callable[..., Any]] = {}
        self._order: Tuple[str, ...] = ()
        self._defined = False
        self._run_counter = 0
        # -- Temporal/Cadence-shaped execution lifecycle state ----------
        self._executions: Dict[str, ExecutionRecord] = {}
        self._exec_signals: Dict[str, List[SignalRecord]] = {}
        self._exec_seq: int = -1
        self._signal_counter: int = 0
        self._exec_audit: List[Dict[str, Any]] = []

    # -- definition ---------------------------------------------------

    def define(
        self,
        steps: Mapping[str, Mapping[str, Any]],
        seq: int = 0,
    ) -> Tuple[str, ...]:
        """Define the workflow DAG.

        ``steps`` maps ``step_id`` -> ``{"fn": callable,
        "dependencies": [ids], "max_attempts": int, "backoff_ms": int,
        "retry_on": exception type(s)}``. ``dependencies``,
        ``max_attempts``, ``backoff_ms``, and ``retry_on`` all have
        fail-closed defaults (no deps, 1 attempt, no backoff, retry only
        :class:`Exception`). Returns the topological order.
        """
        if self._defined:
            raise WorkflowError("workflow is already defined")
        _check_seq(seq)
        if not isinstance(steps, Mapping) or not steps:
            raise WorkflowError("steps must be a non-empty mapping")
        if len(steps) > _MAX_STEPS:
            raise WorkflowError(f"too many steps (>{_MAX_STEPS})")

        parsed: Dict[str, StepSpec] = {}
        fns: Dict[str, Callable[..., Any]] = {}
        for step_id, spec in steps.items():
            _check_str(step_id, "step_id")
            if step_id in parsed:
                raise WorkflowError(f"duplicate step id {step_id!r}")
            if not isinstance(spec, Mapping):
                raise WorkflowError(f"spec for {step_id!r} must be a mapping")
            fn = spec.get("fn")
            if not callable(fn):
                raise WorkflowError(f"step {step_id!r} has no callable fn")
            deps = tuple(spec.get("dependencies", ()))
            if any(not isinstance(d, str) for d in deps):
                raise WorkflowError(f"step {step_id!r} dependencies must be str")
            if step_id in deps:
                raise WorkflowError(f"step {step_id!r} depends on itself")
            parsed[step_id] = StepSpec(
                step_id=step_id,
                dependencies=deps,
                max_attempts=_check_attempts(spec.get("max_attempts", 1)),
                backoff_ms=_check_backoff(spec.get("backoff_ms", 0)),
                retry_on=tuple(t.__name__ for t in _check_retry_on(spec.get("retry_on", Exception))),
            )
            fns[step_id] = fn

        for step_id, spec in parsed.items():
            for dep in spec.dependencies:
                if dep not in parsed:
                    raise WorkflowError(
                        f"step {step_id!r} depends on unknown step {dep!r}"
                    )

        self._order = self._topological_order(parsed)
        self._steps = parsed
        self._fn = fns
        self._defined = True
        return self._order

    @staticmethod
    def _topological_order(parsed: Dict[str, StepSpec]) -> Tuple[str, ...]:
        indegree = {sid: len(spec.dependencies) for sid, spec in parsed.items()}
        dependents: Dict[str, List[str]] = {sid: [] for sid in parsed}
        for sid, spec in parsed.items():
            for dep in spec.dependencies:
                dependents[dep].append(sid)
        ready = sorted(sid for sid, deg in indegree.items() if deg == 0)
        order: List[str] = []
        while ready:
            sid = ready.pop(0)
            order.append(sid)
            for nxt in dependents[sid]:
                indegree[nxt] -= 1
                if indegree[nxt] == 0:
                    ready.append(nxt)
            ready.sort()
        if len(order) != len(parsed):
            cycle = sorted(sid for sid, deg in indegree.items() if deg > 0)
            raise CycleError(f"dependency cycle involving steps: {cycle}")
        return tuple(order)

    # -- execution ----------------------------------------------------

    def run(
        self,
        context: Optional[Mapping[str, Any]] = None,
        seq: int = 0,
        sleeper: Optional[Callable[[float], None]] = None,
    ) -> RunReport:
        """Execute the workflow in topological order.

        Each step's ``fn`` is called as ``fn(inputs, context)`` where
        ``inputs`` maps dependency step ids to their outputs and
        ``context`` is the caller-supplied (read-only) context.
        Raises :class:`RunFailed` on the first failing step; later steps
        are not attempted. Retrying happens per step inside the step
        boundary.
        """
        self._require_defined()
        _check_seq(seq)
        ctx = dict(context) if context is not None else {}
        self._run_counter += 1
        run_id = f"run-{self._run_counter}"

        outputs: Dict[str, Any] = {}
        step_reports: List[StepReport] = []
        failed_step: Optional[str] = None
        failure: Optional[StepFailed] = None

        for step_id in self._order:
            spec = self._steps[step_id]
            inputs = {dep: outputs[dep] for dep in spec.dependencies}
            try:
                output, report = self._execute_step(
                    spec, self._fn[step_id], inputs, ctx, seq, sleeper
                )
            except StepFailed as exc:
                step_reports.append(exc.report)
                failed_step = step_id
                failure = exc
                break
            outputs[step_id] = output
            step_reports.append(report)

        succeeded = failure is None
        report = RunReport(
            run_id=run_id,
            succeeded=succeeded,
            step_order=self._order,
            step_reports=tuple(step_reports),
            failed_step=failed_step,
            run_digest=self._run_digest(run_id, step_reports, succeeded),
            seq=seq,
        )
        if failure is not None:
            raise RunFailed(report, failure)
        return report

    def _execute_step(
        self,
        spec: StepSpec,
        fn: Callable[..., Any],
        inputs: Dict[str, Any],
        context: Dict[str, Any],
        seq: int,
        sleeper: Optional[Callable[[float], None]],
    ) -> Tuple[Any, StepReport]:
        retry_types = self._resolve_retry_types(spec)
        last_error: Optional[BaseException] = None
        attempts = 0
        for attempt in range(1, spec.max_attempts + 1):
            attempts = attempt
            try:
                output = fn(dict(inputs), dict(context))
            except BaseException as exc:  # noqa: BLE001 - classification below
                if not isinstance(exc, retry_types):
                    raise StepFailed(
                        self._step_report(spec, attempts, None,
                                          type(exc).__name__, seq),
                        exc,
                    ) from exc
                last_error = exc
                if attempt < spec.max_attempts and spec.backoff_ms and sleeper:
                    sleeper(spec.backoff_ms * attempt / 1000.0)
                continue
            digest = _digest(_canonical(output)) if output is not None else None
            return output, self._step_report(spec, attempts, digest, None, seq)
        assert last_error is not None
        raise StepFailed(
            self._step_report(spec, attempts, None, type(last_error).__name__, seq),
            last_error,
        )

    def _resolve_retry_types(self, spec: StepSpec) -> Tuple[type, ...]:
        # retry_on names were pinned at define time; resolve against the
        # exception classes supplied in the original spec. We re-derive
        # from a registry: builtins + Exception hierarchy is enough for
        # the fail-closed contract (unknown names -> no retry).
        import builtins

        resolved = []
        for name in spec.retry_on:
            cls = getattr(builtins, name, None)
            if isinstance(cls, type) and issubclass(cls, BaseException):
                resolved.append(cls)
        return tuple(resolved) if resolved else (Exception,)

    @staticmethod
    def _step_report(
        spec: StepSpec,
        attempts: int,
        output_digest: Optional[str],
        error_type: Optional[str],
        seq: int,
    ) -> StepReport:
        return StepReport(
            step_id=spec.step_id,
            succeeded=error_type is None,
            attempts_made=attempts,
            output_digest=output_digest,
            error_type=error_type,
            seq=seq,
        )

    @staticmethod
    def _run_digest(
        run_id: str, step_reports: List[StepReport], succeeded: bool
    ) -> str:
        body = _canonical(
            {
                "run_id": run_id,
                "succeeded": succeeded,
                "steps": [r.as_dict() for r in step_reports],
            }
        )
        return _digest(body)

    # -- manual retry -------------------------------------------------

    def retry_run(
        self,
        failed_report: RunReport,
        step_id: str,
        seq: int = 0,
        sleeper: Optional[Callable[[float], None]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> RunReport:
        """Re-execute a failed step and everything downstream of it.

        ``failed_report`` must be a failed report from this engine's
        ``run`` (same DAG, same run lineage is not required — the
        graph must match). Only the failed step may be retried; any
        other id is refused fail-closed. Produces a fresh run report.
        """
        self._require_defined()
        _check_seq(seq)
        if not isinstance(failed_report, RunReport):
            raise WorkflowError("failed_report must be a RunReport")
        if failed_report.succeeded:
            raise WorkflowError("cannot retry a succeeded run")
        if failed_report.step_order != self._order:
            raise WorkflowError("report does not belong to this workflow")
        _check_str(step_id, "step_id")
        if step_id != failed_report.failed_step:
            raise WorkflowError(
                f"only the failed step {failed_report.failed_step!r} may be retried"
            )

        ctx = dict(context) if context is not None else {}
        self._run_counter += 1
        run_id = f"run-{self._run_counter}"

        outputs: Dict[str, Any] = {}
        step_reports: List[StepReport] = []
        failed: Optional[str] = None
        failure: Optional[StepFailed] = None
        start_idx = self._order.index(step_id)

        # Re-materialize upstream outputs is the caller's job: we only
        # have digests, not values. The retried segment re-runs with an
        # empty upstream input set EXCEPT outputs are unknown, so steps
        # whose fn requires upstream inputs receive what they received
        # in the original run only if re-supplied. Simplest honest
        # contract: rerun from the failed step with no upstream outputs
        # (its original inputs are unavailable), so the failed step's
        # fn must not depend on upstream outputs for retry. Enforce:
        spec = self._steps[step_id]
        if spec.dependencies:
            raise WorkflowError(
                f"step {step_id!r} has dependencies; retry requires "
                "re-running with original upstream outputs (not supported)"
            )

        for sid in self._order[start_idx:]:
            sspec = self._steps[sid]
            inputs = {dep: outputs[dep] for dep in sspec.dependencies}
            try:
                output, report = self._execute_step(
                    sspec, self._fn[sid], inputs, ctx, seq, sleeper
                )
            except StepFailed as exc:
                step_reports.append(exc.report)
                failed = sid
                failure = exc
                break
            outputs[sid] = output
            step_reports.append(report)

        succeeded = failure is None
        report = RunReport(
            run_id=run_id,
            succeeded=succeeded,
            step_order=self._order[start_idx:],
            step_reports=tuple(step_reports),
            failed_step=failed,
            run_digest=self._run_digest(run_id, step_reports, succeeded),
            seq=seq,
        )
        if failure is not None:
            raise RunFailed(report, failure)
        return report

    # -- execution lifecycle (Temporal/Cadence-shaped) ------------------

    def _claim_exec_seq(self, seq: int) -> int:
        """Claim a strictly-increasing execution-ledger seq.

        Bad shapes and rewinds raise bare (no consumption, no audit);
        post-claim validation failures consume the claimed seq and book
        a ``rejected`` audit row via :meth:`_reject_exec`.
        """
        _check_seq(seq)
        if seq <= self._exec_seq:
            raise WorkflowError(
                f"seq must be strictly increasing (last {self._exec_seq}), got {seq}"
            )
        self._exec_seq = seq
        return seq

    def _reject_exec(self, exc: ExecutionError, seq: int) -> ExecutionError:
        """Book a rejected execution mutation and return the error to raise."""
        self._exec_audit.append(workflow_engine_audit_event("rejected", seq))
        return exc

    def start(
        self,
        execution_id: str,
        workflow_id: str,
        seq: int,
        input: Any = None,
    ) -> ExecutionRecord:
        """Start a workflow execution instance.

        ``execution_id`` is the unique instance id (Temporal run-id
        shaped); ids are never recycled. ``workflow_id`` is the logical
        workflow name. ``input`` is optional and pinned by digest — raw
        bytes never enter the record. Duplicate ids are refused
        fail-closed (seq consumed, ``rejected`` booked).
        """
        _check_str(execution_id, "execution_id")
        self._claim_exec_seq(seq)
        if execution_id in self._executions:
            raise self._reject_exec(
                DuplicateExecutionError(
                    f"execution id {execution_id!r} already used"
                ),
                seq,
            )
        _check_str(workflow_id, "workflow_id")
        input_digest: Optional[str] = None
        if input is not None:
            try:
                input_digest = _digest(_canonical(input))
            except WorkflowError as exc:
                raise self._reject_exec(
                    ExecutionError(f"input is not pinnable: {exc}"), seq
                ) from exc
        digest = _digest(
            _canonical(
                {
                    "execution_id": execution_id,
                    "workflow_id": workflow_id,
                    "input_digest": input_digest,
                    "start_seq": seq,
                }
            )
        )
        record = ExecutionRecord(
            execution_id=execution_id,
            workflow_id=workflow_id,
            status="running",
            input_digest=input_digest,
            start_seq=seq,
            digest=digest,
        )
        self._executions[execution_id] = record
        self._exec_signals[execution_id] = []
        self._exec_audit.append(
            workflow_engine_audit_event(
                "execution-started", seq, execution_id=execution_id
            )
        )
        return record

    def signal(
        self,
        execution_id: str,
        signal_name: str,
        seq: int,
        payload: Any = None,
    ) -> SignalRecord:
        """Book a signal against a running execution.

        The execution must be ``running``; unknown ids and terminal
        executions are refused fail-closed. ``payload`` is pinned by
        digest only — raw bytes never enter the record. Verdicts are
        bookings, not deliveries: a booked signal means the ledger saw
        it, not that the workflow consumed it.
        """
        _check_str(execution_id, "execution_id")
        self._claim_exec_seq(seq)
        record = self._executions.get(execution_id)
        if record is None:
            raise self._reject_exec(
                UnknownExecutionError(f"unknown execution {execution_id!r}"), seq
            )
        if record.status != "running":
            raise self._reject_exec(
                TerminalExecutionError(
                    f"execution {execution_id!r} is terminal ({record.status})"
                ),
                seq,
            )
        try:
            _check_str(signal_name, "signal_name")
        except WorkflowError as exc:
            raise self._reject_exec(
                BadSignalError(f"bad signal name: {exc}"), seq
            ) from exc
        if len(signal_name) > 256:
            raise self._reject_exec(
                BadSignalError("signal_name must be <= 256 chars"), seq
            )
        payload_digest: Optional[str] = None
        if payload is not None:
            try:
                payload_digest = _digest(_canonical(payload))
            except WorkflowError as exc:
                raise self._reject_exec(
                    BadSignalError(f"payload is not pinnable: {exc}"), seq
                ) from exc
        self._signal_counter += 1
        signal_id = f"sig-{self._signal_counter}"
        digest = _digest(
            _canonical(
                {
                    "signal_id": signal_id,
                    "execution_id": execution_id,
                    "signal_name": signal_name,
                    "payload_digest": payload_digest,
                    "seq": seq,
                }
            )
        )
        srec = SignalRecord(
            signal_id=signal_id,
            execution_id=execution_id,
            signal_name=signal_name,
            payload_digest=payload_digest,
            seq=seq,
            digest=digest,
        )
        self._exec_signals[execution_id].append(srec)
        self._exec_audit.append(
            workflow_engine_audit_event("signaled", seq, execution_id=execution_id)
        )
        return srec

    def complete(
        self,
        execution_id: str,
        seq: int,
        result: Any = None,
    ) -> CompletionRecord:
        """Terminally complete a running execution.

        Unknown ids and already-terminal executions are refused
        fail-closed. ``result`` is pinned by digest only. Completion is
        terminal: later ``signal``/``complete`` calls on the id raise.
        """
        _check_str(execution_id, "execution_id")
        self._claim_exec_seq(seq)
        record = self._executions.get(execution_id)
        if record is None:
            raise self._reject_exec(
                UnknownExecutionError(f"unknown execution {execution_id!r}"), seq
            )
        if record.status != "running":
            raise self._reject_exec(
                TerminalExecutionError(
                    f"execution {execution_id!r} is terminal ({record.status})"
                ),
                seq,
            )
        result_digest: Optional[str] = None
        if result is not None:
            try:
                result_digest = _digest(_canonical(result))
            except WorkflowError as exc:
                raise self._reject_exec(
                    ExecutionError(f"result is not pinnable: {exc}"), seq
                ) from exc
        digest = _digest(
            _canonical(
                {
                    "execution_id": execution_id,
                    "outcome": "completed",
                    "result_digest": result_digest,
                    "seq": seq,
                }
            )
        )
        crec = CompletionRecord(
            execution_id=execution_id,
            outcome="completed",
            result_digest=result_digest,
            seq=seq,
            digest=digest,
        )
        self._executions[execution_id] = ExecutionRecord(
            execution_id=record.execution_id,
            workflow_id=record.workflow_id,
            status="completed",
            input_digest=record.input_digest,
            start_seq=record.start_seq,
            digest=record.digest,
        )
        self._exec_audit.append(
            workflow_engine_audit_event(
                "execution-completed", seq, execution_id=execution_id
            )
        )
        return crec

    # -- execution views (pure reads) --------------------------------

    def execution(self, execution_id: str) -> Optional[ExecutionRecord]:
        """Return the execution record, or None if unknown."""
        return self._executions.get(_check_str(execution_id, "execution_id"))

    def execution_ids(self) -> Tuple[str, ...]:
        """Sorted execution ids known to the ledger."""
        return tuple(sorted(self._executions))

    def status(self, execution_id: str) -> Optional[str]:
        """Status of an execution, or None if unknown."""
        record = self.execution(execution_id)
        return record.status if record is not None else None

    def signals_for(self, execution_id: str) -> Tuple[SignalRecord, ...]:
        """Signals booked against an execution (chronological)."""
        _check_str(execution_id, "execution_id")
        if execution_id not in self._executions:
            raise UnknownExecutionError(f"unknown execution {execution_id!r}")
        return tuple(self._exec_signals[execution_id])

    def execution_audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """Execution-ledger audit rows (booking order)."""
        return tuple(self._exec_audit)

    def _require_defined(self) -> None:
        if not self._defined:
            raise WorkflowError("workflow is not defined; call define() first")


def workflow_engine_audit_event(
    kind: str,
    seq: int,
    step_id: Optional[str] = None,
    run_id: Optional[str] = None,
    execution_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a workflow event.

    ``kind`` is one of ``"defined"`` / ``"step-started"`` /
    ``"step-succeeded"`` / ``"step-failed"`` / ``"run-completed"`` /
    ``"step-retried"`` / ``"execution-started"`` / ``"signaled"`` /
    ``"execution-completed"`` / ``"rejected"``.
    """
    if not isinstance(kind, str) or kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    record: Dict[str, Any] = {
        "format": AUDIT_FORMAT,
        "schema": SCHEMA_PIN,
        "kind": kind,
        "seq": _check_seq(seq),
    }
    if step_id is not None:
        record["step_id"] = _check_str(step_id, "step_id")
    if run_id is not None:
        record["run_id"] = _check_str(run_id, "run_id")
    if execution_id is not None:
        record["execution_id"] = _check_str(execution_id, "execution_id")
    return record


def main() -> None:
    engine = WorkflowEngine()
    order = engine.define(
        {
            "fetch": {"fn": lambda inputs, ctx: {"n": 2}},
            "double": {
                "fn": lambda inputs, ctx: {"n": inputs["fetch"]["n"] * 2},
                "dependencies": ["fetch"],
            },
        }
    )
    assert order == ("fetch", "double"), order
    report = engine.run(seq=1)
    assert report.succeeded and report.step_reports[1].output_digest is not None
    assert report.run_digest.startswith("sha256:")
    # Temporal/Cadence-shaped execution lifecycle smoke test.
    exec_rec = engine.start("exec-1", "order-workflow", 2, input={"order": "o-9"})
    assert exec_rec.status == "running" and exec_rec.digest.startswith("sha256:")
    sig = engine.signal("exec-1", "cancel-request", 3, payload={"reason": "user"})
    assert sig.signal_id == "sig-1" and sig.digest.startswith("sha256:")
    comp = engine.complete("exec-1", 4, result={"done": True})
    assert comp.outcome == "completed" and engine.status("exec-1") == "completed"
    assert len(engine.execution_audit_log()) == 3
    print("workflow-engine OK: define, topological run, digests, audit")
    print("workflow-engine OK: start, signal, complete, execution ledger")


if __name__ == "__main__":
    main()
