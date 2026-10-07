"""Runbook automation — simulated runbook execution/rollback bookkeeping.

Research note (runbook automation literature): Rundeck and Ansible
model operational runbooks as *ordered step lists* executed by a
caller-supplied executor; each step declares a type (shell command,
HTTP call, script, manual approval) and a failure policy
(stop-the-run or continue). Rollback is a *compensating run* over
the reverse of the steps that actually completed, never a time
machine. Schedules are cron-shaped declarations booked against a
runbook, not timers. This module takes the intersection for a
single-host deterministic ledger:

* **Definitions, not runners**: ``define`` books a runbook (ordered
  steps, pinned step-type vocabulary, per-step failure policy and
  rollback type). No commands are executed by this module.
* **Host-reported outcomes**: ``execute`` books one run against the
  runbook with a host-injectable ``executor(step, attempt) -> bool``;
  the default is a deterministic always-succeeds simulator. Step
  outcomes are data; a raising executor counts as failure
  (fail-closed). Fail-fast stops the run at the first failed step
  whose ``on_failure`` is ``"stop"``; later steps are booked as
  skipped (data, never silently dropped).
* **Rollback as compensating run**: ``rollback`` books a new
  execution of kind ``"rollback"`` over the reverse of the original
  run's *completed* steps, linked via ``rollback_of``. Rolling back
  a rollback is refused — compensation chains stay one level deep.
* **Schedules as declarations**: ``schedule`` books a cron-shaped
  declaration (validated to five cron fields); ``unschedule``
  retires it. No timers fire.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs on mutations (failed mutations consume their seq; bool/negative
/rewind refused), RLock-guarded, fail-closed taxonomy, stdlib-only
(``canonical_json`` sibling helper behind the standard try/except
fallback), hmac-``sha256:`` digest pins over type-tagged canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *declared* runbook runs
deterministically. It executes no commands, touches no hosts, and
cannot prove a step did what it claimed — the host declares every
outcome (GIGO). A ``completed`` record means "the host reported all
steps succeeded", never "the change landed". A rollback record means
"compensation was booked", never "the system is restored". Pair with
a real executor (Ansible/Rundeck/SSH) for production.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
from dataclasses import dataclass
from typing import Any, Callable, Mapping

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
RUNBOOK_AUTOMATION_VERSION = "runbook-automation.v1"

#: Schema pin carried by records and audit events.
RUNBOOK_AUTOMATION_SCHEMA = "northstar.runbook-automation.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned step-type vocabulary (drift detectable).
STEP_SHELL = "shell"
STEP_HTTP = "http"
STEP_SCRIPT = "script"
STEP_APPROVAL = "approval"
STEP_NOOP = "noop"
STEP_TYPES = (STEP_SHELL, STEP_HTTP, STEP_SCRIPT, STEP_APPROVAL, STEP_NOOP)

#: Pinned per-step failure policy.
ON_FAILURE_STOP = "stop"
ON_FAILURE_CONTINUE = "continue"
ON_FAILURE_POLICIES = (ON_FAILURE_STOP, ON_FAILURE_CONTINUE)

#: Execution kinds.
KIND_RUN = "run"
KIND_ROLLBACK = "rollback"
EXECUTION_KINDS = (KIND_RUN, KIND_ROLLBACK)

#: Execution statuses (computed data).
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
EXECUTION_STATUSES = (STATUS_COMPLETED, STATUS_FAILED)

#: Cron field validator: five cron fields, loose but fail-closed.
_CRON_TOKEN = re.compile(r"^[\d\*,\-/]+$")
_CRON_FIELDS = 5

#: Audit event kinds.
KIND_DEFINED = "runbook.defined"
KIND_EXECUTED = "runbook.executed"
KIND_STEP_FAILED = "runbook.step-failed"
KIND_ROLLED_BACK = "runbook.rolled-back"
KIND_SCHEDULED = "runbook.scheduled"
KIND_UNSCHEDULED = "runbook.unscheduled"
KIND_REJECTED = "runbook.rejected"
_KINDS = (
    KIND_DEFINED,
    KIND_EXECUTED,
    KIND_STEP_FAILED,
    KIND_ROLLED_BACK,
    KIND_SCHEDULED,
    KIND_UNSCHEDULED,
    KIND_REJECTED,
)

_GENESIS = "genesis"
_DIGEST_PREFIX = "sha256:"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class RunbookAutomationError(ValueError):
    """Base error for runbook automation."""


class BadRunbookError(RunbookAutomationError):
    """Malformed runbook definition (bad id, name, or steps)."""


class DuplicateRunbookError(RunbookAutomationError):
    """A runbook with this id is already defined."""


class UnknownRunbookError(RunbookAutomationError):
    """No runbook with this id is defined."""


class BadStepError(RunbookAutomationError):
    """Malformed step declaration inside a runbook."""


class UnknownExecutionError(RunbookAutomationError):
    """No execution with this id exists."""


class BadRollbackError(RunbookAutomationError):
    """Malformed rollback request (e.g. rolling back a rollback)."""


class BadScheduleError(RunbookAutomationError):
    """Malformed schedule (bad runbook, cron expression, or id)."""


class DuplicateScheduleError(RunbookAutomationError):
    """A schedule with this id already exists (or cron already booked)."""


class UnknownScheduleError(RunbookAutomationError):
    """No schedule with this id exists."""


class SeqOrderError(RunbookAutomationError):
    """Seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RunbookAutomationError(
            f"{field_name} must be a non-negative int"
        )
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RunbookAutomationError(
            f"{field_name} must be a non-empty string"
        )
    return value.strip()


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
    import json

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) >= 2**53:
                raise RunbookAutomationError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise RunbookAutomationError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise RunbookAutomationError(f"unencodable type: {type(v).__name__}")

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(payload: Any, seed: str = "") -> str:
    return _DIGEST_PREFIX + hmac.new(
        seed.encode("utf-8"), _canonical(payload), hashlib.sha256
    ).hexdigest()


def _check_cron(cron: Any) -> str:
    if not isinstance(cron, str):
        raise RunbookAutomationError("cron must be a string")
    cron = cron.strip()
    fields = cron.split()
    if len(fields) != _CRON_FIELDS or any(
        not _CRON_TOKEN.match(f) for f in fields
    ):
        raise BadScheduleError(
            "cron must be five space-separated fields of [0-9*,-/]"
        )
    return cron


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StepDeclaration:
    """One pinned step inside a runbook definition."""

    step_id: str
    name: str
    step_type: str
    on_failure: str
    rollback_type: str
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "step-declaration",
                    self.step_id,
                    self.name,
                    self.step_type,
                    self.on_failure,
                    self.rollback_type,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class RunbookRecord:
    """A pinned runbook definition (ordered steps)."""

    runbook_id: str
    name: str
    steps: tuple
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "runbook",
                    self.runbook_id,
                    self.name,
                    [s.digest for s in self.steps],
                    self.seq,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class StepResult:
    """One booked step outcome (data, never an action)."""

    execution_id: str
    step_id: str
    step_type: str
    outcome: bool
    skipped: bool
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "step-result",
                    self.execution_id,
                    self.step_id,
                    self.step_type,
                    self.outcome,
                    self.skipped,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class ExecutionRecord:
    """One booked run (kind ``run``) or compensating run (``rollback``)."""

    execution_id: str
    runbook_id: str
    kind: str
    status: str
    results: tuple
    failed_step_id: str
    rollback_of: str
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "execution",
                    self.execution_id,
                    self.runbook_id,
                    self.kind,
                    self.status,
                    [(r.step_id, r.outcome, r.skipped) for r in self.results],
                    self.failed_step_id,
                    self.rollback_of,
                    self.seq,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class ScheduleRecord:
    """A pinned cron-shaped schedule declaration (no timers fire)."""

    schedule_id: str
    runbook_id: str
    cron: str
    active: bool
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "schedule",
                    self.schedule_id,
                    self.runbook_id,
                    self.cron,
                    self.active,
                    self.seq,
                ],
                seed,
            ),
        )


def runbook_automation_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for runbook automation."""
    if kind not in _KINDS:
        raise RunbookAutomationError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if "kind" in detail:
        raise RunbookAutomationError("detail must not carry 'kind'")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "runbook_automation",
        "module_version": RUNBOOK_AUTOMATION_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


def _default_executor(step: StepDeclaration, attempt: int) -> bool:
    """Deterministic always-succeeds simulator (no commands run)."""
    return True


# ---------------------------------------------------------------------------
# RunbookAutomation
# ---------------------------------------------------------------------------


class RunbookAutomation:
    """Deterministic runbook-execution bookkeeping.

    All mutations require a caller-supplied strictly increasing ``seq``.
    Failed mutations consume their seq (ledger position stays total).
    Reads validate the seq shape but do not consume it and write no
    audit rows (``execute``/``rollback``/``define``/``schedule``/
    ``unschedule`` are the audited writes).
    """

    def __init__(self, seed: str = "") -> None:
        self._lock = threading.RLock()
        self._seed = seed
        self._last_seq = -1
        self._runbooks: dict[str, RunbookRecord] = {}
        self._executions: dict[str, ExecutionRecord] = {}
        self._execution_ids: list[str] = []
        self._schedules: dict[str, ScheduleRecord] = {}
        self._audit_log: list[Mapping[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _next_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last {self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(
            runbook_automation_audit_event(kind, seq, **detail)
        )

    def _reject(self, seq: int, reason: str) -> None:
        # Seq already consumed by _next_seq; only book the refusal.
        self._emit(KIND_REJECTED, seq, reason=reason)

    # -- define ------------------------------------------------------------

    @staticmethod
    def _parse_step(raw: Any, seed: str) -> StepDeclaration:
        if not isinstance(raw, Mapping):
            raise BadStepError("step must be a mapping")
        step_id = raw.get("step_id")
        name = raw.get("name")
        step_type = raw.get("step_type")
        on_failure = raw.get("on_failure", ON_FAILURE_STOP)
        rollback_type = raw.get("rollback_type", STEP_NOOP)
        if not isinstance(step_id, str) or not step_id.strip():
            raise BadStepError("step.step_id must be a non-empty string")
        if not isinstance(name, str) or not name.strip():
            raise BadStepError("step.name must be a non-empty string")
        if step_type not in STEP_TYPES:
            raise BadStepError(
                f"step.step_type must be one of {STEP_TYPES}"
            )
        if on_failure not in ON_FAILURE_POLICIES:
            raise BadStepError(
                f"step.on_failure must be one of {ON_FAILURE_POLICIES}"
            )
        if rollback_type not in STEP_TYPES:
            raise BadStepError(
                f"step.rollback_type must be one of {STEP_TYPES}"
            )
        step_id = step_id.strip()
        name = name.strip()
        return StepDeclaration(
            step_id=step_id,
            name=name,
            step_type=step_type,
            on_failure=on_failure,
            rollback_type=rollback_type,
            digest=_pin(
                [
                    "step-declaration",
                    step_id,
                    name,
                    step_type,
                    on_failure,
                    rollback_type,
                ],
                seed,
            ),
        )

    def define(self, runbook_id: str, name: str, steps: Any, seq: Any) -> RunbookRecord:
        """Book a runbook definition (ordered, pinned steps)."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                runbook_id = _check_nonempty_str(runbook_id, "runbook_id")
                name = _check_nonempty_str(name, "name")
                if not isinstance(steps, (list, tuple)) or not steps:
                    raise BadRunbookError("steps must be a non-empty list")
                parsed = [self._parse_step(s, self._seed) for s in steps]
                step_ids = [s.step_id for s in parsed]
                if len(set(step_ids)) != len(step_ids):
                    raise BadRunbookError("duplicate step_id in runbook")
                if runbook_id in self._runbooks:
                    raise DuplicateRunbookError(
                        f"runbook {runbook_id!r} already defined"
                    )
            except RunbookAutomationError as exc:
                self._reject(seq, str(exc))
                raise
            record = RunbookRecord(
                runbook_id=runbook_id,
                name=name,
                steps=tuple(parsed),
                seq=seq,
                digest=_pin(
                    [
                        "runbook",
                        runbook_id,
                        name,
                        [s.digest for s in parsed],
                        seq,
                    ],
                    self._seed,
                ),
            )
            self._runbooks[runbook_id] = record
            self._emit(
                KIND_DEFINED,
                seq,
                runbook_id=runbook_id,
                steps=len(parsed),
            )
            return record

    # -- execute -----------------------------------------------------------

    def _run_steps(
        self,
        execution_id: str,
        decls: list[StepDeclaration],
        executor: Callable[[StepDeclaration, int], bool] | None,
    ) -> tuple[tuple[StepResult, ...], str, str]:
        """Execute step declarations; returns (results, status, failed_step_id).

        A raising executor counts as failure (fail-closed). Fail-fast
        stops at the first failed step with on_failure == "stop"; later
        steps are booked as skipped (data, never dropped).
        """
        run = executor if executor is not None else _default_executor
        results: list[StepResult] = []
        stopped = False
        failed_step_id = ""
        any_failed = False
        for decl in decls:
            if stopped:
                results.append(
                    StepResult(
                        execution_id=execution_id,
                        step_id=decl.step_id,
                        step_type=decl.step_type,
                        outcome=False,
                        skipped=True,
                        digest=_pin(
                            [
                                "step-result",
                                execution_id,
                                decl.step_id,
                                decl.step_type,
                                False,
                                True,
                            ],
                            self._seed,
                        ),
                    )
                )
                continue
            try:
                outcome = run(decl, 1)
                if not isinstance(outcome, bool):
                    outcome = False
            except Exception:
                outcome = False
            skipped = False
            if not outcome:
                any_failed = True
                if not failed_step_id:
                    failed_step_id = decl.step_id
                if decl.on_failure == ON_FAILURE_STOP:
                    stopped = True
            results.append(
                StepResult(
                    execution_id=execution_id,
                    step_id=decl.step_id,
                    step_type=decl.step_type,
                    outcome=outcome,
                    skipped=skipped,
                    digest=_pin(
                        [
                            "step-result",
                            execution_id,
                            decl.step_id,
                            decl.step_type,
                            outcome,
                            skipped,
                        ],
                        self._seed,
                    ),
                )
            )
        status = STATUS_FAILED if any_failed else STATUS_COMPLETED
        return tuple(results), status, failed_step_id

    def _book_execution(
        self,
        runbook_id: str,
        kind: str,
        decls: list[StepDeclaration],
        executor: Callable[[StepDeclaration, int], bool] | None,
        seq: int,
        rollback_of: str = "",
        audit_kind: str = KIND_EXECUTED,
    ) -> ExecutionRecord:
        execution_id = f"exec-{len(self._execution_ids) + 1}"
        results, status, failed_step_id = self._run_steps(
            execution_id, decls, executor
        )
        record = ExecutionRecord(
            execution_id=execution_id,
            runbook_id=runbook_id,
            kind=kind,
            status=status,
            results=results,
            failed_step_id=failed_step_id,
            rollback_of=rollback_of,
            seq=seq,
            digest=_pin(
                [
                    "execution",
                    execution_id,
                    runbook_id,
                    kind,
                    status,
                    [(r.step_id, r.outcome, r.skipped) for r in results],
                    failed_step_id,
                    rollback_of,
                    seq,
                ],
                self._seed,
            ),
        )
        self._executions[execution_id] = record
        self._execution_ids.append(execution_id)
        self._emit(
            audit_kind,
            seq,
            execution_id=execution_id,
            runbook_id=runbook_id,
            status=status,
            steps=len(results),
            failed_steps=sum(1 for r in results if not r.outcome and not r.skipped),
            skipped_steps=sum(1 for r in results if r.skipped),
        )
        if status == STATUS_FAILED:
            self._emit(
                KIND_STEP_FAILED,
                seq,
                execution_id=execution_id,
                failed_step_id=failed_step_id,
            )
        return record

    def execute(
        self,
        runbook_id: str,
        seq: Any,
        executor: Callable[[StepDeclaration, int], bool] | None = None,
    ) -> ExecutionRecord:
        """Book one run of a runbook (outcomes via host executor)."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                if runbook_id not in self._runbooks:
                    raise UnknownRunbookError(
                        f"unknown runbook: {runbook_id!r}"
                    )
                if executor is not None and not callable(executor):
                    raise BadRunbookError("executor must be callable")
            except RunbookAutomationError as exc:
                self._reject(seq, str(exc))
                raise
            runbook = self._runbooks[runbook_id]
            return self._book_execution(
                runbook_id, KIND_RUN, list(runbook.steps), executor, seq
            )

    # -- rollback ----------------------------------------------------------

    def rollback(
        self,
        execution_id: str,
        seq: Any,
        executor: Callable[[StepDeclaration, int], bool] | None = None,
    ) -> ExecutionRecord:
        """Book a compensating run over the reverse of completed steps."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                if execution_id not in self._executions:
                    raise UnknownExecutionError(
                        f"unknown execution: {execution_id!r}"
                    )
                original = self._executions[execution_id]
                if original.kind != KIND_RUN:
                    raise BadRollbackError(
                        "cannot roll back a rollback execution"
                    )
                if executor is not None and not callable(executor):
                    raise BadRollbackError("executor must be callable")
            except RunbookAutomationError as exc:
                self._reject(seq, str(exc))
                raise
            runbook = self._runbooks[original.runbook_id]
            by_id = {s.step_id: s for s in runbook.steps}
            # Compensate, in reverse, the steps that actually completed.
            completed = [
                r for r in original.results if r.outcome and not r.skipped
            ]
            decls: list[StepDeclaration] = []
            for res in reversed(completed):
                src = by_id[res.step_id]
                decls.append(
                    StepDeclaration(
                        step_id=f"rb-{src.step_id}",
                        name=f"rollback:{src.name}",
                        step_type=src.rollback_type,
                        on_failure=ON_FAILURE_STOP,
                        rollback_type=STEP_NOOP,
                        digest=_pin(
                            [
                                "step-declaration",
                                f"rb-{src.step_id}",
                                f"rollback:{src.name}",
                                src.rollback_type,
                                ON_FAILURE_STOP,
                                STEP_NOOP,
                            ],
                            self._seed,
                        ),
                    )
                )
            record = self._book_execution(
                original.runbook_id,
                KIND_ROLLBACK,
                decls,
                executor,
                seq,
                rollback_of=execution_id,
                audit_kind=KIND_ROLLED_BACK,
            )
            return record

    # -- schedule ----------------------------------------------------------

    def schedule(self, runbook_id: str, cron: str, seq: Any) -> ScheduleRecord:
        """Book a cron-shaped schedule declaration (no timers fire)."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                if runbook_id not in self._runbooks:
                    raise UnknownRunbookError(
                        f"unknown runbook: {runbook_id!r}"
                    )
                cron = _check_cron(cron)
                for existing in self._schedules.values():
                    if (
                        existing.runbook_id == runbook_id
                        and existing.cron == cron
                        and existing.active
                    ):
                        raise DuplicateScheduleError(
                            "this cron is already scheduled for the runbook"
                        )
            except RunbookAutomationError as exc:
                self._reject(seq, str(exc))
                raise
            schedule_id = f"sch-{len(self._schedules) + 1}"
            record = ScheduleRecord(
                schedule_id=schedule_id,
                runbook_id=runbook_id,
                cron=cron,
                active=True,
                seq=seq,
                digest=_pin(
                    ["schedule", schedule_id, runbook_id, cron, True, seq],
                    self._seed,
                ),
            )
            self._schedules[schedule_id] = record
            self._emit(
                KIND_SCHEDULED,
                seq,
                schedule_id=schedule_id,
                runbook_id=runbook_id,
            )
            return record

    def unschedule(self, schedule_id: str, seq: Any) -> ScheduleRecord:
        """Retire a schedule (id never recycled)."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                if schedule_id not in self._schedules:
                    raise UnknownScheduleError(
                        f"unknown schedule: {schedule_id!r}"
                    )
                current = self._schedules[schedule_id]
                if not current.active:
                    raise UnknownScheduleError(
                        f"schedule {schedule_id!r} already retired"
                    )
            except RunbookAutomationError as exc:
                self._reject(seq, str(exc))
                raise
            record = ScheduleRecord(
                schedule_id=current.schedule_id,
                runbook_id=current.runbook_id,
                cron=current.cron,
                active=False,
                seq=seq,
                digest=_pin(
                    [
                        "schedule",
                        current.schedule_id,
                        current.runbook_id,
                        current.cron,
                        False,
                        seq,
                    ],
                    self._seed,
                ),
            )
            self._schedules[schedule_id] = record
            self._emit(KIND_UNSCHEDULED, seq, schedule_id=schedule_id)
            return record

    # -- views -------------------------------------------------------------

    def runbook(self, runbook_id: str) -> RunbookRecord:
        with self._lock:
            if runbook_id not in self._runbooks:
                raise UnknownRunbookError(f"unknown runbook: {runbook_id!r}")
            return self._runbooks[runbook_id]

    def runbook_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._runbooks)

    def execution(self, execution_id: str) -> ExecutionRecord:
        with self._lock:
            if execution_id not in self._executions:
                raise UnknownExecutionError(
                    f"unknown execution: {execution_id!r}"
                )
            return self._executions[execution_id]

    def executions_for(self, runbook_id: str) -> list[ExecutionRecord]:
        with self._lock:
            return [
                self._executions[eid]
                for eid in self._execution_ids
                if self._executions[eid].runbook_id == runbook_id
            ]

    def rollback_of(self, rollback_execution_id: str) -> ExecutionRecord:
        """Return the original execution a rollback compensated."""
        with self._lock:
            record = self.execution(rollback_execution_id)
            if record.kind != KIND_ROLLBACK or not record.rollback_of:
                raise BadRollbackError(
                    f"{rollback_execution_id!r} is not a rollback execution"
                )
            return self._executions[record.rollback_of]

    def schedule_record(self, schedule_id: str) -> ScheduleRecord:
        with self._lock:
            if schedule_id not in self._schedules:
                raise UnknownScheduleError(
                    f"unknown schedule: {schedule_id!r}"
                )
            return self._schedules[schedule_id]

    def schedule_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._schedules)

    def active_schedule_ids(self) -> list[str]:
        with self._lock:
            return sorted(
                sid
                for sid, rec in self._schedules.items()
                if rec.active
            )

    def stats(self) -> Mapping[str, int]:
        with self._lock:
            return {
                "runbooks": len(self._runbooks),
                "executions": len(self._executions),
                "rollbacks": sum(
                    1
                    for r in self._executions.values()
                    if r.kind == KIND_ROLLBACK
                ),
                "schedules": len(self._schedules),
                "audit_events": len(self._audit_log),
            }

    def audit_log(self) -> list[Mapping[str, Any]]:
        with self._lock:
            return list(self._audit_log)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Deterministic smoke test; prints one line on success."""
    ra = RunbookAutomation()
    seq = 0

    def nxt() -> int:
        nonlocal seq
        seq += 1
        return seq

    rb = ra.define(
        "rb-1",
        "deploy",
        [
            {"step_id": "s1", "name": "build", "step_type": "shell"},
            {
                "step_id": "s2",
                "name": "health",
                "step_type": "http",
                "on_failure": "continue",
                "rollback_type": "http",
            },
        ],
        nxt(),
    )
    assert rb.verify()
    assert [s.step_id for s in rb.steps] == ["s1", "s2"]

    calls: list[str] = []

    def boom(step: StepDeclaration, attempt: int) -> bool:
        calls.append(step.step_id)
        return step.step_id != "s1"

    run = ra.execute("rb-1", nxt(), executor=boom)
    assert run.verify()
    assert run.kind == KIND_RUN
    assert run.status == STATUS_FAILED
    assert run.failed_step_id == "s1"
    assert all(r.skipped for r in run.results[1:])
    assert calls == ["s1"]

    ok = ra.execute(
        "rb-1", nxt(), executor=lambda step, attempt: True
    )
    assert ok.status == STATUS_COMPLETED
    assert not ok.results[0].skipped

    rbk = ra.rollback(ok.execution_id, nxt())
    assert rbk.verify()
    assert rbk.kind == KIND_ROLLBACK
    assert rbk.rollback_of == ok.execution_id
    assert [r.step_id for r in rbk.results] == ["rb-s2", "rb-s1"]
    assert rbk.status == STATUS_COMPLETED
    assert ra.rollback_of(rbk.execution_id).execution_id == ok.execution_id

    sch = ra.schedule("rb-1", "0 * * * *", nxt())
    assert sch.verify()
    assert ra.active_schedule_ids() == [sch.schedule_id]
    retired = ra.unschedule(sch.schedule_id, nxt())
    assert retired.active is False
    assert ra.active_schedule_ids() == []

    try:
        ra.rollback(rbk.execution_id, nxt())
    except BadRollbackError:
        pass
    else:  # pragma: no cover
        raise AssertionError("rollback of rollback must fail")

    print(
        "runbook-automation OK: define, execute, fail-fast, "
        "rollback, schedule, pins, audit"
    )


if __name__ == "__main__":
    main()
