"""Governed local Agent Loop contracts and admission boundary."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import fcntl

from durable_contract import RunContract

_PLAN_SCHEMA = "northstar.agent-plan.v1"
_STEP_SCHEMA = "northstar.agent-plan-step.v1"
_DIGEST_PREFIX = "sha256:"
_ID_RE = re.compile(r"^[^\s/\\\x00]+$")
_SCOPE_RE = re.compile(r"^[^\s/\\:]+:[^\s/\\:]+$")
_MAX_ID = 128
_MAX_PAYLOAD_BYTES = 256_000
_MAX_STEPS = 64
_MAX_PLAN_STEP_ID_CHARS = 128


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("value is not canonical JSON") from error


def _digest(value: Any) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(_canonical(value)).hexdigest()


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_ID or not _ID_RE.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _digest_field(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith(_DIGEST_PREFIX) or any(c not in "0123456789abcdef" for c in value[7:]):
        raise ValueError(f"{field} is invalid")
    return value


def _positive(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _failure_reason(error: BaseException) -> str:
    """Name the failure kind without ever copying error text into evidence."""
    reason = type(error).__name__
    return reason if reason.isidentifier() and len(reason) <= _MAX_ID else "action_error"


def _scopes(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be a non-empty list")
    result: list[str] = []
    seen: set[str] = set()
    for scope in value:
        if not isinstance(scope, str) or not _SCOPE_RE.fullmatch(scope) or scope in seen:
            raise ValueError(f"{field} contains an invalid or duplicate scope")
        seen.add(scope)
        result.append(scope)
    return tuple(result)


def _postconditions(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("expected_postconditions must be a list")
    result = tuple(_id(item, "expected_postcondition") for item in value)
    if len(set(result)) != len(result):
        raise ValueError("expected_postconditions contain duplicates")
    return result


@dataclass(frozen=True)
class PlanStep:
    schema_version: str
    step_id: str
    action_id: str
    input_payload: dict[str, Any]
    scope_snapshot: tuple[str, ...]
    expected_postconditions: tuple[str, ...]
    idempotency_key: str
    max_attempts: int
    deadline_at: int

    @classmethod
    def from_dict(cls, value: Any) -> "PlanStep":
        fields = {
            "schema_version", "step_id", "action_id", "input_payload", "scope_snapshot",
            "expected_postconditions", "idempotency_key", "max_attempts", "deadline_at",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("plan step has unknown or missing fields")
        if value["schema_version"] != _STEP_SCHEMA:
            raise ValueError("plan step schema is invalid")
        payload = value["input_payload"]
        if not isinstance(payload, dict):
            raise ValueError("input_payload must be an object")
        if len(_canonical(payload)) > _MAX_PAYLOAD_BYTES:
            raise ValueError("input_payload exceeds the maximum size")
        return cls(
            schema_version=_STEP_SCHEMA,
            step_id=_id(value["step_id"], "step_id"),
            action_id=_id(value["action_id"], "action_id"),
            input_payload=payload,
            scope_snapshot=_scopes(value["scope_snapshot"], "scope_snapshot"),
            expected_postconditions=_postconditions(value["expected_postconditions"]),
            idempotency_key=_id(value["idempotency_key"], "idempotency_key"),
            max_attempts=_positive(value["max_attempts"], "max_attempts"),
            deadline_at=_positive(value["deadline_at"], "deadline_at"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "step_id": self.step_id,
            "action_id": self.action_id,
            "input_payload": self.input_payload,
            "scope_snapshot": list(self.scope_snapshot),
            "expected_postconditions": list(self.expected_postconditions),
            "idempotency_key": self.idempotency_key,
            "max_attempts": self.max_attempts,
            "deadline_at": self.deadline_at,
        }


@dataclass(frozen=True)
class AgentPlan:
    schema_version: str
    plan_id: str
    plan_version: int
    task_id: str
    thread_id: str
    run_id: str
    actor_id: str
    workspace_id: str
    policy_revision: str
    trace_id: str
    steps: tuple[PlanStep, ...]
    plan_digest: str

    @classmethod
    def from_dict(cls, value: Any) -> "AgentPlan":
        fields = {
            "schema_version", "plan_id", "plan_version", "task_id", "thread_id", "run_id",
            "actor_id", "workspace_id", "policy_revision", "trace_id", "steps",
        }
        if not isinstance(value, dict) or set(value) not in (fields, fields | {"plan_digest"}):
            raise ValueError("agent plan has unknown or missing fields")
        if value["schema_version"] != _PLAN_SCHEMA:
            raise ValueError("agent plan schema is invalid")
        steps_value = value["steps"]
        if not isinstance(steps_value, list) or not steps_value or len(steps_value) > _MAX_STEPS:
            raise ValueError("agent plan steps are invalid")
        steps = tuple(PlanStep.from_dict(item) for item in steps_value)
        if len({step.step_id for step in steps}) != len(steps):
            raise ValueError("agent plan contains duplicate step_id")
        if len({step.idempotency_key for step in steps}) != len(steps):
            raise ValueError("agent plan contains duplicate idempotency_key")
        plan = cls(
            schema_version=_PLAN_SCHEMA,
            plan_id=_id(value["plan_id"], "plan_id"),
            plan_version=_positive(value["plan_version"], "plan_version"),
            task_id=_id(value["task_id"], "task_id"),
            thread_id=_id(value["thread_id"], "thread_id"),
            run_id=_id(value["run_id"], "run_id"),
            actor_id=_id(value["actor_id"], "actor_id"),
            workspace_id=_id(value["workspace_id"], "workspace_id"),
            policy_revision=_id(value["policy_revision"], "policy_revision"),
            trace_id=_id(value["trace_id"], "trace_id"),
            steps=steps,
            plan_digest="",
        )
        digest = _digest(plan._unsigned_dict())
        supplied = value.get("plan_digest")
        if supplied is not None and supplied != digest:
            raise ValueError("agent plan digest does not match plan")
        return cls(**{**plan.__dict__, "plan_digest": digest})

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "plan_version": self.plan_version,
            "task_id": self.task_id,
            "thread_id": self.thread_id,
            "run_id": self.run_id,
            "actor_id": self.actor_id,
            "workspace_id": self.workspace_id,
            "policy_revision": self.policy_revision,
            "trace_id": self.trace_id,
            "steps": [step.to_dict() for step in self.steps],
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "plan_digest": self.plan_digest}
def _manifest_for_plan(plan: AgentPlan) -> tuple[dict[str, Any], ...]:
    return tuple(
        {
            "step_id": step.step_id,
            "execution_id": f"execution-{step.idempotency_key}",
            "idempotency_key": step.idempotency_key,
            "max_attempts": step.max_attempts,
            "deadline_at": step.deadline_at,
        }
        for step in plan.steps
    )


def _plan_step_manifest(value: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, (list, tuple)) or not value or len(value) > _MAX_STEPS:
        raise ValueError("plan_step_manifest is invalid")
    fields = {"step_id", "execution_id", "idempotency_key", "max_attempts", "deadline_at"}
    result: list[dict[str, Any]] = []
    seen_steps: set[str] = set()
    seen_execution_ids: set[str] = set()
    seen_idempotency_keys: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("plan_step_manifest has unknown or missing fields")
        step_id = _id(item["step_id"], "plan_step_manifest.step_id")
        execution_id = _id(item["execution_id"], "plan_step_manifest.execution_id")
        idempotency_key = _id(item["idempotency_key"], "plan_step_manifest.idempotency_key")
        if execution_id != f"execution-{idempotency_key}":
            raise ValueError("plan_step_manifest execution_id does not match idempotency_key")
        if step_id in seen_steps or execution_id in seen_execution_ids or idempotency_key in seen_idempotency_keys:
            raise ValueError("plan_step_manifest contains duplicate identity")
        seen_steps.add(step_id)
        seen_execution_ids.add(execution_id)
        seen_idempotency_keys.add(idempotency_key)
        result.append({
            "step_id": step_id,
            "execution_id": execution_id,
            "idempotency_key": idempotency_key,
            "max_attempts": _positive(item["max_attempts"], "plan_step_manifest.max_attempts"),
            "deadline_at": _positive(item["deadline_at"], "plan_step_manifest.deadline_at"),
        })
    return tuple(result)


_LOOP_SCHEMA = "northstar.agent-loop-event.v1"
_LOOP_EVENT_TYPES = {
    "plan.admitted",
    "loop.started",
    "step.attempted",
    "step.action_failed",
    "step.observed",
    "loop.paused",
    "loop.failed",
    "loop.finished",
}
_LOOP_STATUS_BY_EVENT = {
    "plan.admitted": "admitted",
    "loop.started": "running",
    "step.attempted": "attempted",
    "step.action_failed": "attempted",
    "step.observed": {"verified_committed", "verified_absent", "paused_unknown"},
    "loop.paused": "paused_unknown",
    "loop.failed": "failed",
    "loop.finished": "finished",
}
_LOOP_STATUSES = {
    "admitted",
    "running",
    "attempted",
    "verified_absent",
    "verified_committed",
    "paused_unknown",
    "failed",
    "finished",
}


def _nonnegative(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _optional_id(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _id(value, field)


def _optional_digest(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _digest_field(value, field)


@dataclass(frozen=True)
class PostconditionResult:
    verdict: str
    reason_code: str
    observed_digest: str | None = None

    def __post_init__(self) -> None:
        if self.verdict not in {"verified", "absent", "unknown"}:
            raise ValueError("postcondition verdict is invalid")
        _id(self.reason_code, "reason_code")
        if self.observed_digest is not None:
            _digest_field(self.observed_digest, "observed_digest")
        if self.verdict == "verified" and self.observed_digest is None:
            raise ValueError("verified postcondition requires observed_digest")


@dataclass(frozen=True)
class LoopEvent:
    schema_version: str
    sequence: int
    prev_event_digest: str | None
    event_digest: str
    plan_digest: str
    event_type: str
    step_id: str
    execution_id: str | None
    attempt_id: str | None
    attempt: int
    status: str
    reason_code: str | None
    observed_digest: str | None
    output_digest: str | None
    plan_step_manifest: tuple[dict[str, Any], ...] | None
    idempotency_key: str
    recorded_at: int

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        prev_event_digest: str | None,
        plan_digest: str,
        event_type: str,
        step_id: str,
        execution_id: str | None,
        attempt_id: str | None,
        attempt: int,
        status: str,
        reason_code: str | None,
        observed_digest: str | None,
        output_digest: str | None,
        plan_step_manifest: tuple[dict[str, Any], ...] | None = None,
        idempotency_key: str,
        recorded_at: int,
    ) -> "LoopEvent":
        if sequence <= 0:
            raise ValueError("sequence must be positive")
        _digest_field(plan_digest, "plan_digest")
        if event_type not in _LOOP_EVENT_TYPES:
            raise ValueError("loop event type is invalid")
        expected_status = _LOOP_STATUS_BY_EVENT[event_type]
        if isinstance(expected_status, set):
            if status not in expected_status:
                raise ValueError("loop event status does not match event type")
        elif status != expected_status:
            raise ValueError("loop event status does not match event type")
        if sequence > 1:
            _digest_field(prev_event_digest, "prev_event_digest")
        elif prev_event_digest is not None:
            raise ValueError("first loop event cannot have predecessor")
        if step_id == "":
            raise ValueError("step_id is invalid")
        _id(step_id, "step_id")
        execution_id = _optional_id(execution_id, "execution_id")
        attempt_id = _optional_id(attempt_id, "attempt_id")
        attempt = _nonnegative(attempt, "attempt")
        if attempt_id is None and attempt != 0:
            raise ValueError("non-attempt event must use attempt zero")
        if attempt_id is not None and attempt <= 0:
            raise ValueError("attempt event must use a positive attempt")
        if status not in _LOOP_STATUSES:
            raise ValueError("loop event status is invalid")
        reason_code = _optional_id(reason_code, "reason_code")
        observed_digest = _optional_digest(observed_digest, "observed_digest")
        output_digest = _optional_digest(output_digest, "output_digest")
        if event_type == "plan.admitted":
            if step_id != "__plan__" or execution_id is not None or attempt_id is not None or attempt != 0:
                raise ValueError("plan.admitted has invalid identity")
            plan_step_manifest = _plan_step_manifest(plan_step_manifest)
        elif plan_step_manifest is not None:
            raise ValueError("only plan.admitted can carry a plan_step_manifest")
        idempotency_key = _id(idempotency_key, "idempotency_key")
        recorded_at = _positive(recorded_at, "recorded_at")
        unsigned = {
            "schema_version": _LOOP_SCHEMA,
            "sequence": sequence,
            "prev_event_digest": prev_event_digest,
            "plan_digest": plan_digest,
            "event_type": event_type,
            "step_id": step_id,
            "execution_id": execution_id,
            "attempt_id": attempt_id,
            "attempt": attempt,
            "status": status,
            "reason_code": reason_code,
            "observed_digest": observed_digest,
            "output_digest": output_digest,
            "plan_step_manifest": list(plan_step_manifest) if plan_step_manifest is not None else None,
            "idempotency_key": idempotency_key,
            "recorded_at": recorded_at,
        }
        return cls(
            schema_version=_LOOP_SCHEMA,
            sequence=sequence,
            prev_event_digest=prev_event_digest,
            event_digest=_digest(unsigned),
            plan_digest=plan_digest,
            event_type=event_type,
            step_id=step_id,
            execution_id=execution_id,
            attempt_id=attempt_id,
            attempt=attempt,
            status=status,
            reason_code=reason_code,
            observed_digest=observed_digest,
            output_digest=output_digest,
            plan_step_manifest=plan_step_manifest,
            idempotency_key=idempotency_key,
            recorded_at=recorded_at,
        )

    @classmethod
    def from_dict(cls, value: Any) -> "LoopEvent":
        fields = {
            "schema_version", "sequence", "prev_event_digest", "event_digest",
            "plan_digest", "event_type", "step_id", "execution_id", "attempt_id",
            "attempt", "status", "reason_code", "observed_digest", "output_digest",
            "plan_step_manifest", "idempotency_key", "recorded_at",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("loop event has unknown or missing fields")
        if value["schema_version"] != _LOOP_SCHEMA:
            raise ValueError("loop event schema is invalid")
        event = cls.create(
            sequence=_positive(value["sequence"], "sequence"),
            prev_event_digest=value["prev_event_digest"],
            plan_digest=value["plan_digest"],
            event_type=value["event_type"],
            step_id=value["step_id"],
            execution_id=value["execution_id"],
            attempt_id=value["attempt_id"],
            attempt=value["attempt"],
            status=value["status"],
            reason_code=value["reason_code"],
            observed_digest=value["observed_digest"],
            output_digest=value["output_digest"],
            plan_step_manifest=value["plan_step_manifest"],
            idempotency_key=value["idempotency_key"],
            recorded_at=value["recorded_at"],
        )
        supplied = _digest_field(value["event_digest"], "event_digest")
        if supplied != event.event_digest:
            raise ValueError("loop event digest does not match event")
        return event

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "prev_event_digest": self.prev_event_digest,
            "event_digest": self.event_digest,
            "plan_digest": self.plan_digest,
            "event_type": self.event_type,
            "step_id": self.step_id,
            "execution_id": self.execution_id,
            "attempt_id": self.attempt_id,
            "attempt": self.attempt,
            "status": self.status,
            "reason_code": self.reason_code,
            "observed_digest": self.observed_digest,
            "output_digest": self.output_digest,
            "plan_step_manifest": list(self.plan_step_manifest) if self.plan_step_manifest is not None else None,
            "idempotency_key": self.idempotency_key,
            "recorded_at": self.recorded_at,
        }


@dataclass(frozen=True)
class LoopState:
    status: str
    plan_digest: str
    current_step_id: str | None
    steps: dict[str, dict[str, Any]]
    sequence: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "plan_digest": self.plan_digest,
            "current_step_id": self.current_step_id,
            "steps": self.steps,
            "sequence": self.sequence,
        }


class AgentLoop:
    """Governed local loop: admit, attempt, observe, checkpoint, and resume."""

    def __init__(
        self,
        run: RunContract,
        evidence_path: str | Path,
        *,
        actor_id: str,
        workspace_id: str,
        actions: dict[str, Callable[..., Any]],
        observer: Callable[..., Any],
    ):
        if not isinstance(run, RunContract):
            raise ValueError("run must be a RunContract")
        if not isinstance(actions, dict) or any(
            not isinstance(key, str) or not callable(value)
            for key, value in actions.items()
        ):
            raise ValueError("actions must be a mapping of IDs to callables")
        if not callable(observer):
            raise ValueError("observer must be callable")
        self.run_contract = run
        self.actor_id = _id(actor_id, "actor_id")
        self.workspace_id = _id(workspace_id, "workspace_id")
        self.evidence_path = Path(evidence_path).absolute()
        self.lock_path = self.evidence_path.with_name(self.evidence_path.name + ".lock")
        self.checkpoint_path = self.evidence_path.with_name(
            self.evidence_path.name + ".checkpoint.json"
        )
        self.evidence_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path.touch(mode=0o600, exist_ok=True)
        os.chmod(self.lock_path, 0o600)
        self.actions = dict(actions)
        self.observer = observer

    @contextmanager
    def _locked(self):
        try:
            lock = self.lock_path.open("a+b")
        except OSError as error:
            raise ValueError("agent loop lock is unavailable") from error
        try:
            os.chmod(self.lock_path, 0o600)
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            except OSError as error:
                raise ValueError("agent loop lock is unavailable") from error
            yield
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            except OSError as error:
                raise ValueError("agent loop lock release failed") from error
        finally:
            lock.close()

    def _read_locked(self) -> list[LoopEvent]:
        if not self.evidence_path.exists():
            return []
        try:
            raw = self.evidence_path.read_bytes()
        except OSError as error:
            raise ValueError("agent loop evidence cannot be read") from error
        if not raw:
            return []
        events: list[LoopEvent] = []
        for raw_line in raw.splitlines(keepends=True):
            if not raw_line.endswith((b"\n", b"\r")):
                raise ValueError("agent loop evidence contains incomplete event")
            try:
                events.append(LoopEvent.from_dict(json.loads(raw_line.decode("utf-8"))))
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
                raise ValueError("agent loop evidence contains invalid event") from error
        previous: LoopEvent | None = None
        seen_keys: set[str] = set()
        for expected, event in enumerate(events, start=1):
            if event.sequence != expected:
                raise ValueError("agent loop evidence sequence is not contiguous")
            if event.prev_event_digest != (previous.event_digest if previous else None):
                raise ValueError("agent loop evidence predecessor does not match")
            if event.idempotency_key in seen_keys:
                raise ValueError("agent loop evidence contains duplicate idempotency key")
            seen_keys.add(event.idempotency_key)
            previous = event
        return events

    @staticmethod
    def _derive(events: list[LoopEvent]) -> LoopState:
        if not events:
            raise ValueError("agent loop has no evidence history")
        plan_digest = events[0].plan_digest
        if events[0].event_type != "plan.admitted" or events[0].status != "admitted":
            raise ValueError("agent loop must begin with plan.admitted")
        manifest = events[0].plan_step_manifest
        if manifest is None:
            raise ValueError("plan.admitted is missing plan_step_manifest")
        manifest_by_step = {item["step_id"]: item for item in manifest}
        status = "admitted"
        current_step_id: str | None = None
        steps: dict[str, dict[str, Any]] = {}
        for event in events:
            if event.plan_digest != plan_digest:
                raise ValueError("agent loop plan digest changed")
            if event.event_type == "plan.admitted":
                if event.sequence != 1 or status != "admitted" or event.plan_step_manifest != manifest:
                    raise ValueError("duplicate or misplaced plan.admitted")
                continue
            if event.step_id not in {"__loop__", "__plan__"} and event.step_id not in manifest_by_step:
                raise ValueError("loop event step is not in admitted plan")
            if event.event_type in {"step.attempted", "step.observed"}:
                expected = manifest_by_step[event.step_id]
                if event.execution_id != expected["execution_id"]:
                    raise ValueError("loop event execution_id is not bound to plan")
                if event.attempt_id is None or event.attempt_id != f"{expected['execution_id']}:attempt-{event.attempt}":
                    raise ValueError("loop event attempt_id is not bound to plan")
                if event.idempotency_key.startswith(event.attempt_id or "") is False:
                    raise ValueError("loop event attempt identity is invalid")
            if event.event_type == "loop.started":
                if status not in {"admitted", "paused_unknown"}:
                    raise ValueError("loop.started follows invalid loop state")
                status = "running"
                current_step_id = None
                continue
            if event.event_type == "step.attempted":
                if status != "running":
                    raise ValueError("step.attempted requires a running loop")
                if event.execution_id is None or event.attempt_id is None:
                    raise ValueError("step.attempted requires attempt identity")
                old = steps.get(event.step_id)
                if old is not None and old["status"] == "verified_committed":
                    raise ValueError("verified step cannot be attempted again")
                if old is not None and event.attempt < old["attempt"]:
                    raise ValueError("step attempt moved backwards")
                expected = manifest_by_step[event.step_id]
                if event.attempt > expected["max_attempts"]:
                    raise ValueError("step attempt exceeds plan maximum")
                steps[event.step_id] = {
                    "status": "attempted",
                    "attempt": event.attempt,
                    "execution_id": event.execution_id,
                    "attempt_id": event.attempt_id,
                    "reason_code": event.reason_code,
                    "observed_digest": None,
                }
                current_step_id = event.step_id
                continue
            if event.event_type == "step.action_failed":
                if status != "running":
                    raise ValueError("step.action_failed requires a running loop")
                if event.execution_id is None or event.attempt_id is None:
                    raise ValueError("step.action_failed requires attempt identity")
                old = steps.get(event.step_id)
                if old is None or old["status"] != "attempted":
                    raise ValueError("step.action_failed requires an attempted step")
                if old["attempt"] != event.attempt or old["attempt_id"] != event.attempt_id:
                    raise ValueError("step.action_failed attempt does not match attempted step")
                # Trajectory record only: the step verdict still comes from step.observed.
                current_step_id = event.step_id
                continue
            if event.event_type == "step.observed":
                if event.step_id not in steps:
                    raise ValueError("observation has no attempted step")
                old = steps[event.step_id]
                if old["attempt"] != event.attempt or old["attempt_id"] != event.attempt_id:
                    raise ValueError("observation attempt does not match attempted step")
                if event.status not in {"verified_committed", "verified_absent", "paused_unknown"}:
                    raise ValueError("step observation status is invalid")
                old = dict(old)
                old["status"] = event.status
                old["reason_code"] = event.reason_code
                old["observed_digest"] = event.observed_digest
                steps[event.step_id] = old
                current_step_id = event.step_id if event.status == "paused_unknown" else None
                continue
            if event.event_type == "loop.paused":
                if status != "running" or event.status != "paused_unknown":
                    raise ValueError("loop.paused follows invalid loop state")
                status = "paused_unknown"
                current_step_id = event.step_id if event.step_id != "__loop__" else current_step_id
                continue
            if event.event_type == "loop.failed":
                if status not in {"running", "paused_unknown"} or event.status != "failed":
                    raise ValueError("loop.failed follows invalid loop state")
                status = "failed"
                current_step_id = None
                continue
            if event.event_type == "loop.finished":
                if status != "running" or event.status != "finished":
                    raise ValueError("loop.finished follows invalid loop state")
                if set(steps) != set(manifest_by_step) or any(step["status"] != "verified_committed" for step in steps.values()):
                    raise ValueError("loop.finished has unverified or missing steps")
                status = "finished"
                current_step_id = None
                continue
            raise ValueError("unsupported agent loop event")
        return LoopState(status, plan_digest, current_step_id, steps, events[-1].sequence)

    @staticmethod
    def _checkpoint_dict(state: LoopState, cursor: str | None) -> dict[str, Any]:
        body = {
            "schema_version": "northstar.agent-loop-checkpoint.v1",
            "plan_digest": state.plan_digest,
            "sequence": state.sequence,
            "cursor": cursor,
            "state": state.to_dict(),
        }
        return {**body, "state_digest": _digest(body)}

    def _write_checkpoint_locked(self, events: list[LoopEvent]) -> None:
        state = self._derive(events)
        checkpoint = self._checkpoint_dict(
            state,
            events[-1].event_digest if events else None,
        )
        fd = -1
        temporary: Path | None = None
        try:
            fd, name = tempfile.mkstemp(
                prefix=f".{self.checkpoint_path.name}.",
                dir=str(self.checkpoint_path.parent),
            )
            temporary = Path(name)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(_canonical(checkpoint) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.checkpoint_path)
        except OSError as error:
            if fd != -1:
                os.close(fd)
            if temporary is not None:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
            raise ValueError("agent loop checkpoint could not be persisted") from error

    def _append_event(
        self,
        *,
        plan_digest: str,
        event_type: str,
        step_id: str,
        execution_id: str | None = None,
        attempt_id: str | None = None,
        attempt: int = 0,
        status: str,
        reason_code: str | None,
        observed_digest: str | None = None,
        output_digest: str | None = None,
        plan_step_manifest: tuple[dict[str, Any], ...] | None = None,
        idempotency_key: str,
        recorded_at: int,
    ) -> LoopEvent:
        with self._locked():
            events = self._read_locked()
            for existing in events:
                if existing.idempotency_key == idempotency_key:
                    candidate = LoopEvent.create(
                        sequence=existing.sequence,
                        prev_event_digest=existing.prev_event_digest,
                        plan_digest=plan_digest,
                        event_type=event_type,
                        step_id=step_id,
                        execution_id=execution_id,
                        attempt_id=attempt_id,
                        attempt=attempt,
                        status=status,
                        reason_code=reason_code,
                        observed_digest=observed_digest,
                        output_digest=output_digest,
                        plan_step_manifest=plan_step_manifest,
                        idempotency_key=idempotency_key,
                        recorded_at=recorded_at,
                    )
                    if candidate.to_dict() == existing.to_dict():
                        return existing
                    raise ValueError("agent loop event idempotency conflict")
            event = LoopEvent.create(
                sequence=len(events) + 1,
                prev_event_digest=events[-1].event_digest if events else None,
                plan_digest=plan_digest,
                event_type=event_type,
                step_id=step_id,
                execution_id=execution_id,
                attempt_id=attempt_id,
                attempt=attempt,
                status=status,
                reason_code=reason_code,
                observed_digest=observed_digest,
                output_digest=output_digest,
                plan_step_manifest=plan_step_manifest,
                idempotency_key=idempotency_key,
                recorded_at=recorded_at,
            )
            events.append(event)
            self._derive(events)
            try:
                with self.evidence_path.open("ab") as stream:
                    stream.write(_canonical(event.to_dict()) + b"\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as error:
                raise ValueError("agent loop event could not be persisted") from error
            self._write_checkpoint_locked(events)
            return event

    def _read_checkpoint_locked(self, state: LoopState, state_cursor: str | None) -> None:
        if not self.checkpoint_path.exists():
            raise ValueError("agent loop checkpoint is missing")
        try:
            value = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("agent loop checkpoint is invalid") from error
        fields = {"schema_version", "plan_digest", "sequence", "cursor", "state", "state_digest"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("agent loop checkpoint has unknown or missing fields")
        if value["schema_version"] != "northstar.agent-loop-checkpoint.v1":
            raise ValueError("agent loop checkpoint schema is invalid")
        if value["plan_digest"] != state.plan_digest or value["sequence"] != state.sequence:
            raise ValueError("agent loop checkpoint is stale")
        if value["state"] != state.to_dict():
            raise ValueError("agent loop checkpoint state does not match evidence")
        if value["cursor"] != state_cursor:
            raise ValueError("agent loop checkpoint cursor does not match evidence")
        supplied = _digest_field(value["state_digest"], "state_digest")
        body = {key: value[key] for key in ("schema_version", "plan_digest", "sequence", "cursor", "state")}
        if supplied != _digest(body):
            raise ValueError("agent loop checkpoint digest does not match")

    def _load_state(self, plan_digest: str) -> LoopState | None:
        with self._locked():
            events = self._read_locked()
            if not events:
                return None
            state = self._derive(events)
            if state.plan_digest != plan_digest:
                raise ValueError("agent loop plan digest does not match evidence")
            self._read_checkpoint_locked(
                state,
                events[-1].event_digest if events else None,
            )
            return state
    def admit(
        self,
        planner_output: AgentPlan | dict[str, Any],
        *,
        current_policy_revision: str,
    ) -> AgentPlan:
        if isinstance(planner_output, AgentPlan):
            plan = AgentPlan.from_dict(planner_output.to_dict())
        else:
            plan = AgentPlan.from_dict(planner_output)
        if not isinstance(current_policy_revision, str) or current_policy_revision != plan.policy_revision:
            raise ValueError("current policy revision does not match plan")
        for field in ("task_id", "thread_id", "run_id", "trace_id"):
            if getattr(plan, field) != getattr(self.run_contract, field):
                raise ValueError(f"plan {field} does not match run")
        if plan.actor_id != self.actor_id:
            raise ValueError("plan actor_id does not match host binding")
        if plan.workspace_id != self.workspace_id:
            raise ValueError("plan workspace_id does not match host binding")
        run_scopes = set(self.run_contract.scope_snapshot)
        for step in plan.steps:
            if step.action_id not in self.actions:
                raise ValueError(f"unknown action_id: {step.action_id}")
            if not set(step.scope_snapshot).issubset(run_scopes):
                raise ValueError(f"step {step.step_id} scope exceeds run scope")
            if step.deadline_at > self.run_contract.deadline_at:
                raise ValueError(f"step {step.step_id} deadline exceeds run deadline")
        return plan

    @staticmethod
    def _execution_id(step: PlanStep) -> str:
        return f"execution-{step.idempotency_key}"

    def _observe(self, step: PlanStep, attempt_id: str) -> PostconditionResult:
        try:
            result = self.observer(step, attempt_id)
        except BaseException:
            return PostconditionResult("unknown", "observer_exception")
        if not isinstance(result, PostconditionResult):
            return PostconditionResult("unknown", "observer_result_invalid")
        return result

    def _record_observation(
        self,
        plan: AgentPlan,
        step: PlanStep,
        attempt: int,
        attempt_id: str,
        result: PostconditionResult,
        *,
        output_digest: str | None = None,
        now: int,
    ) -> None:
        status = {
            "verified": "verified_committed",
            "absent": "verified_absent",
            "unknown": "paused_unknown",
        }[result.verdict]
        self._append_event(
            plan_digest=plan.plan_digest,
            event_type="step.observed",
            step_id=step.step_id,
            execution_id=self._execution_id(step),
            attempt_id=attempt_id,
            attempt=attempt,
            status=status,
            reason_code=result.reason_code,
            observed_digest=result.observed_digest,
            output_digest=output_digest,
            idempotency_key=f"{attempt_id}:observed:{result.verdict}",
            recorded_at=now,
        )

    def _run_attempt(
        self,
        plan: AgentPlan,
        step: PlanStep,
        attempt: int,
        *,
        now: int,
        observe_only: bool = False,
        existing_attempt_id: str | None = None,
    ) -> PostconditionResult:
        execution_id = self._execution_id(step)
        attempt_id = existing_attempt_id or f"{execution_id}:attempt-{attempt}"
        output_digest: str | None = None
        if not observe_only:
            self._append_event(
                plan_digest=plan.plan_digest,
                event_type="step.attempted",
                step_id=step.step_id,
                execution_id=execution_id,
                attempt_id=attempt_id,
                attempt=attempt,
                status="attempted",
                reason_code="action_attempted",
                idempotency_key=f"{attempt_id}:attempted",
                recorded_at=now,
            )
            try:
                output = self.actions[step.action_id](step, attempt_id)
            except KeyboardInterrupt:
                raise
            except BaseException as error:
                output = None
                # Record the failure itself: "action ran" and "action raised"
                # must be distinguishable in the evidence stream.
                self._append_event(
                    plan_digest=plan.plan_digest,
                    event_type="step.action_failed",
                    step_id=step.step_id,
                    execution_id=execution_id,
                    attempt_id=attempt_id,
                    attempt=attempt,
                    status="attempted",
                    reason_code=_failure_reason(error),
                    idempotency_key=f"{attempt_id}:action-failed",
                    recorded_at=now,
                )
            if isinstance(output, dict):
                output_digest = _digest(output)
        result = self._observe(step, attempt_id)
        self._record_observation(
            plan,
            step,
            attempt,
            attempt_id,
            result,
            output_digest=output_digest,
            now=now,
        )
        return result

    def _execute(
        self,
        plan: AgentPlan,
        *,
        owner_id: str,
        now: int,
        current_policy_revision: str,
    ) -> LoopState:
        _id(owner_id, "owner_id")
        if not isinstance(now, int) or isinstance(now, bool) or now <= 0:
            raise ValueError("now must be a positive integer")
        if now >= self.run_contract.deadline_at:
            raise ValueError("run deadline has expired")
        if not isinstance(current_policy_revision, str) or not current_policy_revision:
            raise ValueError("current policy revision is required")
        plan = self.admit(plan, current_policy_revision=current_policy_revision)
        expected_manifest = _manifest_for_plan(plan)
        state = self._load_state(plan.plan_digest)
        if state is not None:
            with self._locked():
                events = self._read_locked()
                if not events or events[0].plan_step_manifest != expected_manifest:
                    raise ValueError("admitted plan manifest does not match supplied plan")
        if state is None:
            self._append_event(
                plan_digest=plan.plan_digest,
                event_type="plan.admitted",
                step_id="__plan__",
                plan_step_manifest=_manifest_for_plan(plan),
                status="admitted",
                reason_code="plan_admitted",
                idempotency_key=f"{plan.plan_digest}:admitted",
                recorded_at=now,
            )
            state = self._load_state(plan.plan_digest)
            assert state is not None
        if state.status == "finished":
            return state
        if state.status == "failed":
            raise ValueError("agent loop has already failed")
        if state.status == "admitted":
            self._append_event(
                plan_digest=plan.plan_digest,
                event_type="loop.started",
                step_id="__loop__",
                status="running",
                reason_code="loop_started",
                idempotency_key=f"{plan.plan_digest}:started",
                recorded_at=now,
            )
        elif state.status == "paused_unknown":
            self._append_event(
                plan_digest=plan.plan_digest,
                event_type="loop.started",
                step_id="__loop__",
                status="running",
                reason_code="loop_resumed_for_readback",
                idempotency_key=f"{plan.plan_digest}:resumed:{state.sequence + 1}",
                recorded_at=now,
            )

        for step in plan.steps:
            state = self._load_state(plan.plan_digest)
            assert state is not None
            details = state.steps.get(step.step_id)
            if details is not None and details["status"] == "verified_committed":
                continue
            if details is not None and details["status"] in {"attempted", "paused_unknown"}:
                result = self._run_attempt(
                    plan,
                    step,
                    details["attempt"],
                    now=now,
                    observe_only=True,
                    existing_attempt_id=details["attempt_id"],
                )
                if result.verdict == "unknown":
                    self._append_event(
                        plan_digest=plan.plan_digest,
                        event_type="loop.paused",
                        step_id=step.step_id,
                        execution_id=details["execution_id"],
                        attempt_id=details["attempt_id"],
                        attempt=details["attempt"],
                        status="paused_unknown",
                        reason_code=result.reason_code,
                        idempotency_key=f"{details['attempt_id']}:paused",
                        recorded_at=now,
                    )
                    return self._load_state(plan.plan_digest)  # type: ignore[return-value]
                if result.verdict == "verified":
                    continue
                details = self._load_state(plan.plan_digest).steps[step.step_id]  # type: ignore[union-attr]
            attempt = details["attempt"] + 1 if details is not None else 1
            while attempt <= step.max_attempts:
                if now >= step.deadline_at:
                    self._append_event(
                        plan_digest=plan.plan_digest,
                        event_type="loop.failed",
                        step_id=step.step_id,
                        status="failed",
                        reason_code="step_deadline_expired",
                        idempotency_key=f"{plan.plan_digest}:{step.step_id}:deadline-failed",
                        recorded_at=now,
                    )
                    return self._load_state(plan.plan_digest)  # type: ignore[return-value]
                result = self._run_attempt(plan, step, attempt, now=now)
                if result.verdict == "verified":
                    break
                if result.verdict == "unknown":
                    attempt_id = f"{self._execution_id(step)}:attempt-{attempt}"
                    self._append_event(
                        plan_digest=plan.plan_digest,
                        event_type="loop.paused",
                        step_id=step.step_id,
                        execution_id=self._execution_id(step),
                        attempt_id=attempt_id,
                        attempt=attempt,
                        status="paused_unknown",
                        reason_code=result.reason_code,
                        idempotency_key=f"{attempt_id}:paused",
                        recorded_at=now,
                    )
                    return self._load_state(plan.plan_digest)  # type: ignore[return-value]
                attempt += 1
            else:
                self._append_event(
                    plan_digest=plan.plan_digest,
                    event_type="loop.failed",
                    step_id=step.step_id,
                    status="failed",
                    reason_code="max_attempts_exhausted",
                    idempotency_key=f"{plan.plan_digest}:{step.step_id}:attempts-exhausted",
                    recorded_at=now,
                )
                return self._load_state(plan.plan_digest)  # type: ignore[return-value]

        self._append_event(
            plan_digest=plan.plan_digest,
            event_type="loop.finished",
            step_id="__loop__",
            status="finished",
            reason_code="all_postconditions_verified",
            idempotency_key=f"{plan.plan_digest}:finished",
            recorded_at=now,
        )
        return self._load_state(plan.plan_digest)  # type: ignore[return-value]

    def run(
        self,
        plan: AgentPlan,
        *,
        owner_id: str,
        now: int,
        current_policy_revision: str,
    ) -> LoopState:
        return self._execute(
            plan,
            owner_id=owner_id,
            now=now,
            current_policy_revision=current_policy_revision,
        )

    def resume(
        self,
        plan: AgentPlan,
        *,
        owner_id: str,
        now: int,
        current_policy_revision: str,
    ) -> LoopState:
        return self._execute(
            plan,
            owner_id=owner_id,
            now=now,
            current_policy_revision=current_policy_revision,
        )

    def state(self, plan_digest: str) -> LoopState:
        _digest_field(plan_digest, "plan_digest")
        state = self._load_state(plan_digest)
        if state is None:
            raise ValueError("agent loop has no evidence history")
        return state
