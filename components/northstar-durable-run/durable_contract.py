"""Strict schemas for a durable Northstar run's local event boundary.

The durable-run component deliberately contains no model calls, tool execution,
filesystem persistence, or authorization decisions.  It only validates and
canonicalizes the identity and lifecycle data consumed by later runtime
components.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, ClassVar, Mapping

RUN_SCHEMA_VERSION = "northstar.durable-run.v1"
STEP_SCHEMA_VERSION = "northstar.durable-step.v1"
EVENT_SCHEMA_VERSION = "northstar.durable-event.v1"

MAX_ID_CHARS = 128
MAX_SCOPE_CHARS = 128
MAX_SCOPES = 64
MAX_POSTCONDITIONS = 64
MAX_IDEMPOTENCY_KEY_CHARS = 256
MAX_EVENT_TYPE_CHARS = 64
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[^\s/\\]+$")
_SCOPE_RE = re.compile(r"^[^\s/\\:]+:[^\s/\\:]+$")

RUN_STATUSES = frozenset({
    "planned",
    "running",
    "waiting",
    "finished",
    "failed",
    "cancelled",
})

_EVENT_STATUS_BY_TYPE = {
    "run.created": "planned",
    "run.started": "running",
    "run.waiting": "waiting",
    "run.finished": "finished",
    "run.failed": "failed",
    "run.cancelled": "cancelled",
    "run.retry": "planned",
    "step.planned": "planned",
    "step.retry": "planned",
    "step.started": "running",
    "step.waiting": "waiting",
    "step.finished": "finished",
    "step.failed": "failed",
    "step.cancelled": "cancelled",
    "checkpoint.created": "running",
}

_ALLOWED_TRANSITIONS = frozenset({
    ("planned", "running"),
    ("planned", "cancelled"),
    ("running", "waiting"),
    ("running", "finished"),
    ("running", "failed"),
    ("running", "cancelled"),
    ("waiting", "running"),
    ("waiting", "failed"),
    ("waiting", "cancelled"),
    ("failed", "planned"),
})


class _CanonicalContract:
    _fields: ClassVar[tuple[str, ...]]

    def to_dict(self) -> dict[str, Any]:
        raise NotImplementedError

    def canonical_json(self) -> bytes:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _require_exact_fields(
    value: Mapping[str, Any], expected: set[str], label: str
) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing:
        raise ValueError(f"{label} missing fields: {', '.join(missing)}")
    if unknown:
        raise ValueError(f"{label} has unknown fields: {', '.join(unknown)}")


def _require_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    if len(value) > MAX_ID_CHARS:
        raise ValueError(f"{field} is too long")
    if not _ID_RE.fullmatch(value):
        raise ValueError(f"{field} must not contain whitespace, /, or \\")
    return value


def _require_positive_integer(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    if value <= 0:
        raise ValueError(f"{field} must be positive")
    return value


def _require_status(value: Any, field: str = "status") -> str:
    if value not in RUN_STATUSES:
        raise ValueError(f"{field} is invalid")
    return value


def _require_scopes(value: Any, field: str = "scope_snapshot") -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    if len(value) > MAX_SCOPES:
        raise ValueError(f"{field} has too many entries")
    result: list[str] = []
    seen: set[str] = set()
    for index, scope in enumerate(value):
        if not isinstance(scope, str) or not scope:
            raise ValueError(f"{field}[{index}] must be a non-empty string")
        if len(scope) > MAX_SCOPE_CHARS or not _SCOPE_RE.fullmatch(scope):
            raise ValueError(f"{field}[{index}] is invalid")
        if scope in seen:
            raise ValueError(f"duplicate {field} entry: {scope}")
        seen.add(scope)
        result.append(scope)
    return tuple(result)


def _require_postconditions(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("expected_postconditions must be a list")
    if len(value) > MAX_POSTCONDITIONS:
        raise ValueError("expected_postconditions has too many entries")
    result: list[str] = []
    seen: set[str] = set()
    for index, name in enumerate(value):
        try:
            normalized = _require_id(name, f"expected_postconditions[{index}]")
        except ValueError as error:
            raise ValueError(str(error)) from error
        if normalized in seen:
            raise ValueError(f"duplicate expected postcondition: {normalized}")
        seen.add(normalized)
        result.append(normalized)
    return tuple(result)


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase sha256 digest")
    return value


def _require_idempotency_key(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("idempotency_key must be a non-empty string")
    if len(value) > MAX_IDEMPOTENCY_KEY_CHARS or not _ID_RE.fullmatch(value):
        raise ValueError("idempotency_key is invalid")
    return value


def _require_event_type(value: Any) -> str:
    if not isinstance(value, str) or value not in _EVENT_STATUS_BY_TYPE:
        raise ValueError("event_type is invalid")
    return value


def _to_list(values: tuple[str, ...]) -> list[str]:
    return list(values)


@dataclass(frozen=True)
class RunContract(_CanonicalContract):
    schema_version: str
    task_id: str
    thread_id: str
    run_id: str
    parent_run_id: str | None
    status: str
    deadline_at: int
    scope_snapshot: tuple[str, ...]
    trace_id: str

    _fields: ClassVar[tuple[str, ...]] = (
        "schema_version",
        "task_id",
        "thread_id",
        "run_id",
        "parent_run_id",
        "status",
        "deadline_at",
        "scope_snapshot",
        "trace_id",
    )

    @classmethod
    def from_dict(cls, value: Any) -> "RunContract":
        data = _require_object(value, "run contract")
        _require_exact_fields(data, set(cls._fields), "run contract")
        if data["schema_version"] != RUN_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {RUN_SCHEMA_VERSION}")
        task_id = _require_id(data["task_id"], "task_id")
        thread_id = _require_id(data["thread_id"], "thread_id")
        run_id = _require_id(data["run_id"], "run_id")
        parent = data["parent_run_id"]
        if parent is not None:
            parent = _require_id(parent, "parent_run_id")
        return cls(
            schema_version=RUN_SCHEMA_VERSION,
            task_id=task_id,
            thread_id=thread_id,
            run_id=run_id,
            parent_run_id=parent,
            status=_require_status(data["status"]),
            deadline_at=_require_positive_integer(data["deadline_at"], "deadline_at"),
            scope_snapshot=_require_scopes(data["scope_snapshot"]),
            trace_id=_require_id(data["trace_id"], "trace_id"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "thread_id": self.thread_id,
            "run_id": self.run_id,
            "parent_run_id": self.parent_run_id,
            "status": self.status,
            "deadline_at": self.deadline_at,
            "scope_snapshot": _to_list(self.scope_snapshot),
            "trace_id": self.trace_id,
        }


@dataclass(frozen=True)
class StepContract(_CanonicalContract):
    schema_version: str
    task_id: str
    thread_id: str
    run_id: str
    step_id: str
    step_version: int
    status: str
    attempt: int
    input_digest: str
    scope_snapshot: tuple[str, ...]
    idempotency_key: str
    expected_postconditions: tuple[str, ...]
    trace_id: str
    deadline_at: int

    _fields: ClassVar[tuple[str, ...]] = (
        "schema_version",
        "task_id",
        "thread_id",
        "run_id",
        "step_id",
        "step_version",
        "status",
        "attempt",
        "input_digest",
        "scope_snapshot",
        "idempotency_key",
        "expected_postconditions",
        "trace_id",
        "deadline_at",
    )

    @classmethod
    def from_dict(cls, value: Any) -> "StepContract":
        data = _require_object(value, "step contract")
        _require_exact_fields(data, set(cls._fields), "step contract")
        if data["schema_version"] != STEP_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {STEP_SCHEMA_VERSION}")
        return cls(
            schema_version=STEP_SCHEMA_VERSION,
            task_id=_require_id(data["task_id"], "task_id"),
            thread_id=_require_id(data["thread_id"], "thread_id"),
            run_id=_require_id(data["run_id"], "run_id"),
            step_id=_require_id(data["step_id"], "step_id"),
            step_version=_require_positive_integer(data["step_version"], "step_version"),
            status=_require_status(data["status"]),
            attempt=_require_positive_integer(data["attempt"], "attempt"),
            input_digest=_require_digest(data["input_digest"], "input_digest"),
            scope_snapshot=_require_scopes(data["scope_snapshot"]),
            idempotency_key=_require_idempotency_key(data["idempotency_key"]),
            expected_postconditions=_require_postconditions(
                data["expected_postconditions"]
            ),
            trace_id=_require_id(data["trace_id"], "trace_id"),
            deadline_at=_require_positive_integer(data["deadline_at"], "deadline_at"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "thread_id": self.thread_id,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "step_version": self.step_version,
            "status": self.status,
            "attempt": self.attempt,
            "input_digest": self.input_digest,
            "scope_snapshot": _to_list(self.scope_snapshot),
            "idempotency_key": self.idempotency_key,
            "expected_postconditions": _to_list(self.expected_postconditions),
            "trace_id": self.trace_id,
            "deadline_at": self.deadline_at,
        }


@dataclass(frozen=True)
class EventContract(_CanonicalContract):
    schema_version: str
    event_id: str
    task_id: str
    thread_id: str
    run_id: str
    step_id: str
    sequence: int
    event_type: str
    status: str
    occurred_at: int
    idempotency_key: str
    trace_id: str
    payload_digest: str

    _fields: ClassVar[tuple[str, ...]] = (
        "schema_version",
        "event_id",
        "task_id",
        "thread_id",
        "run_id",
        "step_id",
        "sequence",
        "event_type",
        "status",
        "occurred_at",
        "idempotency_key",
        "trace_id",
        "payload_digest",
    )

    @classmethod
    def from_dict(cls, value: Any) -> "EventContract":
        data = _require_object(value, "event contract")
        _require_exact_fields(data, set(cls._fields), "event contract")
        if data["schema_version"] != EVENT_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {EVENT_SCHEMA_VERSION}")
        event_type = _require_event_type(data["event_type"])
        status = _require_status(data["status"])
        expected_status = _EVENT_STATUS_BY_TYPE[event_type]
        if status != expected_status:
            raise ValueError(
                f"status {status} does not match event_type {event_type}"
            )
        return cls(
            schema_version=EVENT_SCHEMA_VERSION,
            event_id=_require_id(data["event_id"], "event_id"),
            task_id=_require_id(data["task_id"], "task_id"),
            thread_id=_require_id(data["thread_id"], "thread_id"),
            run_id=_require_id(data["run_id"], "run_id"),
            step_id=_require_id(data["step_id"], "step_id"),
            sequence=_require_positive_integer(data["sequence"], "sequence"),
            event_type=event_type,
            status=status,
            occurred_at=_require_positive_integer(data["occurred_at"], "occurred_at"),
            idempotency_key=_require_idempotency_key(data["idempotency_key"]),
            trace_id=_require_id(data["trace_id"], "trace_id"),
            payload_digest=_require_digest(data["payload_digest"], "payload_digest"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "task_id": self.task_id,
            "thread_id": self.thread_id,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "sequence": self.sequence,
            "event_type": self.event_type,
            "status": self.status,
            "occurred_at": self.occurred_at,
            "idempotency_key": self.idempotency_key,
            "trace_id": self.trace_id,
            "payload_digest": self.payload_digest,
        }


def validate_deadline(run: RunContract, *, now: int) -> bool:
    if not isinstance(run, RunContract):
        raise ValueError("run must be a RunContract")
    if not isinstance(now, int) or isinstance(now, bool):
        raise ValueError("now must be an integer")
    if now >= run.deadline_at:
        raise ValueError("run deadline has expired")
    return True


def can_transition(current: Any, target: Any) -> bool:
    return (current, target) in _ALLOWED_TRANSITIONS


def assert_transition(current: Any, target: Any) -> None:
    if not can_transition(current, target):
        raise ValueError(f"invalid durable status transition: {current} -> {target}")


def assert_step_identity(run: RunContract, step: StepContract) -> None:
    """Assert that a step belongs to the supplied run lineage."""
    if not isinstance(run, RunContract) or not isinstance(step, StepContract):
        raise ValueError("run and step must be contract instances")
    for field in ("task_id", "thread_id", "run_id", "trace_id"):
        if getattr(run, field) != getattr(step, field):
            raise ValueError(f"step {field} does not match run")
    if step.deadline_at > run.deadline_at:
        raise ValueError("step deadline exceeds run deadline")


def assert_event_identity(
    run: RunContract, step: StepContract, event: EventContract
) -> None:
    """Assert that an event belongs to both its run and step lineage."""
    if not isinstance(event, EventContract):
        raise ValueError("event must be an EventContract")
    assert_step_identity(run, step)
    for field in ("task_id", "thread_id", "run_id", "trace_id"):
        if getattr(step, field) != getattr(event, field):
            raise ValueError(f"event {field} does not match step")
    if event.step_id != step.step_id:
        raise ValueError("event step_id does not match step")
    if event.occurred_at > run.deadline_at:
        raise ValueError("event occurred after run deadline")
