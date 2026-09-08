"""Append-only RouteDecision/Receipt ledger with deterministic replay."""
from __future__ import annotations

import hashlib
import json
import os
import fcntl
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backend_router import RouteDecision

_EVENT_SCHEMA = "northstar.route-event.v1"
_DECISION_SCHEMA = "northstar.route-decision-record.v1"
_RECEIPT_SCHEMA = "northstar.route-receipt.v1"
_CHECKED_STATUSES = {"started", "succeeded", "failed", "cancelled"}
_FAILURE_CLASSES = {
    "backend_timeout",
    "backend_process_exit",
    "backend_malformed_output",
    "backend_unavailable",
    "adapter_error",
    "policy_denied",
    "route_no_candidate",
    "cancelled_by_parent",
    "stale_policy",
}
FAILURE_CLASSES = frozenset({
    "backend_timeout",
    "backend_process_exit",
    "backend_malformed_output",
    "backend_unavailable",
    "adapter_error",
    "policy_denied",
    "route_no_candidate",
    "cancelled_by_parent",
    "stale_policy",
})
_ERROR_CODES = {
    "timeout",
    "process_exit",
    "malformed_output",
    "unavailable",
    "adapter_error",
    "policy_denied",
    "no_candidate",
    "cancelled",
    "stale_policy",
}
_CANCEL_FAILURE_CLASSES = {"cancelled_by_parent"}
_EVENT_TYPES = {"decision.selected", "route.started", "route.succeeded", "route.failed", "route.cancelled"}

_EVENT_FIELDS = {
    "schema_version", "event_id", "sequence", "event_type", "route_id", "task_id",
    "thread_id", "run_id", "actor_id", "workspace_id", "policy_revision", "step_id",
    "trace_id", "target_agent_id", "provider", "backend_version", "decision_digest",
    "payload_digest", "attempt", "idempotency_key", "recorded_at", "payload",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _id(value: Any, field: str, max_chars: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > max_chars or any(c.isspace() or c in "/\\\x00" for c in value):
        raise ValueError(f"{field} is invalid")
    return value


def _positive(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field} must be positive integer")
    return value


def _nonnegative(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be non-negative integer")
    return value


def _digest_field(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:") or any(c not in "0123456789abcdef" for c in value[7:]):
        raise ValueError(f"{field} is invalid")
    return value


def _caps(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError("capabilities must be non-empty list")
    result = tuple(sorted(value))
    if any(not isinstance(v, str) or ":" not in v or "*" in v for v in result) or len(set(result)) != len(result):
        raise ValueError("capabilities are invalid")
    return result


def _refs(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(v, str) or not v for v in value):
        raise ValueError("artifact_refs are invalid")
    return tuple(value)


def _identity(value: Any) -> dict[str, Any]:
    return {
        "route_id": value.route_id,
        "task_id": value.task_id,
        "thread_id": value.thread_id,
        "run_id": value.run_id,
        "actor_id": value.actor_id,
        "workspace_id": value.workspace_id,
        "policy_revision": value.policy_revision,
        "step_id": value.step_id,
        "trace_id": value.trace_id,
        "target_agent_id": value.target_agent_id,
        "provider": value.provider,
        "backend_version": value.backend_version,
    }


def _decision_dict(value: RouteDecision) -> dict[str, Any]:
    return value.to_dict()


@dataclass(frozen=True)
class RouteDecisionRecord:
    schema_version: str
    decision: RouteDecision
    decision_digest: str
    attempt: int
    idempotency_key: str
    recorded_at: int

    @classmethod
    def from_decision(cls, decision: RouteDecision, *, attempt: int, idempotency_key: str, recorded_at: int) -> "RouteDecisionRecord":
        if not isinstance(decision, RouteDecision):
            raise ValueError("decision is invalid")
        return cls(
            schema_version=_DECISION_SCHEMA,
            decision=decision,
            decision_digest=_digest(_decision_dict(decision)),
            attempt=_positive(attempt, "attempt"),
            idempotency_key=_id(idempotency_key, "idempotency_key"),
            recorded_at=_positive(recorded_at, "recorded_at"),
        )

    @classmethod
    def from_dict(cls, value: Any) -> "RouteDecisionRecord":
        if not isinstance(value, dict):
            raise ValueError("decision record must be object")
        fields = {"schema_version", "decision", "decision_digest", "attempt", "idempotency_key", "recorded_at"}
        if set(value) != fields:
            raise ValueError("decision record has unknown or missing fields")
        if value["schema_version"] != _DECISION_SCHEMA:
            raise ValueError("decision record schema is invalid")
        decision = RouteDecision.from_dict(value["decision"])
        result = cls(
            schema_version=_DECISION_SCHEMA,
            decision=decision,
            decision_digest=_digest_field(value["decision_digest"], "decision_digest"),
            attempt=_positive(value["attempt"], "attempt"),
            idempotency_key=_id(value["idempotency_key"], "idempotency_key"),
            recorded_at=_positive(value["recorded_at"], "recorded_at"),
        )
        if result.decision_digest != _digest(_decision_dict(decision)):
            raise ValueError("decision digest does not match decision")
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "decision": self.decision.to_dict(),
            "decision_digest": self.decision_digest,
            "attempt": self.attempt,
            "idempotency_key": self.idempotency_key,
            "recorded_at": self.recorded_at,
        }


@dataclass(frozen=True)
class RouteReceipt:
    schema_version: str
    decision_digest: str
    route_id: str
    task_id: str
    thread_id: str
    run_id: str
    actor_id: str
    workspace_id: str
    policy_revision: str
    step_id: str
    trace_id: str
    target_agent_id: str
    provider: str
    backend_version: str
    status: str
    attempt: int
    latency_ms: int
    failure_class: str | None
    error_code: str | None
    retryable: bool
    idempotency_key: str
    recorded_at: int

    @classmethod
    def from_decision(
        cls,
        decision: RouteDecision,
        *,
        status: str,
        attempt: int,
        latency_ms: int,
        failure_class: str | None,
        error_code: str | None,
        retryable: bool,
        idempotency_key: str,
        recorded_at: int,
    ) -> "RouteReceipt":
        record = RouteDecisionRecord.from_decision(
            decision,
            attempt=1,
            idempotency_key="decision",
            recorded_at=decision.selected_at,
        )
        return cls.from_dict(
            {
                "schema_version": _RECEIPT_SCHEMA,
                "decision_digest": record.decision_digest,
                **_identity(decision),
                "status": status,
                "attempt": attempt,
                "latency_ms": latency_ms,
                "failure_class": failure_class,
                "error_code": error_code,
                "retryable": retryable,
                "idempotency_key": idempotency_key,
                "recorded_at": recorded_at,
            }
        )

    @classmethod
    def from_dict(cls, value: Any) -> "RouteReceipt":
        if not isinstance(value, dict):
            raise ValueError("route receipt must be object")
        fields = {
            "schema_version", "decision_digest", "route_id", "task_id", "thread_id", "run_id",
            "actor_id", "workspace_id", "policy_revision", "step_id", "trace_id", "target_agent_id",
            "provider", "backend_version", "status", "attempt", "latency_ms", "failure_class",
            "error_code", "retryable", "idempotency_key", "recorded_at",
        }
        if set(value) != fields:
            raise ValueError("route receipt has unknown or missing fields")
        if value["schema_version"] != _RECEIPT_SCHEMA:
            raise ValueError("route receipt schema is invalid")
        if value["status"] not in _CHECKED_STATUSES:
            raise ValueError("route receipt status is invalid")
        if not isinstance(value["retryable"], bool):
            raise ValueError("retryable must be boolean")
        failure = value["failure_class"]
        error = value["error_code"]
        if value["status"] == "failed":
            if failure not in FAILURE_CLASSES or error not in _ERROR_CODES:
                raise ValueError("failed receipt requires bounded failure fields")
        elif value["status"] == "cancelled":
            if failure != "cancelled_by_parent" or error != "cancelled" or value["retryable"]:
                raise ValueError("cancelled receipt has invalid cancellation fields")
        elif failure is not None or error is not None or value["retryable"]:
            raise ValueError("non-failed receipt cannot contain failure fields")
        return cls(
            schema_version=_RECEIPT_SCHEMA,
            decision_digest=_digest_field(value["decision_digest"], "decision_digest"),
            **{field: _id(value[field], field) for field in (
                "route_id", "task_id", "thread_id", "run_id", "actor_id", "workspace_id",
                "policy_revision", "step_id", "trace_id", "target_agent_id", "provider", "backend_version"
            )},
            status=value["status"],
            attempt=_positive(value["attempt"], "attempt"),
            latency_ms=_nonnegative(value["latency_ms"], "latency_ms"),
            failure_class=failure,
            error_code=error,
            retryable=value["retryable"],
            idempotency_key=_id(value["idempotency_key"], "idempotency_key"),
            recorded_at=_positive(value["recorded_at"], "recorded_at"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "decision_digest": self.decision_digest,
            "route_id": self.route_id,
            "task_id": self.task_id,
            "thread_id": self.thread_id,
            "run_id": self.run_id,
            "actor_id": self.actor_id,
            "workspace_id": self.workspace_id,
            "policy_revision": self.policy_revision,
            "step_id": self.step_id,
            "trace_id": self.trace_id,
            "target_agent_id": self.target_agent_id,
            "provider": self.provider,
            "backend_version": self.backend_version,
            "status": self.status,
            "attempt": self.attempt,
            "latency_ms": self.latency_ms,
            "failure_class": self.failure_class,
            "error_code": self.error_code,
            "retryable": self.retryable,
            "idempotency_key": self.idempotency_key,
            "recorded_at": self.recorded_at,
        }


@dataclass(frozen=True)
class RouteEvent:
    schema_version: str
    event_id: str
    sequence: int
    event_type: str
    route_id: str
    task_id: str
    thread_id: str
    run_id: str
    actor_id: str
    workspace_id: str
    policy_revision: str
    step_id: str
    trace_id: str
    target_agent_id: str
    provider: str
    backend_version: str
    decision_digest: str
    payload_digest: str
    attempt: int
    idempotency_key: str
    recorded_at: int
    payload: dict[str, Any]

    @classmethod
    def from_decision(cls, decision: RouteDecision, *, event_type: str, attempt: int, idempotency_key: str, recorded_at: int) -> "RouteEvent":
        if event_type != "decision.selected":
            raise ValueError("decision event_type is invalid")
        record = RouteDecisionRecord.from_decision(decision, attempt=attempt, idempotency_key=idempotency_key, recorded_at=recorded_at)
        return cls(
            schema_version=_EVENT_SCHEMA,
            event_id=idempotency_key,
            sequence=1,
            event_type=event_type,
            **_identity(decision),
            decision_digest=record.decision_digest,
            payload_digest=_digest({"decision": decision.to_dict()}),
            attempt=attempt,
            idempotency_key=idempotency_key,
            recorded_at=recorded_at,
            payload={"decision": decision.to_dict()},
        )

    @classmethod
    def from_receipt(cls, receipt: RouteReceipt, *, sequence: int) -> "RouteEvent":
        event_type = "route." + receipt.status
        if event_type not in _EVENT_TYPES:
            raise ValueError("receipt status cannot become event")
        return cls(
            schema_version=_EVENT_SCHEMA,
            event_id=receipt.idempotency_key,
            sequence=sequence,
            event_type=event_type,
            route_id=receipt.route_id,
            task_id=receipt.task_id,
            thread_id=receipt.thread_id,
            run_id=receipt.run_id,
            actor_id=receipt.actor_id,
            workspace_id=receipt.workspace_id,
            policy_revision=receipt.policy_revision,
            step_id=receipt.step_id,
            trace_id=receipt.trace_id,
            target_agent_id=receipt.target_agent_id,
            provider=receipt.provider,
            backend_version=receipt.backend_version,
            decision_digest=receipt.decision_digest,
            payload_digest=_digest({"receipt": receipt.to_dict()}),
            attempt=receipt.attempt,
            idempotency_key=receipt.idempotency_key,
            recorded_at=receipt.recorded_at,
            payload={"receipt": receipt.to_dict()},
        )

    @classmethod
    def from_dict(cls, value: Any) -> "RouteEvent":
        if not isinstance(value, dict) or set(value) != _EVENT_FIELDS:
            raise ValueError("route event has unknown or missing fields")
        if value["schema_version"] != _EVENT_SCHEMA or value["event_type"] not in _EVENT_TYPES:
            raise ValueError("route event is invalid")
        payload = value["payload"]
        if not isinstance(payload, dict) or set(payload) not in ({"decision"}, {"receipt"}):
            raise ValueError("route event payload is invalid")
        if value["event_type"] == "decision.selected" and set(payload) != {"decision"}:
            raise ValueError("decision event must contain a decision payload")
        if value["event_type"] != "decision.selected" and set(payload) != {"receipt"}:
            raise ValueError("route receipt event must contain a receipt payload")
        if value["payload_digest"] != _digest(payload):
            raise ValueError("route event payload digest does not match payload")
        return cls(
            schema_version=_EVENT_SCHEMA,
            event_id=_id(value["event_id"], "event_id"),
            sequence=_positive(value["sequence"], "sequence"),
            event_type=value["event_type"],
            route_id=_id(value["route_id"], "route_id"),
            task_id=_id(value["task_id"], "task_id"),
            thread_id=_id(value["thread_id"], "thread_id"),
            run_id=_id(value["run_id"], "run_id"),
            actor_id=_id(value["actor_id"], "actor_id"),
            workspace_id=_id(value["workspace_id"], "workspace_id"),
            policy_revision=_id(value["policy_revision"], "policy_revision"),
            step_id=_id(value["step_id"], "step_id"),
            trace_id=_id(value["trace_id"], "trace_id"),
            target_agent_id=_id(value["target_agent_id"], "target_agent_id"),
            provider=_id(value["provider"], "provider"),
            backend_version=_id(value["backend_version"], "backend_version"),
            decision_digest=_digest_field(value["decision_digest"], "decision_digest"),
            payload_digest=_digest_field(value["payload_digest"], "payload_digest"),
            attempt=_positive(value["attempt"], "attempt"),
            idempotency_key=_id(value["idempotency_key"], "idempotency_key"),
            recorded_at=_positive(value["recorded_at"], "recorded_at"),
            payload=payload,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass(frozen=True)
class RouteReplay:
    run_id: str
    route_id: str
    status: str
    current_attempt: int
    target_agent_id: str
    provider: str
    backend_version: str
    receipt_count: int
    retry_count: int
    total_latency_ms: int
    failure_counts: dict[str, int]


class RouteLedger:
    def __init__(self, path: str | Path):
        self.path = Path(path).absolute()
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path.touch(mode=0o600, exist_ok=True)
        os.chmod(self.lock_path, 0o600)

    @contextmanager
    def _locked(self):
        try:
            with self.lock_path.open("a+b") as lock:
                os.chmod(self.lock_path, 0o600)
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                yield
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        except OSError as error:
            raise ValueError("route ledger lock is unavailable") from error

    def _read_with_boundary(self) -> tuple[list[RouteEvent], int]:
        if not self.path.exists():
            return [], 0
        events: list[RouteEvent] = []
        valid_bytes = 0
        try:
            raw = self.path.read_bytes()
            lines = raw.splitlines(keepends=True)
        except OSError as error:
            raise ValueError("route ledger cannot be read") from error
        for index, raw_line in enumerate(lines):
            is_last = index == len(lines) - 1
            has_newline = raw_line.endswith((b"\n", b"\r"))
            try:
                line = raw_line.decode("utf-8")
                value = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                if is_last and not has_newline:
                    break
                raise ValueError("route ledger contains invalid event") from error
            if not line.strip():
                raise ValueError("route ledger contains blank line")
            try:
                events.append(RouteEvent.from_dict(value))
            except (TypeError, ValueError) as error:
                raise ValueError("route ledger contains invalid event") from error
            valid_bytes += len(raw_line)
        return events, valid_bytes

    def _read(self) -> list[RouteEvent]:
        events, _ = self._read_with_boundary()
        return events

    def _append(self, event: RouteEvent) -> RouteEvent:
        with self._locked():
            return self._append_locked(event)

    def _append_locked(self, event: RouteEvent) -> RouteEvent:
        events, valid_bytes = self._read_with_boundary()
        for existing in events:
            if existing.idempotency_key == event.idempotency_key:
                if existing.to_dict() == event.to_dict():
                    return existing
                raise ValueError("route event idempotency conflict")
        expected = len(events) + 1
        if event.sequence != expected:
            raise ValueError("route event sequence is not contiguous")
        candidate = events + [event]
        self._replay_events(candidate)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self.path.open("r+b" if self.path.exists() else "wb") as stream:
                stream.truncate(valid_bytes)
                stream.seek(0, os.SEEK_END)
                stream.write(_canonical(event.to_dict()) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as error:
            raise ValueError("route event could not be appended") from error
        return event

    def append_decision(self, decision: RouteDecision, *, attempt: int, idempotency_key: str, recorded_at: int) -> RouteEvent:
        record = RouteDecisionRecord.from_decision(decision, attempt=attempt, idempotency_key=idempotency_key, recorded_at=recorded_at)
        event = RouteEvent.from_decision(decision, event_type="decision.selected", attempt=attempt, idempotency_key=idempotency_key, recorded_at=recorded_at)
        if event.decision_digest != record.decision_digest:
            raise ValueError("decision digest mismatch")
        return self._append(event)

    def append_receipt(self, receipt: RouteReceipt) -> RouteEvent:
        if not isinstance(receipt, RouteReceipt):
            raise ValueError("receipt is invalid")
        with self._locked():
            return self._append_receipt_locked(receipt)

    def _append_receipt_locked(self, receipt: RouteReceipt) -> RouteEvent:
        events = self._read()
        if not events or events[0].event_type != "decision.selected":
            raise ValueError("route decision must be persisted first")
        decision_event = events[0]
        if receipt.decision_digest != decision_event.decision_digest:
            raise ValueError("receipt decision digest does not match decision")
        for field in ("route_id", "task_id", "thread_id", "run_id", "actor_id", "workspace_id", "policy_revision", "step_id", "trace_id", "target_agent_id", "provider", "backend_version"):
            if getattr(receipt, field) != getattr(decision_event, field):
                raise ValueError(f"receipt {field} does not match decision")
        existing = next(
            (item for item in events if item.idempotency_key == receipt.idempotency_key),
            None,
        )
        event = RouteEvent.from_receipt(
            receipt,
            sequence=existing.sequence if existing is not None else len(events) + 1,
        )
        return self._append_locked(event)

    def read_history(self, run_id: str) -> list[RouteEvent]:
        events = self._read()
        if events and events[0].run_id != run_id:
            raise ValueError("route ledger run_id does not match")
        self._replay_events(events)
        return events

    def _replay_events(self, events: list[RouteEvent]) -> RouteReplay | None:
        if not events:
            return None
        for index, event in enumerate(events, start=1):
            if event.sequence != index:
                raise ValueError("route event sequence is not contiguous")
        selected = events[0]
        if selected.event_type != "decision.selected" or "decision" not in selected.payload:
            raise ValueError("route ledger must begin with decision.selected")
        state = "selected"
        attempt = selected.attempt
        receipts = 0
        retries = 0
        latency = 0
        failures: dict[str, int] = {}
        previous_retryable = False
        for event in events[1:]:
            receipt = RouteReceipt.from_dict(event.payload.get("receipt"))
            if receipt.decision_digest != selected.decision_digest:
                raise ValueError("route receipt digest does not match decision")
            if event.payload_digest != _digest(event.payload):
                raise ValueError("route event payload digest does not match payload")
            if event.event_type == "route.started":
                receipts += 1
                latency += receipt.latency_ms
                if state in {"succeeded", "cancelled"}:
                    raise ValueError("terminal route cannot start")
                if receipt.attempt < attempt or receipt.attempt > attempt + 1:
                    raise ValueError("route attempt transition is invalid")
                if receipt.attempt == attempt + 1:
                    if state != "failed" or not previous_retryable:
                        raise ValueError("retry requires a retryable failed prior attempt")
                    retries += 1
                    state = "selected"
                if state not in {"selected", "failed"}:
                    raise ValueError("started receipt follows invalid state")
                state = "started"
                attempt = receipt.attempt
            elif event.event_type in {"route.succeeded", "route.failed", "route.cancelled"}:
                if state != "started" or receipt.attempt != attempt:
                    raise ValueError("terminal receipt follows invalid state")
                if event.event_type == "route.succeeded":
                    state = "succeeded"
                elif event.event_type == "route.cancelled":
                    state = "cancelled"
                else:
                    state = "failed"
                    assert receipt.failure_class is not None
                    failures[receipt.failure_class] = failures.get(receipt.failure_class, 0) + 1
                previous_retryable = receipt.retryable
                if event.event_type != "route.started":
                    receipts += 1
                    latency += receipt.latency_ms
            else:
                raise ValueError("unsupported route event in replay")
        return RouteReplay(
            run_id=selected.run_id,
            route_id=selected.route_id,
            status=state,
            current_attempt=attempt,
            target_agent_id=selected.target_agent_id,
            provider=selected.provider,
            backend_version=selected.backend_version,
            receipt_count=receipts,
            retry_count=retries,
            total_latency_ms=latency,
            failure_counts=failures,
        )

    def replay(self, run_id: str) -> RouteReplay:
        events = self.read_history(run_id)
        result = self._replay_events(events)
        if result is None:
            raise ValueError("route has no history")
        return result
