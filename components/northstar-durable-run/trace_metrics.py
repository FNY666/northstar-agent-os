"""Small structured trace and metrics boundary for durable runs."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

_ID_RE = re.compile(r"^[^\s/\\]+$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SPAN_KINDS = {"agent_step", "chat", "execute_tool", "handoff", "guardrail", "checkpoint"}
_APPROVAL_STATES = {"not_required", "required", "approved", "denied"}
_STATUSES = {"ok", "error", "cancelled", "waiting"}

_SPAN_FIELDS = {
    "schema_version",
    "span_id",
    "parent_span_id",
    "trace_id",
    "task_id",
    "thread_id",
    "run_id",
    "step_id",
    "span_kind",
    "name",
    "started_at",
    "ended_at",
    "attempt",
    "tool_name",
    "scope_digest",
    "approval_state",
    "status",
    "error_class",
    "verifier_verdict",
    "input_tokens",
    "output_tokens",
    "cost_micros",
}


def _id(value: Any, field: str, *, allow_none: bool = False) -> str | None:
    if allow_none and value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 128 or not _ID_RE.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _positive(value: Any, field: str, *, allow_none: bool = False) -> int | None:
    if allow_none and value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase sha256 digest")
    return value


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class TraceSpan:
    schema_version: str
    span_id: str
    parent_span_id: str | None
    trace_id: str
    task_id: str
    thread_id: str
    run_id: str
    step_id: str
    span_kind: str
    name: str
    started_at: int
    ended_at: int
    attempt: int
    tool_name: str | None
    scope_digest: str
    approval_state: str
    status: str
    error_class: str | None
    verifier_verdict: str | None
    input_tokens: int
    output_tokens: int
    cost_micros: int

    @classmethod
    def from_dict(cls, value: Any) -> "TraceSpan":
        if not isinstance(value, dict):
            raise ValueError("trace span must be an object")
        missing = sorted(_SPAN_FIELDS - set(value))
        unknown = sorted(set(value) - _SPAN_FIELDS)
        if missing:
            raise ValueError(f"trace span missing fields: {', '.join(missing)}")
        if unknown:
            raise ValueError(f"trace span has unknown fields: {', '.join(unknown)}")
        if value["schema_version"] != "northstar.trace-span.v1":
            raise ValueError("trace span schema_version is invalid")
        started = _positive(value["started_at"], "started_at")
        ended = _positive(value["ended_at"], "ended_at")
        assert started is not None and ended is not None
        if ended < started:
            raise ValueError("ended_at cannot precede started_at")
        if value["span_kind"] not in _SPAN_KINDS:
            raise ValueError("span_kind is invalid")
        if not isinstance(value["name"], str) or not value["name"]:
            raise ValueError("span name is invalid")
        if value["approval_state"] not in _APPROVAL_STATES:
            raise ValueError("approval_state is invalid")
        if value["status"] not in _STATUSES:
            raise ValueError("status is invalid")
        verdict = value["verifier_verdict"]
        if verdict is not None and verdict not in {"verified", "failed", "unknown"}:
            raise ValueError("verifier_verdict is invalid")
        for field in ("input_tokens", "output_tokens", "cost_micros"):
            _positive(value[field], field)
        if not isinstance(value["attempt"], int) or isinstance(value["attempt"], bool) or value["attempt"] <= 0:
            raise ValueError("attempt must be a positive integer")
        _positive(value["attempt"], "attempt")
        for field in ("span_id", "trace_id", "task_id", "thread_id", "run_id", "step_id"):
            _id(value[field], field)
        _id(value["parent_span_id"], "parent_span_id", allow_none=True)
        _id(value["tool_name"], "tool_name", allow_none=True)
        _id(value["error_class"], "error_class", allow_none=True)
        _digest(value["scope_digest"], "scope_digest")
        return cls(
            schema_version=value["schema_version"],
            span_id=value["span_id"],
            parent_span_id=value["parent_span_id"],
            trace_id=value["trace_id"],
            task_id=value["task_id"],
            thread_id=value["thread_id"],
            run_id=value["run_id"],
            step_id=value["step_id"],
            span_kind=value["span_kind"],
            name=value["name"],
            started_at=started,
            ended_at=ended,
            attempt=value["attempt"],
            tool_name=value["tool_name"],
            scope_digest=value["scope_digest"],
            approval_state=value["approval_state"],
            status=value["status"],
            error_class=value["error_class"],
            verifier_verdict=verdict,
            input_tokens=value["input_tokens"],
            output_tokens=value["output_tokens"],
            cost_micros=value["cost_micros"],
        )

    @property
    def duration_ms(self) -> int:
        return (self.ended_at - self.started_at) * 1_000

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "trace_id": self.trace_id,
            "task_id": self.task_id,
            "thread_id": self.thread_id,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "span_kind": self.span_kind,
            "name": self.name,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "attempt": self.attempt,
            "tool_name": self.tool_name,
            "scope_digest": self.scope_digest,
            "approval_state": self.approval_state,
            "status": self.status,
            "error_class": self.error_class,
            "verifier_verdict": self.verifier_verdict,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_micros": self.cost_micros,
        }

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())


class TraceRecorder:
    def __init__(self, *, task_id: str, thread_id: str, run_id: str, trace_id: str):
        self.task_id = _id(task_id, "task_id")
        self.thread_id = _id(thread_id, "thread_id")
        self.run_id = _id(run_id, "run_id")
        self.trace_id = _id(trace_id, "trace_id")
        self._spans: list[TraceSpan] = []

    def record(self, value: dict[str, Any] | TraceSpan) -> TraceSpan:
        span = value if isinstance(value, TraceSpan) else TraceSpan.from_dict(value)
        for field, expected in (
            ("task_id", self.task_id),
            ("thread_id", self.thread_id),
            ("run_id", self.run_id),
            ("trace_id", self.trace_id),
        ):
            if getattr(span, field) != expected:
                raise ValueError(f"trace span {field} does not match recorder")
        if any(existing.span_id == span.span_id for existing in self._spans):
            raise ValueError("span_id already recorded")
        self._spans.append(span)
        return span

    def spans(self) -> tuple[TraceSpan, ...]:
        return tuple(self._spans)


@dataclass(frozen=True)
class MetricsSummary:
    span_count: int
    total_duration_ms: int
    total_cost_micros: int
    error_count: int
    verifier_counts: dict[str, int]

    @classmethod
    def from_spans(cls, spans: tuple[TraceSpan, ...] | list[TraceSpan]) -> "MetricsSummary":
        if not isinstance(spans, (tuple, list)):
            raise ValueError("spans must be a sequence")
        if not all(isinstance(span, TraceSpan) for span in spans):
            raise ValueError("spans contain an invalid value")
        verifier_counts: dict[str, int] = {}
        for span in spans:
            if span.verifier_verdict is not None:
                verifier_counts[span.verifier_verdict] = verifier_counts.get(span.verifier_verdict, 0) + 1
        return cls(
            span_count=len(spans),
            total_duration_ms=sum(span.duration_ms for span in spans),
            total_cost_micros=sum(span.cost_micros for span in spans),
            error_count=sum(span.status == "error" for span in spans),
            verifier_counts=verifier_counts,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "span_count": self.span_count,
            "total_duration_ms": self.total_duration_ms,
            "total_cost_micros": self.total_cost_micros,
            "error_count": self.error_count,
            "verifier_counts": dict(self.verifier_counts),
        }
