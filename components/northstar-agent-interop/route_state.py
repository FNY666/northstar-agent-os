"""Pure RouteEvent state-machine validation and bounded replay summary."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from route_ledger import RouteEvent, RouteReceipt

_IDENTITY_FIELDS = (
    "route_id", "task_id", "thread_id", "run_id", "actor_id", "workspace_id",
    "policy_revision", "step_id", "trace_id", "target_agent_id", "provider",
    "backend_version",
)


@dataclass(frozen=True)
class RouteState:
    status: str
    current_attempt: int
    receipt_count: int
    retry_count: int
    total_latency_ms: int
    failure_counts: dict[str, int]


class RouteStateMachine:
    """Validate and replay a complete bounded route event sequence."""

    @staticmethod
    def replay(events: Sequence[RouteEvent]) -> RouteState:
        if not isinstance(events, Sequence):
            raise ValueError("route events must be a sequence")
        if not events:
            raise ValueError("route history is empty")
        if any(not isinstance(event, RouteEvent) for event in events):
            raise ValueError("route history contains invalid event")
        try:
            events = tuple(RouteEvent.from_dict(event.to_dict()) for event in events)
        except (TypeError, ValueError) as error:
            raise ValueError("route history contains forged event") from error
        for expected, event in enumerate(events, start=1):
            if event.sequence != expected:
                raise ValueError("route event sequence is not contiguous")

        selected = events[0]
        if selected.event_type != "decision.selected" or set(selected.payload) != {"decision"}:
            raise ValueError("route history must begin with decision.selected")
        decision = selected.payload["decision"]
        try:
            from backend_router import RouteDecision
            checked_decision = RouteDecision.from_dict(decision)
        except (ImportError, TypeError, ValueError) as error:
            raise ValueError("route decision payload is invalid") from error
        if selected.decision_digest != _decision_digest(checked_decision):
            raise ValueError("route decision digest does not match payload")
        for field in _IDENTITY_FIELDS:
            if getattr(selected, field) != getattr(checked_decision, field):
                raise ValueError(f"route decision {field} does not match event")

        state = "selected"
        attempt = selected.attempt
        receipts = 0
        retries = 0
        latency = 0
        failures: dict[str, int] = {}
        previous_retryable = False

        for event in events[1:]:
            if event.event_type == "decision.selected":
                raise ValueError("route history contains duplicate decision")
            if set(event.payload) != {"receipt"}:
                raise ValueError("route receipt payload is invalid")
            try:
                receipt = RouteReceipt.from_dict(event.payload["receipt"])
            except (TypeError, ValueError) as error:
                raise ValueError("route receipt payload is invalid") from error
            if event.event_type != "route." + receipt.status:
                raise ValueError("route event type and receipt status disagree")
            if receipt.decision_digest != selected.decision_digest:
                raise ValueError("route receipt digest does not match decision")
            for field in _IDENTITY_FIELDS:
                if getattr(event, field) != getattr(selected, field):
                    raise ValueError(f"route event {field} does not match decision")
                if getattr(receipt, field) != getattr(selected, field):
                    raise ValueError(f"route receipt {field} does not match decision")
            if event.attempt != receipt.attempt or event.idempotency_key != receipt.idempotency_key:
                raise ValueError("route event metadata does not match receipt")
            receipts += 1
            latency += receipt.latency_ms
            if event.event_type == "route.started":
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
                    if receipt.failure_class is None:
                        raise ValueError("failed receipt has no failure class")
                    failures[receipt.failure_class] = failures.get(receipt.failure_class, 0) + 1
                previous_retryable = receipt.retryable
            else:
                raise ValueError("unsupported route event")

        return RouteState(
            status=state,
            current_attempt=attempt,
            receipt_count=receipts,
            retry_count=retries,
            total_latency_ms=latency,
            failure_counts=failures,
        )


def _decision_digest(decision: object) -> str:
    import hashlib
    import json
    value = decision.to_dict()
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
