"""Deterministic backend selection above backend-specific adapters."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from interop_contract import AgentProfile, HandoffRequest
from process_backend import ProcessBackendSpec

_SCHEMA = "northstar.route-request.v1"
_DECISION_SCHEMA = "northstar.route-decision.v1"
_ID_RE = re.compile(r"^[^\s/\\]+$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CAP_RE = re.compile(r"^[^\s/\\:]+:[^\s/\\:]+$")
_HEALTH = {"healthy", "degraded", "cooldown", "unhealthy"}
_FIELDS = {
    "schema_version", "task_id", "thread_id", "run_id", "actor_id", "workspace_id",
    "policy_revision", "step_id", "trace_id", "input_digest", "requested_capabilities",
    "deadline_at", "preferred_agent_ids", "excluded_agent_ids",
}
_DECISION_FIELDS = {
    "schema_version", "route_id", "task_id", "thread_id", "run_id", "actor_id",
    "workspace_id", "policy_revision", "step_id", "trace_id", "input_digest",
    "requested_capabilities", "deadline_at", "target_agent_id", "provider",
    "backend_version", "priority", "selected_at",
}


def _id(value: Any, field: str, limit: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or not _ID_RE.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _caps(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > 32:
        raise ValueError("requested_capabilities must be a non-empty bounded list")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _CAP_RE.fullmatch(item) or "*" in item:
            raise ValueError("requested_capabilities contains an invalid capability")
        if item in result:
            raise ValueError("requested_capabilities contains a duplicate")
        result.append(item)
    return tuple(sorted(result))


def _ids(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError(f"{field} must be a bounded list")
    result: list[str] = []
    for item in value:
        normalized = _id(item, field)
        if normalized in result:
            raise ValueError(f"{field} contains a duplicate")
        result.append(normalized)
    return tuple(result)


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class RouteRequest:
    schema_version: str
    task_id: str
    thread_id: str
    run_id: str
    actor_id: str
    workspace_id: str
    policy_revision: str
    step_id: str
    trace_id: str
    input_digest: str
    requested_capabilities: tuple[str, ...]
    deadline_at: int
    preferred_agent_ids: tuple[str, ...]
    excluded_agent_ids: tuple[str, ...]

    @classmethod
    def from_dict(cls, value: Any) -> "RouteRequest":
        if not isinstance(value, dict):
            raise ValueError("route request must be an object")
        missing = sorted(_FIELDS - set(value))
        unknown = sorted(set(value) - _FIELDS)
        if missing:
            raise ValueError(f"route request missing fields: {', '.join(missing)}")
        if unknown:
            raise ValueError(f"route request has unknown fields: {', '.join(unknown)}")
        if value["schema_version"] != _SCHEMA:
            raise ValueError("route request schema_version is invalid")
        deadline = value["deadline_at"]
        if not isinstance(deadline, int) or isinstance(deadline, bool) or deadline <= 0:
            raise ValueError("deadline_at must be a positive integer")
        preferred = _ids(value["preferred_agent_ids"], "preferred_agent_ids")
        excluded = _ids(value["excluded_agent_ids"], "excluded_agent_ids")
        if set(preferred) & set(excluded):
            raise ValueError("preferred and excluded agents overlap")
        return cls(
            schema_version=_SCHEMA,
            task_id=_id(value["task_id"], "task_id"),
            thread_id=_id(value["thread_id"], "thread_id"),
            run_id=_id(value["run_id"], "run_id"),
            actor_id=_id(value["actor_id"], "actor_id"),
            workspace_id=_id(value["workspace_id"], "workspace_id"),
            policy_revision=_id(value["policy_revision"], "policy_revision"),
            step_id=_id(value["step_id"], "step_id"),
            trace_id=_id(value["trace_id"], "trace_id"),
            input_digest=_digest(value["input_digest"], "input_digest"),
            requested_capabilities=_caps(value["requested_capabilities"]),
            deadline_at=deadline,
            preferred_agent_ids=preferred,
            excluded_agent_ids=excluded,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "thread_id": self.thread_id,
            "run_id": self.run_id,
            "actor_id": self.actor_id,
            "workspace_id": self.workspace_id,
            "policy_revision": self.policy_revision,
            "step_id": self.step_id,
            "trace_id": self.trace_id,
            "input_digest": self.input_digest,
            "requested_capabilities": list(self.requested_capabilities),
            "deadline_at": self.deadline_at,
            "preferred_agent_ids": list(self.preferred_agent_ids),
            "excluded_agent_ids": list(self.excluded_agent_ids),
        }

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())


@dataclass(frozen=True)
class RouteDecision:
    schema_version: str
    route_id: str
    task_id: str
    thread_id: str
    run_id: str
    actor_id: str
    workspace_id: str
    policy_revision: str
    step_id: str
    trace_id: str
    input_digest: str
    requested_capabilities: tuple[str, ...]
    deadline_at: int
    target_agent_id: str
    provider: str
    backend_version: str
    priority: int
    selected_at: int

    @classmethod
    def from_dict(cls, value: Any) -> "RouteDecision":
        if not isinstance(value, dict):
            raise ValueError("route decision must be an object")
        if set(value) != _DECISION_FIELDS:
            raise ValueError("route decision has unknown or missing fields")
        if value["schema_version"] != _DECISION_SCHEMA:
            raise ValueError("route decision schema_version is invalid")
        priority = value["priority"]
        if not isinstance(priority, int) or isinstance(priority, bool) or priority < 0:
            raise ValueError("priority must be a non-negative integer")
        selected_at = value["selected_at"]
        if not isinstance(selected_at, int) or isinstance(selected_at, bool) or selected_at <= 0:
            raise ValueError("selected_at must be a positive integer")
        deadline = value["deadline_at"]
        if not isinstance(deadline, int) or isinstance(deadline, bool) or deadline <= 0:
            raise ValueError("deadline_at must be a positive integer")
        return cls(
            schema_version=_DECISION_SCHEMA,
            route_id=_id(value["route_id"], "route_id"),
            task_id=_id(value["task_id"], "task_id"),
            thread_id=_id(value["thread_id"], "thread_id"),
            run_id=_id(value["run_id"], "run_id"),
            actor_id=_id(value["actor_id"], "actor_id"),
            workspace_id=_id(value["workspace_id"], "workspace_id"),
            policy_revision=_id(value["policy_revision"], "policy_revision"),
            step_id=_id(value["step_id"], "step_id"),
            trace_id=_id(value["trace_id"], "trace_id"),
            input_digest=_digest(value["input_digest"], "input_digest"),
            requested_capabilities=_caps(value["requested_capabilities"]),
            deadline_at=deadline,
            target_agent_id=_id(value["target_agent_id"], "target_agent_id"),
            provider=_id(value["provider"], "provider"),
            backend_version=_id(value["backend_version"], "backend_version", 64),
            priority=priority,
            selected_at=selected_at,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "route_id": self.route_id,
            "task_id": self.task_id,
            "thread_id": self.thread_id,
            "run_id": self.run_id,
            "actor_id": self.actor_id,
            "workspace_id": self.workspace_id,
            "policy_revision": self.policy_revision,
            "step_id": self.step_id,
            "trace_id": self.trace_id,
            "input_digest": self.input_digest,
            "requested_capabilities": list(self.requested_capabilities),
            "deadline_at": self.deadline_at,
            "target_agent_id": self.target_agent_id,
            "provider": self.provider,
            "backend_version": self.backend_version,
            "priority": self.priority,
            "selected_at": self.selected_at,
        }

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())


@dataclass
class _Backend:
    profile: AgentProfile
    adapter: Any
    priority: int
    enabled: bool = True
    health: str = "healthy"
    cooldown_until: int = 0


class BackendRouter:
    def __init__(self) -> None:
        self._backends: dict[str, _Backend] = {}

    def register(self, profile: AgentProfile, adapter: Any, *, priority: int = 100) -> None:
        if not isinstance(profile, AgentProfile) or not isinstance(priority, int) or isinstance(priority, bool) or priority < 0:
            raise ValueError("backend registration is invalid")
        if not hasattr(adapter, "agent_id") or adapter.agent_id != profile.agent_id:
            raise ValueError("adapter identity does not match profile")
        if profile.agent_id in self._backends:
            raise ValueError("backend is already registered")
        self._backends[profile.agent_id] = _Backend(profile, adapter, priority)

    def register_process_spec(self, spec: ProcessBackendSpec, adapter: Any, *, priority: int = 100) -> None:
        if not isinstance(spec, ProcessBackendSpec) or not spec.enabled:
            raise ValueError("only an enabled process spec can be registered")
        profile = AgentProfile.from_dict({
            "schema_version": "northstar.agent-profile.v1",
            "agent_id": spec.agent_id,
            "provider": spec.provider,
            "version": spec.version,
            "capabilities": sorted(spec.capability_map),
        })
        self.register(profile, adapter, priority=priority)

    def set_enabled(self, agent_id: str, enabled: bool) -> None:
        if agent_id not in self._backends or not isinstance(enabled, bool):
            raise ValueError("backend or enabled value is invalid")
        self._backends[agent_id].enabled = enabled

    def set_health(self, agent_id: str, health: str, *, now: int, cooldown_seconds: int = 0) -> None:
        if agent_id not in self._backends or health not in _HEALTH:
            raise ValueError("backend health is invalid")
        if not isinstance(now, int) or isinstance(now, bool) or now <= 0:
            raise ValueError("now must be a positive integer")
        if not isinstance(cooldown_seconds, int) or isinstance(cooldown_seconds, bool) or cooldown_seconds < 0:
            raise ValueError("cooldown_seconds is invalid")
        backend = self._backends[agent_id]
        backend.health = health
        backend.cooldown_until = now + cooldown_seconds if health == "cooldown" else 0

    def select(self, request: RouteRequest, *, now: int, current_policy_revision: str | None = None) -> RouteDecision:
        if not isinstance(request, RouteRequest):
            raise ValueError("route request is invalid")
        if not isinstance(now, int) or isinstance(now, bool) or now <= 0:
            raise ValueError("now must be a positive integer")
        if now >= request.deadline_at:
            raise ValueError("route request deadline has expired")
        if current_policy_revision is not None and current_policy_revision != request.policy_revision:
            raise ValueError("route policy revision is stale")
        excluded = set(request.excluded_agent_ids)
        candidates = [
            backend for backend in self._backends.values()
            if backend.enabled
            and backend.profile.agent_id not in excluded
            and (
                backend.health == "healthy"
                or (backend.health == "cooldown" and now >= backend.cooldown_until)
            )
            and now >= backend.cooldown_until
            and set(request.requested_capabilities).issubset(backend.profile.capabilities)
        ]
        if request.preferred_agent_ids:
            preferred = {
                agent_id: index
                for index, agent_id in enumerate(request.preferred_agent_ids)
            }
            candidates.sort(
                key=lambda item: (
                    0 if item.profile.agent_id in preferred else 1,
                    preferred.get(item.profile.agent_id, len(preferred)),
                    item.priority,
                    item.profile.agent_id,
                )
            )
        else:
            candidates.sort(key=lambda item: (item.priority, item.profile.agent_id))
        if not candidates:
            raise ValueError("no healthy backend supports the requested capabilities")
        selected = candidates[0]
        route_id = "route-" + hashlib.sha256(request.canonical_json() + b"\0" + selected.profile.agent_id.encode()).hexdigest()[:32]
        return RouteDecision.from_dict({
            "schema_version": _DECISION_SCHEMA,
            "route_id": route_id,
            "task_id": request.task_id,
            "thread_id": request.thread_id,
            "run_id": request.run_id,
            "actor_id": request.actor_id,
            "workspace_id": request.workspace_id,
            "policy_revision": request.policy_revision,
            "step_id": request.step_id,
            "trace_id": request.trace_id,
            "input_digest": request.input_digest,
            "requested_capabilities": list(request.requested_capabilities),
            "deadline_at": request.deadline_at,
            "target_agent_id": selected.profile.agent_id,
            "provider": selected.profile.provider,
            "backend_version": selected.profile.version,
            "priority": selected.priority,
            "selected_at": now,
        })

    def adapter_for(self, decision: RouteDecision, *, current_policy_revision: str | None = None) -> Any:
        if not isinstance(decision, RouteDecision):
            raise ValueError("route decision is invalid")
        if current_policy_revision is not None and current_policy_revision != decision.policy_revision:
            raise ValueError("route decision policy revision is stale")
        backend = self._backends.get(decision.target_agent_id)
        if backend is None or not backend.enabled:
            raise ValueError("route target is unavailable")
        if not (
            backend.health == "healthy"
            or (backend.health == "cooldown" and decision.selected_at >= backend.cooldown_until)
        ):
            raise ValueError("route target is unavailable")
        if backend.profile.provider != decision.provider or backend.profile.version != decision.backend_version:
            raise ValueError("route target profile changed")
        if not set(decision.requested_capabilities).issubset(backend.profile.capabilities):
            raise ValueError("route target no longer supports requested capabilities")
        return backend.adapter


def assert_route_matches_handoff(decision: RouteDecision, request: HandoffRequest) -> None:
    if not isinstance(decision, RouteDecision) or not isinstance(request, HandoffRequest):
        raise ValueError("route decision and handoff request are invalid")
    for field in (
        "task_id", "thread_id", "run_id", "actor_id", "workspace_id", "policy_revision",
        "step_id", "trace_id", "input_digest", "deadline_at",
    ):
        if getattr(decision, field) != getattr(request, field):
            if field == "deadline_at" and request.deadline_at < decision.deadline_at:
                continue
            raise ValueError(f"route {field} does not match handoff request")
    if decision.target_agent_id != request.target_agent_id:
        raise ValueError("route target does not match handoff target")
    if tuple(decision.requested_capabilities) != tuple(request.requested_capabilities):
        raise ValueError("route capabilities do not match handoff request")
