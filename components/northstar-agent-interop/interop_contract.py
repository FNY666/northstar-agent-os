"""Strict backend-neutral contracts for Northstar Agent handoffs."""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, ClassVar

PROFILE_SCHEMA_VERSION = "northstar.agent-profile.v1"
ATTESTATION_SCHEMA_VERSION = "northstar.agent-attestation.v1"
REQUEST_SCHEMA_VERSION = "northstar.handoff-request.v1"
GRANT_SCHEMA_VERSION = "northstar.handoff-grant.v1"

MAX_ID_CHARS = 128
MAX_VERSION_CHARS = 64
MAX_CAPABILITIES = 32
MAX_POSTCONDITIONS = 32
MAX_SCOPE_CHARS = 128
MAX_TIME = 9_223_372_036_854_775_807
_ID_RE = re.compile(r"^[^\s/\\]+$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SCOPE_RE = re.compile(r"^[^\s/\\:]+:[^\s/\\:]+$")


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _exact(data: Mapping[str, Any], fields: set[str], label: str) -> None:
    missing = sorted(fields - set(data))
    unknown = sorted(set(data) - fields)
    if missing:
        raise ValueError(f"{label} missing fields: {', '.join(missing)}")
    if unknown:
        raise ValueError(f"{label} has unknown fields: {', '.join(unknown)}")


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_ID_CHARS or not _ID_RE.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _version(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_VERSION_CHARS or not _ID_RE.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase sha256 digest")
    return value


def _positive(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= MAX_TIME:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _nonnegative(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_TIME:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _capabilities(value: Any, field: str = "capabilities") -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > MAX_CAPABILITIES:
        raise ValueError(f"{field} must be a bounded list")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        normalized = _id(item, f"{field} entry")
        if ":" not in normalized or any(part == "*" for part in normalized.split(":")) or normalized in seen:
            raise ValueError(f"{field} contains an invalid or duplicate capability")
        seen.add(normalized)
        result.append(normalized)
    return tuple(sorted(result))


def _scopes(value: Any, field: str = "scope") -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > MAX_CAPABILITIES:
        raise ValueError(f"{field} must be a bounded list")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or len(item) > MAX_SCOPE_CHARS or not _SCOPE_RE.fullmatch(item) or item in seen:
            raise ValueError(f"{field} contains an invalid or duplicate entry")
        seen.add(item)
        result.append(item)
    return tuple(result)


def _postconditions(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > MAX_POSTCONDITIONS:
        raise ValueError("expected_postconditions must be a bounded list")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        normalized = _id(item, "expected_postcondition")
        if normalized in seen:
            raise ValueError("expected_postconditions contains a duplicate")
        seen.add(normalized)
        result.append(normalized)
    return tuple(result)


def _to_list(values: tuple[str, ...]) -> list[str]:
    return list(values)


@dataclass(frozen=True)
class AgentProfile:
    schema_version: str
    agent_id: str
    provider: str
    version: str
    capabilities: frozenset[str]

    _fields: ClassVar[set[str]] = {"schema_version", "agent_id", "provider", "version", "capabilities"}

    @classmethod
    def from_dict(cls, value: Any) -> "AgentProfile":
        data = _object(value, "agent profile")
        _exact(data, cls._fields, "agent profile")
        if data["schema_version"] != PROFILE_SCHEMA_VERSION:
            raise ValueError("agent profile schema_version is invalid")
        capabilities = _capabilities(data["capabilities"])
        return cls(
            schema_version=PROFILE_SCHEMA_VERSION,
            agent_id=_id(data["agent_id"], "agent_id"),
            provider=_id(data["provider"], "provider"),
            version=_version(data["version"], "version"),
            capabilities=frozenset(capabilities),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "agent_id": self.agent_id,
            "provider": self.provider,
            "version": self.version,
            "capabilities": sorted(self.capabilities),
        }

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())


class AgentRegistry:
    def __init__(self) -> None:
        self._profiles: dict[str, AgentProfile] = {}

    def register(self, profile: AgentProfile) -> None:
        if not isinstance(profile, AgentProfile):
            raise ValueError("profile is invalid")
        if profile.agent_id in self._profiles:
            raise ValueError("agent is already registered")
        self._profiles[profile.agent_id] = profile

    def get(self, agent_id: str) -> AgentProfile | None:
        return self._profiles.get(agent_id)


@dataclass(frozen=True)
class AgentAttestation:
    schema_version: str
    task_id: str
    thread_id: str
    run_id: str
    actor_id: str
    workspace_id: str
    policy_revision: str
    agent_id: str
    step_id: str
    trace_id: str
    input_digest: str
    capabilities: tuple[str, ...]
    delegation_depth: int
    expires_at: int

    _fields: ClassVar[set[str]] = {
        "schema_version", "task_id", "thread_id", "run_id", "actor_id",
        "workspace_id", "policy_revision", "agent_id", "step_id", "trace_id",
        "input_digest", "capabilities", "delegation_depth", "expires_at",
    }

    @classmethod
    def from_dict(cls, value: Any) -> "AgentAttestation":
        data = _object(value, "agent attestation")
        _exact(data, cls._fields, "agent attestation")
        if data["schema_version"] != ATTESTATION_SCHEMA_VERSION:
            raise ValueError("agent attestation schema_version is invalid")
        return cls(
            schema_version=ATTESTATION_SCHEMA_VERSION,
            task_id=_id(data["task_id"], "task_id"),
            thread_id=_id(data["thread_id"], "thread_id"),
            run_id=_id(data["run_id"], "run_id"),
            actor_id=_id(data["actor_id"], "actor_id"),
            workspace_id=_id(data["workspace_id"], "workspace_id"),
            policy_revision=_id(data["policy_revision"], "policy_revision"),
            agent_id=_id(data["agent_id"], "agent_id"),
            step_id=_id(data["step_id"], "step_id"),
            trace_id=_id(data["trace_id"], "trace_id"),
            input_digest=_digest(data["input_digest"], "input_digest"),
            capabilities=_capabilities(data["capabilities"]),
            delegation_depth=_nonnegative(data["delegation_depth"], "delegation_depth"),
            expires_at=_positive(data["expires_at"], "expires_at"),
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
            "agent_id": self.agent_id,
            "step_id": self.step_id,
            "trace_id": self.trace_id,
            "input_digest": self.input_digest,
            "capabilities": _to_list(self.capabilities),
            "delegation_depth": self.delegation_depth,
            "expires_at": self.expires_at,
        }

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())


@dataclass(frozen=True)
class HandoffRequest:
    schema_version: str
    handoff_id: str
    task_id: str
    thread_id: str
    run_id: str
    actor_id: str
    workspace_id: str
    policy_revision: str
    source_agent_id: str
    target_agent_id: str
    step_id: str
    trace_id: str
    input_digest: str
    requested_capabilities: tuple[str, ...]
    expected_postconditions: tuple[str, ...]
    delegation_depth: int
    deadline_at: int
    requested_at: int
    idempotency_key: str

    _fields: ClassVar[set[str]] = {
        "schema_version", "handoff_id", "task_id", "thread_id", "run_id", "actor_id",
        "workspace_id", "policy_revision", "source_agent_id", "target_agent_id", "step_id", "trace_id",
        "input_digest", "requested_capabilities", "expected_postconditions", "delegation_depth",
        "deadline_at", "requested_at", "idempotency_key",
    }

    @classmethod
    def from_dict(cls, value: Any) -> "HandoffRequest":
        data = _object(value, "handoff request")
        _exact(data, cls._fields, "handoff request")
        if data["schema_version"] != REQUEST_SCHEMA_VERSION:
            raise ValueError("handoff request schema_version is invalid")
        requested_at = _positive(data["requested_at"], "requested_at")
        deadline_at = _positive(data["deadline_at"], "deadline_at")
        if deadline_at <= requested_at:
            raise ValueError("deadline_at must be after requested_at")
        depth = _positive(data["delegation_depth"], "delegation_depth")
        return cls(
            schema_version=REQUEST_SCHEMA_VERSION,
            handoff_id=_id(data["handoff_id"], "handoff_id"),
            task_id=_id(data["task_id"], "task_id"),
            thread_id=_id(data["thread_id"], "thread_id"),
            run_id=_id(data["run_id"], "run_id"),
            actor_id=_id(data["actor_id"], "actor_id"),
            workspace_id=_id(data["workspace_id"], "workspace_id"),
            policy_revision=_id(data["policy_revision"], "policy_revision"),
            source_agent_id=_id(data["source_agent_id"], "source_agent_id"),
            target_agent_id=_id(data["target_agent_id"], "target_agent_id"),
            step_id=_id(data["step_id"], "step_id"),
            trace_id=_id(data["trace_id"], "trace_id"),
            input_digest=_digest(data["input_digest"], "input_digest"),
            requested_capabilities=_capabilities(data["requested_capabilities"], "requested_capabilities"),
            expected_postconditions=_postconditions(data["expected_postconditions"]),
            delegation_depth=depth,
            deadline_at=deadline_at,
            requested_at=requested_at,
            idempotency_key=_id(data["idempotency_key"], "idempotency_key"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "handoff_id": self.handoff_id,
            "task_id": self.task_id,
            "thread_id": self.thread_id,
            "run_id": self.run_id,
            "actor_id": self.actor_id,
            "workspace_id": self.workspace_id,
            "policy_revision": self.policy_revision,
            "source_agent_id": self.source_agent_id,
            "target_agent_id": self.target_agent_id,
            "step_id": self.step_id,
            "trace_id": self.trace_id,
            "input_digest": self.input_digest,
            "requested_capabilities": _to_list(self.requested_capabilities),
            "expected_postconditions": _to_list(self.expected_postconditions),
            "delegation_depth": self.delegation_depth,
            "deadline_at": self.deadline_at,
            "requested_at": self.requested_at,
            "idempotency_key": self.idempotency_key,
        }

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())


@dataclass(frozen=True)
class HandoffGrant:
    schema_version: str
    handoff_id: str
    task_id: str
    thread_id: str
    run_id: str
    actor_id: str
    workspace_id: str
    policy_revision: str
    source_agent_id: str
    target_agent_id: str
    step_id: str
    trace_id: str
    input_digest: str
    capabilities: tuple[str, ...]
    expected_postconditions: tuple[str, ...]
    delegation_depth: int
    expires_at: int
    idempotency_key: str

    _fields: ClassVar[set[str]] = {
        "schema_version", "handoff_id", "task_id", "thread_id", "run_id", "actor_id",
        "workspace_id", "policy_revision", "source_agent_id", "target_agent_id", "step_id",
        "trace_id", "input_digest", "capabilities", "expected_postconditions", "delegation_depth",
        "expires_at", "idempotency_key",
    }

    @classmethod
    def from_dict(cls, value: Any) -> "HandoffGrant":
        data = _object(value, "handoff grant")
        _exact(data, cls._fields, "handoff grant")
        if data["schema_version"] != GRANT_SCHEMA_VERSION:
            raise ValueError("handoff grant schema_version is invalid")
        return cls(
            schema_version=GRANT_SCHEMA_VERSION,
            handoff_id=_id(data["handoff_id"], "handoff_id"),
            task_id=_id(data["task_id"], "task_id"),
            thread_id=_id(data["thread_id"], "thread_id"),
            run_id=_id(data["run_id"], "run_id"),
            actor_id=_id(data["actor_id"], "actor_id"),
            workspace_id=_id(data["workspace_id"], "workspace_id"),
            policy_revision=_id(data["policy_revision"], "policy_revision"),
            source_agent_id=_id(data["source_agent_id"], "source_agent_id"),
            target_agent_id=_id(data["target_agent_id"], "target_agent_id"),
            step_id=_id(data["step_id"], "step_id"),
            trace_id=_id(data["trace_id"], "trace_id"),
            input_digest=_digest(data["input_digest"], "input_digest"),
            capabilities=_capabilities(data["capabilities"]),
            expected_postconditions=_postconditions(data["expected_postconditions"]),
            delegation_depth=_positive(data["delegation_depth"], "delegation_depth"),
            expires_at=_positive(data["expires_at"], "expires_at"),
            idempotency_key=_id(data["idempotency_key"], "idempotency_key"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "handoff_id": self.handoff_id,
            "task_id": self.task_id,
            "thread_id": self.thread_id,
            "run_id": self.run_id,
            "actor_id": self.actor_id,
            "workspace_id": self.workspace_id,
            "policy_revision": self.policy_revision,
            "source_agent_id": self.source_agent_id,
            "target_agent_id": self.target_agent_id,
            "step_id": self.step_id,
            "trace_id": self.trace_id,
            "input_digest": self.input_digest,
            "capabilities": _to_list(self.capabilities),
            "expected_postconditions": _to_list(self.expected_postconditions),
            "delegation_depth": self.delegation_depth,
            "expires_at": self.expires_at,
            "idempotency_key": self.idempotency_key,
        }

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())


def assert_attestation_identity(attestation: AgentAttestation, request: HandoffRequest) -> None:
    if not isinstance(attestation, AgentAttestation) or not isinstance(request, HandoffRequest):
        raise ValueError("attestation and request types are invalid")
    for field in (
        "task_id", "thread_id", "run_id", "actor_id", "workspace_id", "policy_revision",
        "agent_id", "step_id", "trace_id", "input_digest",
    ):
        request_field = "source_agent_id" if field == "agent_id" else field
        if getattr(attestation, field) != getattr(request, request_field):
            raise ValueError(f"attestation {field} does not match handoff request")
    if not set(request.requested_capabilities).issubset(set(attestation.capabilities)):
        raise ValueError("handoff capabilities exceed source attestation")
    if request.delegation_depth != attestation.delegation_depth + 1:
        raise ValueError("handoff delegation depth is not exactly one level deeper")
    if request.deadline_at > attestation.expires_at:
        raise ValueError("handoff deadline exceeds attestation expiry")


def assert_grant_identity(request: HandoffRequest, grant: HandoffGrant) -> None:
    if not isinstance(request, HandoffRequest) or not isinstance(grant, HandoffGrant):
        raise ValueError("request and grant types are invalid")
    for field in (
        "handoff_id", "task_id", "thread_id", "run_id", "actor_id", "workspace_id",
        "policy_revision", "source_agent_id", "target_agent_id", "step_id", "trace_id", "input_digest",
        "idempotency_key",
    ):
        if getattr(request, field) != getattr(grant, field):
            raise ValueError(f"grant {field} does not match handoff request")
    if tuple(request.requested_capabilities) != tuple(grant.capabilities):
        raise ValueError("grant capabilities must exactly equal requested capabilities")
    if tuple(request.expected_postconditions) != tuple(grant.expected_postconditions):
        raise ValueError("grant postconditions must exactly equal requested postconditions")
    if request.delegation_depth != grant.delegation_depth:
        raise ValueError("grant delegation depth does not match request")
    if grant.expires_at > request.deadline_at:
        raise ValueError("grant expiry exceeds request deadline")
