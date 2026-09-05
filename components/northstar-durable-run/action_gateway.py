"""Per-call authorization and approval gateway for the durable-run slice.

The gateway treats model-produced ToolCall data and tool output as untrusted.
It validates the call, re-verifies a host authorization grant, enforces the
registered tool's exact capability/scope/resource contract, and only then
invokes a host-registered executor supplied by the caller.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from authorization import verify_authorization
from contract import _valid_id, validate_run_request

TOOL_CALL_SCHEMA_VERSION = "northstar.tool-call.v1"
APPROVAL_SCHEMA_VERSION = "northstar.approval.v1"
_ID_RE = re.compile(r"^[^\s/\\]+$")
_SCOPE_RE = re.compile(r"^[^\s/\\:]+:[^\s/\\:]+$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_SCOPE_ENTRIES = 64
_MAX_ARGUMENT_BYTES = 256_000

_TOOL_CALL_FIELDS = {
    "schema_version",
    "task_id",
    "thread_id",
    "run_id",
    "step_id",
    "actor_id",
    "workspace_id",
    "trace_id",
    "tool_name",
    "resource_id",
    "requested_scope",
    "arguments_digest",
    "idempotency_key",
    "deadline_at",
}
_APPROVAL_FIELDS = {
    "schema_version",
    "approval_id",
    "approver_id",
    "task_id",
    "thread_id",
    "run_id",
    "step_id",
    "actor_id",
    "tool_name",
    "resource_id",
    "decision",
    "expires_at",
}


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("value is not canonical JSON") from error


def _require_id(value: Any, field: str) -> str:
    errors = _valid_id(value, field)
    if errors:
        raise ValueError(errors[0])
    return value


def _require_positive_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    if value <= 0:
        raise ValueError(f"{field} must be positive")
    return value


def _require_secret(secret: bytes) -> None:
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("approval_secret must be non-empty bytes")


def _require_scope(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("requested_scope must be a list")
    if len(value) > _MAX_SCOPE_ENTRIES:
        raise ValueError("requested_scope has too many entries")
    result: list[str] = []
    seen: set[str] = set()
    for index, scope in enumerate(value):
        if not isinstance(scope, str) or not _SCOPE_RE.fullmatch(scope):
            raise ValueError(f"requested_scope[{index}] is invalid")
        if scope in seen:
            raise ValueError(f"duplicate requested scope: {scope}")
        seen.add(scope)
        result.append(scope)
    return tuple(result)


def _decode(value: Any) -> bytes:
    if not isinstance(value, str) or not value or not all(
        char.isalnum() or char in "-_" for char in value
    ):
        raise ValueError("invalid approval token segment")
    if len(value) % 4 == 1:
        raise ValueError("invalid approval token padding")
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as error:
        raise ValueError("invalid approval token segment") from error


def _validate_approval(value: Any) -> tuple[str, ...]:
    if not isinstance(value, dict):
        return ("approval must be an object",)
    errors: list[str] = []
    unknown = sorted(set(value) - _APPROVAL_FIELDS)
    missing = sorted(_APPROVAL_FIELDS - set(value))
    if unknown:
        errors.append(f"unknown approval fields: {', '.join(unknown)}")
    if missing:
        errors.append(f"missing approval fields: {', '.join(missing)}")
    if value.get("schema_version") != APPROVAL_SCHEMA_VERSION:
        errors.append(f"schema_version must be {APPROVAL_SCHEMA_VERSION}")
    for field in (
        "approval_id",
        "approver_id",
        "task_id",
        "thread_id",
        "run_id",
        "step_id",
        "actor_id",
        "tool_name",
        "resource_id",
    ):
        errors.extend(_valid_id(value.get(field), field))
    if value.get("decision") not in {"approved", "denied"}:
        errors.append("decision must be approved or denied")
    expiry = value.get("expires_at")
    if not isinstance(expiry, int) or isinstance(expiry, bool) or expiry <= 0:
        errors.append("expires_at must be a positive integer")
    return tuple(errors)


def sign_approval(approval: dict[str, Any], secret: bytes) -> str:
    _require_secret(secret)
    errors = _validate_approval(approval)
    if errors:
        raise ValueError(errors[0])
    payload = base64.urlsafe_b64encode(_canonical_json(approval)).decode("ascii").rstrip("=")
    signature = base64.urlsafe_b64encode(
        hmac.new(secret, payload.encode("ascii"), hashlib.sha256).digest()
    ).decode("ascii").rstrip("=")
    return f"{payload}.{signature}"


def _verify_approval(token: str, secret: bytes, *, now: int) -> dict[str, Any]:
    _require_secret(secret)
    if not isinstance(now, int) or isinstance(now, bool):
        raise ValueError("now must be an integer")
    if not isinstance(token, str) or token.count(".") != 1:
        raise ValueError("approval token format is invalid")
    payload_segment, signature_segment = token.split(".")
    payload = _decode(payload_segment)
    supplied = _decode(signature_segment)
    expected = hmac.new(
        secret, payload_segment.encode("ascii"), hashlib.sha256
    ).digest()
    if len(supplied) != hashlib.sha256().digest_size or not hmac.compare_digest(
        supplied, expected
    ):
        raise ValueError("approval signature is invalid")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("approval payload is invalid") from error
    errors = _validate_approval(value)
    if errors:
        raise ValueError(errors[0])
    if now >= value["expires_at"]:
        raise ValueError("approval is expired")
    if value["decision"] != "approved":
        raise ValueError("approval was denied")
    return value


def digest_arguments(arguments: Any) -> str:
    encoded = _canonical_json(arguments)
    if len(encoded) > _MAX_ARGUMENT_BYTES:
        raise ValueError("tool arguments exceed the maximum size")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ToolCall:
    schema_version: str
    task_id: str
    thread_id: str
    run_id: str
    step_id: str
    actor_id: str
    workspace_id: str
    trace_id: str
    tool_name: str
    resource_id: str
    requested_scope: tuple[str, ...]
    arguments_digest: str
    idempotency_key: str
    deadline_at: int

    @classmethod
    def from_dict(cls, value: Any) -> "ToolCall":
        if not isinstance(value, dict):
            raise ValueError("tool call must be an object")
        missing = sorted(_TOOL_CALL_FIELDS - set(value))
        unknown = sorted(set(value) - _TOOL_CALL_FIELDS)
        if missing:
            raise ValueError(f"tool call missing fields: {', '.join(missing)}")
        if unknown:
            raise ValueError(f"tool call has unknown fields: {', '.join(unknown)}")
        if value["schema_version"] != TOOL_CALL_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {TOOL_CALL_SCHEMA_VERSION}")
        return cls(
            schema_version=TOOL_CALL_SCHEMA_VERSION,
            task_id=_require_id(value["task_id"], "task_id"),
            thread_id=_require_id(value["thread_id"], "thread_id"),
            run_id=_require_id(value["run_id"], "run_id"),
            step_id=_require_id(value["step_id"], "step_id"),
            actor_id=_require_id(value["actor_id"], "actor_id"),
            workspace_id=_require_id(value["workspace_id"], "workspace_id"),
            trace_id=_require_id(value["trace_id"], "trace_id"),
            tool_name=_require_id(value["tool_name"], "tool_name"),
            resource_id=_require_id(value["resource_id"], "resource_id"),
            requested_scope=_require_scope(value["requested_scope"]),
            arguments_digest=_require_digest(value["arguments_digest"]),
            idempotency_key=_require_id(value["idempotency_key"], "idempotency_key"),
            deadline_at=_require_positive_int(value["deadline_at"], "deadline_at"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "thread_id": self.thread_id,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "actor_id": self.actor_id,
            "workspace_id": self.workspace_id,
            "trace_id": self.trace_id,
            "tool_name": self.tool_name,
            "resource_id": self.resource_id,
            "requested_scope": list(self.requested_scope),
            "arguments_digest": self.arguments_digest,
            "idempotency_key": self.idempotency_key,
            "deadline_at": self.deadline_at,
        }

    def canonical_json(self) -> bytes:
        return _canonical_json(self.to_dict())


def _require_digest(value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError("arguments_digest must be a lowercase sha256 digest")
    return value


@dataclass(frozen=True)
class ToolSpec:
    name: str
    required_capability: str
    required_scope: str
    resource_kind: str
    risk_level: str
    executor: Callable[[dict[str, Any]], dict[str, Any]]

    def __post_init__(self) -> None:
        _require_id(self.name, "tool name")
        _require_id(self.required_capability, "required capability")
        if not _SCOPE_RE.fullmatch(self.required_scope):
            raise ValueError("required_scope is invalid")
        _require_id(self.resource_kind, "resource kind")
        if self.risk_level not in {"low", "high"}:
            raise ValueError("risk_level must be low or high")
        if not callable(self.executor):
            raise ValueError("executor must be callable")


@dataclass(frozen=True)
class ToolExecutionResult:
    status: str
    output: dict[str, Any]
    idempotency_key: str


class ActionGateway:
    """Authorize and dispatch one exact registered tool call at a time."""

    def __init__(self, *, approval_secret: bytes):
        _require_secret(approval_secret)
        self._approval_secret = approval_secret
        self._tools: dict[str, ToolSpec] = {}
        self._results: dict[str, tuple[str, ToolExecutionResult]] = {}

    def register(self, spec: ToolSpec) -> None:
        if not isinstance(spec, ToolSpec):
            raise ValueError("tool spec is invalid")
        if spec.name in self._tools:
            raise ValueError("tool is already registered")
        self._tools[spec.name] = spec

    def execute(
        self,
        call: ToolCall,
        arguments: dict[str, Any],
        *,
        authorization_token: str,
        authorization_secret: bytes,
        now: int,
        approval_token: str | None = None,
        current_policy_revision: str,
        run: dict[str, Any] | None = None,
    ) -> ToolExecutionResult:
        if not isinstance(call, ToolCall):
            raise ValueError("tool call is invalid")
        if not isinstance(arguments, dict):
            raise ValueError("tool arguments must be an object")
        if not isinstance(now, int) or isinstance(now, bool):
            raise ValueError("now must be an integer")
        _require_id(current_policy_revision, "current_policy_revision")
        if now >= call.deadline_at:
            raise ValueError("tool call deadline has expired")
        if run is not None:
            validation = validate_run_request(run)
            if not validation.ok:
                raise ValueError(validation.errors[0])
            for field in ("run_id", "actor_id", "workspace_id"):
                if run[field] != getattr(call, field):
                    raise ValueError(f"run does not match tool call {field}")

        authorization = verify_authorization(
            authorization_token, authorization_secret, now=now
        )
        if not authorization.ok or authorization.authorization is None:
            raise ValueError("authorization grant is not valid")
        grant = authorization.authorization
        if grant.get("policy_revision") != current_policy_revision:
            raise ValueError("authorization policy revision is stale")
        for field in ("run_id", "actor_id", "workspace_id"):
            if grant[field] != getattr(call, field):
                raise ValueError(f"authorization does not match tool call {field}")
        if call.resource_id != call.workspace_id or grant["workspace_id"] != call.resource_id:
            raise ValueError("tool resource is not the authorized workspace")

        argument_digest = digest_arguments(arguments)
        if argument_digest != call.arguments_digest:
            raise ValueError("tool arguments digest does not match call")
        spec = self._tools.get(call.tool_name)
        if spec is None:
            raise ValueError("tool is not registered")
        if spec.required_capability not in grant["capabilities"]:
            raise ValueError("tool capability is not authorized")
        requested_scope = set(call.requested_scope)
        if spec.required_scope not in requested_scope:
            raise ValueError("tool scope does not include the required scope")
        if not requested_scope.issubset(set(grant["capabilities"])):
            raise ValueError("tool scope exceeds the authorization grant")
        if spec.risk_level == "high":
            if approval_token is None:
                raise ValueError("high-risk tool requires approval")
            approval = _verify_approval(
                approval_token, self._approval_secret, now=now
            )
            for field in (
                "task_id",
                "thread_id",
                "run_id",
                "step_id",
                "actor_id",
                "tool_name",
                "resource_id",
            ):
                if approval[field] != getattr(call, field):
                    raise ValueError(f"approval does not match tool call {field}")

        fingerprint = hashlib.sha256(
            call.canonical_json() + b"\0" + argument_digest.encode("ascii")
        ).hexdigest()
        cached = self._results.get(call.idempotency_key)
        if cached is not None:
            old_fingerprint, result = cached
            if old_fingerprint != fingerprint:
                raise ValueError("idempotency key conflicts with another tool call")
            return result

        try:
            output = spec.executor(arguments)
        except Exception as error:
            raise ValueError("tool execution failed") from error
        if not isinstance(output, dict):
            raise ValueError("tool executor must return an object")
        result = ToolExecutionResult(
            status="ok",
            output=output,
            idempotency_key=call.idempotency_key,
        )
        self._results[call.idempotency_key] = (fingerprint, result)
        return result
