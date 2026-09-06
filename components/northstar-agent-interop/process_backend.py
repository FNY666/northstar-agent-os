"""Versioned configuration for process-backed Agent adapters."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from interop_contract import AgentProfile
from process_adapter import ProcessAgentAdapter

_SCHEMA = "northstar.process-backend.v1"
_ALLOWED_FIELDS = {
    "schema_version", "agent_id", "provider", "version", "executable",
    "command_template", "capability_map", "allowed_env", "enabled",
}
_ALLOWED_TEMPLATE_TOKENS = {"{executable}"}
_SHELLS = {"sh", "bash", "dash", "zsh", "fish", "cmd", "powershell", "pwsh"}
_PROTECTED_MARKERS = ("SECRET", "TOKEN", "PASSWORD", "API_KEY", "AUTH", "COOKIE", "CREDENTIAL")


def _id(value: Any, field: str, *, max_chars: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > max_chars or any(c.isspace() or c in "/\\\x00" for c in value):
        raise ValueError(f"{field} is invalid")
    return value


def _absolute_executable(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise ValueError("executable must be an absolute path")
    path = Path(value)
    if not path.is_absolute() or path.name.lower() in _SHELLS:
        raise ValueError("executable is not permitted")
    return value


def _template(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > 32:
        raise ValueError("command_template must be a bounded non-empty list")
    result: list[str] = []
    for index, argument in enumerate(value):
        if not isinstance(argument, str) or not argument or len(argument) > 4096 or "\x00" in argument:
            raise ValueError(f"command_template[{index}] is invalid")
        if "{" in argument or "}" in argument:
            if argument not in _ALLOWED_TEMPLATE_TOKENS:
                raise ValueError("command_template contains an unapproved token")
        if argument in {"-c", "/c", "-command", "-encodedcommand"}:
            raise ValueError("command_template cannot invoke a shell")
        result.append(argument)
    if result.count("{executable}") != 1 or result[0] != "{executable}":
        raise ValueError("command_template must begin with exactly one executable token")
    return tuple(result)


def _capability_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or not value:
        raise ValueError("capability_map must be a non-empty object")
    result: dict[str, str] = {}
    for requested, backend in value.items():
        requested = _id(requested, "capability")
        backend = _id(backend, "backend capability")
        if ":" not in requested or ":" not in backend or requested != backend:
            raise ValueError("capability_map cannot widen or rename capabilities")
        result[requested] = backend
    return result


def _environment(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError("allowed_env must be a bounded list")
    result: list[str] = []
    for key in value:
        key = _id(key, "environment name")
        if not key.replace("_", "A").isalnum() or key[0].isdigit() or any(marker in key.upper() for marker in _PROTECTED_MARKERS):
            raise ValueError("allowed_env contains a protected or invalid name")
        if key in result:
            raise ValueError("allowed_env contains a duplicate")
        result.append(key)
    return tuple(result)


@dataclass(frozen=True)
class ProcessBackendSpec:
    schema_version: str
    agent_id: str
    provider: str
    version: str
    executable: str
    command_template: tuple[str, ...]
    capability_map: dict[str, str]
    allowed_env: tuple[str, ...]
    enabled: bool

    @classmethod
    def from_dict(cls, value: Any) -> "ProcessBackendSpec":
        if not isinstance(value, dict):
            raise ValueError("process backend spec must be an object")
        missing = sorted(_ALLOWED_FIELDS - set(value))
        unknown = sorted(set(value) - _ALLOWED_FIELDS)
        if missing:
            raise ValueError(f"process backend spec missing fields: {', '.join(missing)}")
        if unknown:
            raise ValueError(f"process backend spec has unknown fields: {', '.join(unknown)}")
        if value["schema_version"] != _SCHEMA:
            raise ValueError("process backend schema_version is invalid")
        if not isinstance(value["enabled"], bool):
            raise ValueError("enabled must be boolean")
        return cls(
            schema_version=_SCHEMA,
            agent_id=_id(value["agent_id"], "agent_id"),
            provider=_id(value["provider"], "provider"),
            version=_id(value["version"], "version", max_chars=64),
            executable=_absolute_executable(value["executable"]),
            command_template=_template(value["command_template"]),
            capability_map=_capability_map(value["capability_map"]),
            allowed_env=_environment(value["allowed_env"]),
            enabled=value["enabled"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "agent_id": self.agent_id,
            "provider": self.provider,
            "version": self.version,
            "executable": self.executable,
            "command_template": list(self.command_template),
            "capability_map": dict(self.capability_map),
            "allowed_env": list(self.allowed_env),
            "enabled": self.enabled,
        }

    def command(self) -> tuple[str, ...]:
        return tuple(self.executable if token == "{executable}" else token for token in self.command_template)


def codex_cli_spec(executable: str) -> ProcessBackendSpec:
    return ProcessBackendSpec.from_dict({
        "schema_version": _SCHEMA,
        "agent_id": "codex",
        "provider": "openai",
        "version": "unconfigured",
        "executable": executable,
        "command_template": ["{executable}", "exec", "--json"],
        "capability_map": {"workspace:read": "workspace:read"},
        "allowed_env": [],
        "enabled": False,
    })


def claude_code_cli_spec(executable: str) -> ProcessBackendSpec:
    return ProcessBackendSpec.from_dict({
        "schema_version": _SCHEMA,
        "agent_id": "claude-code",
        "provider": "anthropic",
        "version": "unconfigured",
        "executable": executable,
        "command_template": ["{executable}", "-p", "--output-format", "json"],
        "capability_map": {"workspace:read": "workspace:read"},
        "allowed_env": [],
        "enabled": False,
    })


def cursor_cli_spec(executable: str) -> ProcessBackendSpec:
    return ProcessBackendSpec.from_dict({
        "schema_version": _SCHEMA,
        "agent_id": "cursor",
        "provider": "cursor",
        "version": "unconfigured",
        "executable": executable,
        "command_template": ["{executable}", "-p", "--output-format", "text"],
        "capability_map": {"workspace:read": "workspace:read"},
        "allowed_env": [],
        "enabled": False,
    })


def build_process_adapter(
    spec: ProcessBackendSpec,
    *,
    workspace_resolver: Callable[[str], str | Path],
    context_loader: Callable[[str], str],
    timeout_seconds: float = 60,
    max_output_bytes: int = 1_000_000,
) -> ProcessAgentAdapter:
    if not isinstance(spec, ProcessBackendSpec):
        raise ValueError("process backend spec is invalid")
    if not spec.enabled:
        raise ValueError("process backend is disabled")
    return ProcessAgentAdapter(
        agent_id=spec.agent_id,
        provider=spec.provider,
        version=spec.version,
        command=spec.command(),
        workspace_resolver=workspace_resolver,
        context_loader=context_loader,
        allowed_env=spec.allowed_env,
        supported_capabilities=tuple(spec.capability_map),
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
