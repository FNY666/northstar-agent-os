"""Small, dependency-free prototype for a deterministic AgentOS kernel.

This module deliberately separates two concerns:

* :class:`SandboxPolicy` validates a fail-closed launch policy and produces a
  *plan*. It does not claim that a kernel boundary is active. A trusted host
  must execute the plan through bwrap/OCI/microVM and apply cgroup/seccomp.
* :class:`DeterministicKernel` persists a hash-linked event stream and replays
  it without wall-clock time, randomness, or model input. A completed step is
  returned from the ledger; an in-flight step refuses automatic re-execution
  until an effect receiver reconciles its idempotency key.

The prototype is intentionally single-process and standard-library only. It
is not a container runtime, a cgroup manager, a secret store, or proof of
cross-host exactly-once effects.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

SCHEMA = "northstar.deterministic-kernel.v1"
EVENT_SCHEMA = "northstar.kernel-event.v1"
_ALLOWED_NETWORK = {"none"}
_ALLOWED_SECCOMP = {"required", "auto"}
_MAX_ARG_BYTES = 64 * 1024
_MAX_EVENT_BYTES = 256 * 1024


class KernelError(ValueError):
    """Base class for fail-closed policy, log, and state errors."""


class PolicyError(KernelError):
    pass


class EventIntegrityError(KernelError):
    pass


class RecoveryRequired(KernelError):
    """An effect began but has no durable completion record."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise KernelError("value is not canonical JSON") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _safe_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value:
        raise PolicyError(f"{field} must be a non-empty single-line string")
    return value


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class SandboxPolicy:
    """Host-verifiable launch constraints; defaults are intentionally narrow."""

    workspace: Path
    readonly: bool = True
    network: str = "none"
    seccomp: str = "required"
    rootless: bool = True
    memory_max_bytes: int = 512 * 1024 * 1024
    pids_max: int = 256
    cpu_max_percent: int = 100
    timeout_seconds: int = 60

    def __post_init__(self) -> None:
        workspace = Path(self.workspace)
        if not workspace.is_absolute() or workspace.is_symlink() or not workspace.is_dir():
            raise PolicyError("workspace must be an existing absolute non-symlink directory")
        try:
            resolved_workspace = workspace.resolve(strict=True)
        except OSError as exc:
            raise PolicyError("workspace could not be resolved") from exc
        if not resolved_workspace.is_dir():
            raise PolicyError("resolved workspace must be a directory")
        if self.readonly is not True:
            raise PolicyError("prototype only permits readonly workspace mounts")
        if self.network not in _ALLOWED_NETWORK:
            raise PolicyError("prototype only permits network=none")
        if self.seccomp not in _ALLOWED_SECCOMP:
            raise PolicyError("seccomp must be required or auto")
        if self.rootless is not True:
            raise PolicyError("prototype requires rootless=true")
        for name, value, low, high in (
            ("memory_max_bytes", self.memory_max_bytes, 1, 64 * 1024**3),
            ("pids_max", self.pids_max, 1, 32768),
            ("cpu_max_percent", self.cpu_max_percent, 1, 10000),
            ("timeout_seconds", self.timeout_seconds, 1, 24 * 60 * 60),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise PolicyError(f"{name} must be an int in [{low}, {high}]")

    @property
    def workspace_path(self) -> Path:
        return Path(self.workspace).resolve(strict=True)

    def plan(self, argv: tuple[str, ...], *, cwd: Path | None = None,
             env_names: tuple[str, ...] = ()) -> "SandboxPlan":
        if not argv or any(not isinstance(item, str) or not item or "\x00" in item for item in argv):
            raise PolicyError("argv must be a non-empty tuple of safe strings")
        if len(_canonical(list(argv))) > _MAX_ARG_BYTES:
            raise PolicyError("argv exceeds bounded size")
        target_cwd = self.workspace_path if cwd is None else Path(cwd).resolve(strict=True)
        if not target_cwd.is_dir() or not _inside(target_cwd, self.workspace_path):
            raise PolicyError("cwd must be an existing directory inside workspace")
        if any(not re.fullmatch(r"[A-Z_][A-Z0-9_]*", name) for name in env_names):
            raise PolicyError("env_names must contain only uppercase environment names")
        # The plan is data, not an authorization to execute. A host adapter must
        # translate these fields into bwrap/OCI/microVM flags and verify them.
        data = {
            "schema": SCHEMA,
            "argv": list(argv),
            "cwd": str(target_cwd),
            "workspace": str(self.workspace_path),
            "readonly": self.readonly,
            "network": self.network,
            "seccomp": self.seccomp,
            "rootless": self.rootless,
            "memory_max_bytes": self.memory_max_bytes,
            "pids_max": self.pids_max,
            "cpu_max_percent": self.cpu_max_percent,
            "timeout_seconds": self.timeout_seconds,
            "env_names": list(env_names),
        }
        return SandboxPlan(data=data, digest=_digest(data))


@dataclass(frozen=True)
class SandboxPlan:
    data: dict[str, Any]
    digest: str

    def as_dict(self) -> dict[str, Any]:
        return {**self.data, "plan_digest": self.digest}


@dataclass(frozen=True)
class KernelState:
    run_id: str
    status: str
    sequence: int
    steps: dict[str, str]
    completed_results: dict[str, Any]


class DeterministicKernel:
    """A caller-clocked, hash-linked execution ledger with deterministic replay."""

    def __init__(self, event_path: str | Path):
        self.path = Path(event_path).absolute()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise EventIntegrityError("event history could not be read") from exc
        events: list[dict[str, Any]] = []
        previous = ""
        for line_number, line in enumerate(lines, 1):
            if not line or len(line.encode("utf-8")) > _MAX_EVENT_BYTES:
                raise EventIntegrityError(f"invalid event line {line_number}")
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise EventIntegrityError(f"invalid JSON at line {line_number}") from exc
            if not isinstance(event, dict) or event.get("schema") != EVENT_SCHEMA:
                raise EventIntegrityError(f"invalid event schema at line {line_number}")
            expected_sequence = len(events) + 1
            if event.get("sequence") != expected_sequence or event.get("previous_digest") != previous:
                raise EventIntegrityError(f"event chain discontinuity at line {line_number}")
            body = {k: v for k, v in event.items() if k != "digest"}
            if event.get("digest") != _digest(body):
                raise EventIntegrityError(f"event digest mismatch at line {line_number}")
            events.append(event)
            previous = event["digest"]
        return events

    def _append(self, run_id: str, kind: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        run_id = _safe_text(run_id, "run_id")
        kind = _safe_text(kind, "kind")
        body_payload = dict(payload)
        encoded_payload = _canonical(body_payload)
        if len(encoded_payload) > _MAX_EVENT_BYTES:
            raise KernelError("event payload exceeds bounded size")
        events = self._read()
        if events and events[0]["run_id"] != run_id:
            raise KernelError("event run_id does not match history")
        previous = events[-1]["digest"] if events else ""
        body = {
            "schema": EVENT_SCHEMA,
            "run_id": run_id,
            "sequence": len(events) + 1,
            "kind": kind,
            "payload": body_payload,
            "previous_digest": previous,
        }
        event = {**body, "digest": _digest(body)}
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(_canonical(event).decode("utf-8") + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        return event

    def state(self, run_id: str) -> KernelState:
        events = self._read()
        if not events or events[0]["run_id"] != run_id:
            raise KernelError("run has no matching event history")
        status = "running"
        steps: dict[str, str] = {}
        results: dict[str, Any] = {}
        for event in events:
            kind = event["kind"]
            payload = event["payload"]
            if kind == "run.created":
                if event["sequence"] != 1 or status != "running":
                    raise EventIntegrityError("invalid run.created placement")
            elif kind == "step.planned":
                step_id = _safe_text(payload.get("step_id"), "step_id")
                if step_id in steps:
                    raise EventIntegrityError("step planned twice")
                steps[step_id] = "planned"
            elif kind == "step.started":
                step_id = _safe_text(payload.get("step_id"), "step_id")
                if steps.get(step_id) != "planned":
                    raise EventIntegrityError("step started without plan")
                steps[step_id] = "started"
            elif kind == "step.completed":
                step_id = _safe_text(payload.get("step_id"), "step_id")
                if steps.get(step_id) != "started":
                    raise EventIntegrityError("step completed without start")
                steps[step_id] = "completed"
                results[step_id] = payload["result"]
            elif kind == "step.failed":
                step_id = _safe_text(payload.get("step_id"), "step_id")
                if steps.get(step_id) != "started":
                    raise EventIntegrityError("step failed without start")
                steps[step_id] = "failed"
            else:
                raise EventIntegrityError(f"unsupported event kind: {kind}")
        return KernelState(run_id, status, events[-1]["sequence"], steps, results)

    def start_run(self, run_id: str, input_digest: str) -> None:
        if self._read():
            raise KernelError("run already has history")
        self._append(run_id, "run.created", {"input_digest": _safe_text(input_digest, "input_digest")})

    def plan_step(self, run_id: str, step_id: str, action_key: str, plan_digest: str) -> None:
        current = self.state(run_id)
        if step_id in current.steps:
            raise KernelError("step already exists")
        self._append(run_id, "step.planned", {
            "step_id": _safe_text(step_id, "step_id"),
            "action_key": _safe_text(action_key, "action_key"),
            "plan_digest": _safe_text(plan_digest, "plan_digest"),
        })

    def run_step(self, run_id: str, step_id: str, action_key: str,
                 effect: Callable[[], Any]) -> Any:
        current = self.state(run_id)
        status = current.steps.get(step_id)
        if status == "completed":
            return current.completed_results[step_id]
        if status == "started":
            raise RecoveryRequired("step started without completion; reconcile effect key before retry")
        if status != "planned":
            raise KernelError("step must be planned before execution")
        self._append(run_id, "step.started", {
            "step_id": _safe_text(step_id, "step_id"),
            "action_key": _safe_text(action_key, "action_key"),
        })
        try:
            result = effect()
            _canonical(result)
        except Exception as exc:
            self._append(run_id, "step.failed", {
                "step_id": step_id, "action_key": action_key,
                "error_type": type(exc).__name__,
            })
            raise
        self._append(run_id, "step.completed", {
            "step_id": step_id, "action_key": action_key, "result": result,
            "result_digest": _digest(result),
        })
        return result

    def replay(self, run_id: str) -> KernelState:
        return self.state(run_id)


__all__ = [
    "DeterministicKernel", "EventIntegrityError", "KernelError", "KernelState",
    "PolicyError", "RecoveryRequired", "SandboxPlan", "SandboxPolicy", "SCHEMA",
]
