"""Bounded local process adapter for CLI-style Agent backends.

This module is intentionally narrower than a vendor integration. It runs a
version-pinned command without a shell, in a host-resolved private workspace,
with an explicit environment allowlist and a bounded stdin/stdout protocol.
The process is still untrusted: a signed Handoff Grant and current policy are
verified before launch, and the process result is only a typed intermediate
receipt for independent postcondition verification.
"""
from __future__ import annotations

import hashlib
import json
import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from handoff import verify_handoff_grant
from interop_adapter import AdapterExecution, AdapterReceipt
from interop_contract import HandoffGrant

_MAX_COMMAND_ARGS = 32
_MAX_COMMAND_ARG_CHARS = 4_096
_MAX_CONTEXT_BYTES = 256_000
_SHELL_EXECUTABLES = {"sh", "bash", "dash", "zsh", "fish", "cmd", "powershell", "pwsh"}
_FIXED_ENV = {"NORTHSTAR_CONTEXT_REF", "NORTHSTAR_RUN_ID", "NORTHSTAR_WORKSPACE_ID"}
_EXECUTION_FIELDS = {"status", "output_digest", "artifact_refs", "verifier_verdict"}


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256 or any(char.isspace() or char in "/\\\x00" for char in value):
        raise ValueError(f"{field} is invalid")
    return value


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("value is not canonical JSON") from error


def _private_workspace(value: Any) -> Path:
    if not isinstance(value, (str, Path)):
        raise ValueError("workspace resolver returned an invalid path")
    path = Path(value).absolute()
    try:
        info = path.lstat()
    except OSError as error:
        raise ValueError("workspace is unavailable") from error
    if info.st_mode & 0o170000 == 0o120000 or not path.is_dir():
        raise ValueError("workspace must be a regular directory")
    if info.st_mode & 0o777 != 0o700:
        raise ValueError("workspace must have mode 0700")
    return path


def _validate_environment_allowlist(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)):
        raise ValueError("allowed_env must be a sequence")
    result: list[str] = []
    seen: set[str] = set()
    for key in value:
        if not isinstance(key, str) or not key or len(key) > 128 or not key.replace("_", "A").isalnum() or key[0].isdigit():
            raise ValueError("allowed_env contains an invalid name")
        upper = key.upper()
        if key in _FIXED_ENV or any(marker in upper for marker in ("SECRET", "TOKEN", "PASSWORD", "API_KEY", "AUTH")):
            raise ValueError("allowed_env contains a protected name")
        if key in seen:
            raise ValueError("allowed_env contains a duplicate")
        seen.add(key)
        result.append(key)
    return tuple(result)


def _validate_command(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or not value or len(value) > _MAX_COMMAND_ARGS:
        raise ValueError("command must be a bounded non-empty sequence")
    command: list[str] = []
    for argument in value:
        if not isinstance(argument, str) or not argument or len(argument) > _MAX_COMMAND_ARG_CHARS or "\x00" in argument:
            raise ValueError("command contains an invalid argument")
        command.append(argument)
    executable = Path(command[0]).name.lower()
    if executable in _SHELL_EXECUTABLES:
        raise ValueError("shell interpreters are not permitted")
    if any(argument.lower() in {"-c", "/c", "-command", "-encodedcommand"} for argument in command[1:]):
        raise ValueError("shell command arguments are not permitted")
    return tuple(command)


def _parse_execution(output: bytes) -> AdapterExecution:
    if not output.strip():
        raise ValueError("backend output is empty")
    try:
        value = json.loads(output.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("backend output is not one JSON object") from error
    if not isinstance(value, dict) or set(value) != _EXECUTION_FIELDS:
        raise ValueError("backend output has unknown or missing fields")
    refs = value["artifact_refs"]
    if not isinstance(refs, list):
        raise ValueError("backend artifact_refs must be a list")
    if not all(isinstance(ref, str) and ref for ref in refs):
        raise ValueError("backend artifact_refs contains an invalid reference")
    try:
        return AdapterExecution(
            status=value["status"],
            output_digest=value["output_digest"],
            artifact_refs=tuple(refs),
            verifier_verdict=value["verifier_verdict"],
        )
    except (TypeError, ValueError) as error:
        raise ValueError("backend execution result is invalid") from error


@dataclass(frozen=True)
class _ProcessResult:
    returncode: int
    output: bytes
    error_class: str | None = None


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=0.25)
    except (OSError, subprocess.TimeoutExpired):
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass


def _run_bounded_process(
    command: tuple[str, ...],
    *,
    cwd: Path,
    input_bytes: bytes,
    env: dict[str, str],
    timeout_seconds: float,
    max_output_bytes: int,
) -> _ProcessResult:
    try:
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            start_new_session=True,
        )
    except (OSError, ValueError):
        return _ProcessResult(-1, b"", "process_start")

    assert process.stdin is not None and process.stdout is not None
    selector = selectors.DefaultSelector()
    output = bytearray()
    input_offset = 0
    stdin_fd = process.stdin.fileno()
    stdout_fd = process.stdout.fileno()
    os.set_blocking(stdin_fd, False)
    os.set_blocking(stdout_fd, False)
    selector.register(stdin_fd, selectors.EVENT_WRITE, "stdin")
    selector.register(stdout_fd, selectors.EVENT_READ, "stdout")
    deadline = time.monotonic() + timeout_seconds
    failure: str | None = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "timeout"
                _terminate(process)
                break
            events = selector.select(remaining)
            if not events:
                failure = "timeout"
                _terminate(process)
                break
            for key, mask in events:
                if key.data == "stdin" and mask & selectors.EVENT_WRITE:
                    if input_offset >= len(input_bytes):
                        selector.unregister(stdin_fd)
                        process.stdin.close()
                    else:
                        try:
                            written = os.write(stdin_fd, input_bytes[input_offset:])
                            input_offset += written
                        except (BlockingIOError, BrokenPipeError):
                            selector.unregister(stdin_fd)
                            process.stdin.close()
                elif key.data == "stdout" and mask & selectors.EVENT_READ:
                    try:
                        chunk = os.read(stdout_fd, 65_536)
                    except BlockingIOError:
                        chunk = b""
                    if not chunk:
                        selector.unregister(stdout_fd)
                        process.stdout.close()
                    else:
                        output.extend(chunk)
                        if len(output) > max_output_bytes:
                            failure = "output_limit"
                            _terminate(process)
                            break
            if failure is not None:
                break
            if process.poll() is not None and not selector.get_map():
                break
        if failure is not None:
            return _ProcessResult(process.returncode if process.returncode is not None else -1, bytes(output[:max_output_bytes]), failure)
        try:
            returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            _terminate(process)
            return _ProcessResult(-1, bytes(output[:max_output_bytes]), "timeout")
        return _ProcessResult(returncode, bytes(output), None)
    finally:
        selector.close()
        try:
            process.stdin.close()
        except OSError:
            pass
        try:
            process.stdout.close()
        except OSError:
            pass
        if process.poll() is None:
            _terminate(process)


class ProcessAgentAdapter:
    """Run a CLI-style backend behind the Northstar handoff contract."""

    def __init__(
        self,
        *,
        agent_id: str,
        provider: str,
        version: str,
        command: tuple[str, ...] | list[str],
        workspace_resolver: Callable[[str], str | Path],
        context_loader: Callable[[str], str],
        allowed_env: tuple[str, ...] | list[str],
        supported_capabilities: tuple[str, ...] | list[str],
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> None:
        self.agent_id = _id(agent_id, "agent_id")
        self.provider = _id(provider, "provider")
        self.version = _id(version, "version")
        self.command = _validate_command(command)
        if not callable(workspace_resolver) or not callable(context_loader):
            raise ValueError("resolvers must be callable")
        if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) or not 0 < timeout_seconds <= 900:
            raise ValueError("timeout_seconds must be between 0 and 900")
        if not isinstance(max_output_bytes, int) or isinstance(max_output_bytes, bool) or not 1 <= max_output_bytes <= 16 * 1024 * 1024:
            raise ValueError("max_output_bytes is outside the permitted range")
        if not isinstance(supported_capabilities, (tuple, list)) or not supported_capabilities:
            raise ValueError("supported_capabilities must be non-empty")
        normalized_capabilities = tuple(sorted(set(supported_capabilities)))
        if any(
            not isinstance(capability, str)
            or not capability
            or ":" not in capability
            or any(part == "*" for part in capability.split(":"))
            for capability in normalized_capabilities
        ):
            raise ValueError("supported_capabilities contains an invalid capability")
        if len(normalized_capabilities) != len(supported_capabilities):
            raise ValueError("supported_capabilities contains a duplicate")
        self._workspace_resolver = workspace_resolver
        self._context_loader = context_loader
        self._supported_capabilities = frozenset(normalized_capabilities)
        self._allowed_env = _validate_environment_allowlist(allowed_env)
        self._timeout_seconds = float(timeout_seconds)
        self._max_output_bytes = max_output_bytes
        self._results: dict[str, tuple[str, AdapterReceipt]] = {}

    def _receipt(
        self,
        grant: HandoffGrant,
        *,
        status: str,
        output_digest: str,
        artifact_refs: tuple[str, ...] = (),
        verifier_verdict: str = "unknown",
        error_class: str | None = None,
    ) -> AdapterReceipt:
        value = {
            "schema_version": "northstar.adapter-receipt.v1",
            "handoff_id": grant.handoff_id,
            "task_id": grant.task_id,
            "thread_id": grant.thread_id,
            "run_id": grant.run_id,
            "step_id": grant.step_id,
            "target_agent_id": grant.target_agent_id,
            "trace_id": grant.trace_id,
            "status": status,
            "output_digest": output_digest,
            "artifact_refs": list(artifact_refs),
            "verifier_verdict": verifier_verdict,
            "error_class": error_class,
            "idempotency_key": grant.idempotency_key,
        }
        return AdapterReceipt.from_dict(value)

    def execute(
        self,
        handoff_token: str,
        *,
        context_ref: str,
        handoff_secret: bytes,
        current_policy_revision: str,
        now: int,
    ) -> AdapterReceipt:
        if not isinstance(context_ref, str) or not context_ref or len(context_ref) > 256:
            raise ValueError("context_ref is invalid")
        if not isinstance(current_policy_revision, str) or not current_policy_revision:
            raise ValueError("current_policy_revision is required")
        validation = verify_handoff_grant(handoff_token, handoff_secret, now=now)
        if not validation.ok or validation.grant is None:
            raise ValueError("handoff grant is not valid")
        grant = validation.grant
        if grant.target_agent_id != self.agent_id:
            raise ValueError("handoff target does not match adapter")
        if grant.policy_revision != current_policy_revision:
            raise ValueError("handoff policy revision is stale")
        if not set(grant.capabilities).issubset(self._supported_capabilities):
            raise ValueError("handoff capability is not supported by adapter")
        try:
            workspace = _private_workspace(self._workspace_resolver(grant.workspace_id))
            context = self._context_loader(context_ref)
        except Exception as error:
            raise ValueError("process adapter context is unavailable") from error
        if not isinstance(context, str) or not context:
            raise ValueError("process adapter context is invalid")
        input_bytes = context.encode("utf-8")
        if len(input_bytes) > _MAX_CONTEXT_BYTES:
            raise ValueError("process adapter context exceeds the maximum size")
        fingerprint = hashlib.sha256(
            grant.canonical_json() + b"\0" + context_ref.encode("utf-8")
        ).hexdigest()
        cached = self._results.get(grant.idempotency_key)
        if cached is not None:
            old_fingerprint, receipt = cached
            if old_fingerprint != fingerprint:
                raise ValueError("handoff idempotency key conflicts")
            return receipt

        env = {
            key: os.environ[key]
            for key in self._allowed_env
            if key in os.environ
        }
        env.update(
            {
                "NORTHSTAR_CONTEXT_REF": context_ref,
                "NORTHSTAR_RUN_ID": grant.run_id,
                "NORTHSTAR_WORKSPACE_ID": grant.workspace_id,
            }
        )
        result = _run_bounded_process(
            self.command,
            cwd=workspace,
            input_bytes=input_bytes,
            env=env,
            timeout_seconds=self._timeout_seconds,
            max_output_bytes=self._max_output_bytes,
        )
        raw_digest = _digest_bytes(result.output)
        if result.error_class is not None:
            receipt = self._receipt(
                grant,
                status="failed",
                output_digest=raw_digest,
                error_class=result.error_class,
            )
            self._results[grant.idempotency_key] = (fingerprint, receipt)
            return receipt
        if result.returncode != 0:
            receipt = self._receipt(
                grant,
                status="failed",
                output_digest=raw_digest,
                error_class="process_exit",
            )
            self._results[grant.idempotency_key] = (fingerprint, receipt)
            return receipt
        try:
            execution = _parse_execution(result.output)
        except ValueError:
            receipt = self._receipt(
                grant,
                status="failed",
                output_digest=raw_digest,
                error_class="malformed_output",
            )
            self._results[grant.idempotency_key] = (fingerprint, receipt)
            return receipt
        status = execution.status
        if status == "finished" and execution.verifier_verdict != "verified":
            status = "unknown"
        receipt = self._receipt(
            grant,
            status=status,
            output_digest=execution.output_digest,
            artifact_refs=execution.artifact_refs,
            verifier_verdict=execution.verifier_verdict,
            error_class=None if status in {"finished", "unknown"} else "backend_execution",
        )
        self._results[grant.idempotency_key] = (fingerprint, receipt)
        return receipt
