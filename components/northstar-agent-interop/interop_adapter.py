"""Backend-neutral adapter contract for future Agent engines."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from handoff import verify_handoff_grant
from interop_contract import HandoffGrant

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[^\s/\\]+$")


def _canonical(value: dict[str, Any]) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("value is not canonical JSON") from error


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128 or not _ID_RE.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _postconditions(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError("expected_postconditions must be a bounded list")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        normalized = _id(item, "expected_postcondition")
        if normalized in seen:
            raise ValueError("duplicate expected postcondition")
        seen.add(normalized)
        result.append(normalized)
    return tuple(result)


@dataclass(frozen=True)
class ContextEnvelope:
    schema_version: str
    context_ref: str
    input_digest: str
    expected_postconditions: tuple[str, ...]

    @classmethod
    def from_dict(cls, value: Any) -> "ContextEnvelope":
        if not isinstance(value, dict):
            raise ValueError("context envelope must be an object")
        expected = {"schema_version", "context_ref", "input_digest", "expected_postconditions"}
        if set(value) != expected:
            raise ValueError("context envelope has unknown or missing fields")
        if value["schema_version"] != "northstar.context-envelope.v1":
            raise ValueError("context envelope schema_version is invalid")
        return cls(
            schema_version=value["schema_version"],
            context_ref=_id(value["context_ref"], "context_ref"),
            input_digest=_digest(value["input_digest"], "input_digest"),
            expected_postconditions=_postconditions(value["expected_postconditions"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "context_ref": self.context_ref,
            "input_digest": self.input_digest,
            "expected_postconditions": list(self.expected_postconditions),
        }


@dataclass(frozen=True)
class AdapterExecution:
    status: str
    output_digest: str
    artifact_refs: tuple[str, ...]
    verifier_verdict: str

    def __post_init__(self) -> None:
        if self.status not in {"finished", "failed", "cancelled", "waiting"}:
            raise ValueError("adapter status is invalid")
        _digest(self.output_digest, "output_digest")
        if not isinstance(self.artifact_refs, tuple) or not all(isinstance(ref, str) and ref for ref in self.artifact_refs):
            raise ValueError("artifact_refs must be a tuple of non-empty strings")
        if self.verifier_verdict not in {"verified", "failed", "unknown"}:
            raise ValueError("verifier_verdict is invalid")
        if self.status == "finished" and self.verifier_verdict == "failed":
            raise ValueError("finished execution cannot have failed verification")

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "output_digest": self.output_digest,
            "artifact_refs": list(self.artifact_refs),
            "verifier_verdict": self.verifier_verdict,
        }


@dataclass(frozen=True)
class AdapterReceipt:
    schema_version: str
    handoff_id: str
    task_id: str
    thread_id: str
    run_id: str
    step_id: str
    target_agent_id: str
    trace_id: str
    status: str
    output_digest: str
    artifact_refs: tuple[str, ...]
    verifier_verdict: str
    error_class: str | None
    idempotency_key: str

    @classmethod
    def from_dict(cls, value: Any) -> "AdapterReceipt":
        if not isinstance(value, dict):
            raise ValueError("adapter receipt must be an object")
        fields = {
            "schema_version", "handoff_id", "task_id", "thread_id", "run_id", "step_id",
            "target_agent_id", "trace_id", "status", "output_digest", "artifact_refs",
            "verifier_verdict", "error_class", "idempotency_key",
        }
        if set(value) != fields:
            raise ValueError("adapter receipt has unknown or missing fields")
        if value["schema_version"] != "northstar.adapter-receipt.v1":
            raise ValueError("adapter receipt schema_version is invalid")
        if value["status"] not in {"finished", "failed", "cancelled", "waiting", "unknown"}:
            raise ValueError("adapter receipt status is invalid")
        verdict = value["verifier_verdict"]
        if verdict not in {"verified", "failed", "unknown"}:
            raise ValueError("adapter receipt verifier_verdict is invalid")
        if value["status"] == "finished" and verdict != "verified":
            raise ValueError("finished receipt requires verified postconditions")
        refs = value["artifact_refs"]
        if not isinstance(refs, list) or not all(isinstance(ref, str) and ref for ref in refs):
            raise ValueError("artifact_refs is invalid")
        error_class = value["error_class"]
        if error_class is not None:
            _id(error_class, "error_class")
        return cls(
            schema_version=value["schema_version"],
            handoff_id=_id(value["handoff_id"], "handoff_id"),
            task_id=_id(value["task_id"], "task_id"),
            thread_id=_id(value["thread_id"], "thread_id"),
            run_id=_id(value["run_id"], "run_id"),
            step_id=_id(value["step_id"], "step_id"),
            target_agent_id=_id(value["target_agent_id"], "target_agent_id"),
            trace_id=_id(value["trace_id"], "trace_id"),
            status=value["status"],
            output_digest=_digest(value["output_digest"], "output_digest"),
            artifact_refs=tuple(refs),
            verifier_verdict=verdict,
            error_class=error_class,
            idempotency_key=_id(value["idempotency_key"], "idempotency_key"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "handoff_id": self.handoff_id,
            "task_id": self.task_id,
            "thread_id": self.thread_id,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "target_agent_id": self.target_agent_id,
            "trace_id": self.trace_id,
            "status": self.status,
            "output_digest": self.output_digest,
            "artifact_refs": list(self.artifact_refs),
            "verifier_verdict": self.verifier_verdict,
            "error_class": self.error_class,
            "idempotency_key": self.idempotency_key,
        }


class BackendAdapter:
    """Run one target backend behind a verified, target-bound handoff."""

    def __init__(self, *, agent_id: str, provider: str, version: str, executor: Callable[["AdapterExecutionContext"], AdapterExecution]):
        self.agent_id = _id(agent_id, "agent_id")
        self.provider = _id(provider, "provider")
        self.version = _id(version, "version")
        if not callable(executor):
            raise ValueError("executor must be callable")
        self._executor = executor
        self._results: dict[str, tuple[str, AdapterReceipt]] = {}

    def execute(
        self,
        handoff_token: str,
        context: ContextEnvelope,
        *,
        handoff_secret: bytes,
        current_policy_revision: str,
        now: int,
    ) -> AdapterReceipt:
        if not isinstance(context, ContextEnvelope):
            raise ValueError("context envelope is invalid")
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
        if grant.input_digest != context.input_digest:
            raise ValueError("context digest does not match handoff")
        if tuple(grant.expected_postconditions) != tuple(context.expected_postconditions):
            raise ValueError("context postconditions do not match handoff")
        fingerprint = hashlib.sha256(
            grant.canonical_json() + b"\0" + _canonical(context.to_dict())
        ).hexdigest()
        cached = self._results.get(grant.idempotency_key)
        if cached is not None:
            old_fingerprint, receipt = cached
            if old_fingerprint != fingerprint:
                raise ValueError("handoff idempotency key conflicts")
            return receipt
        execution_context = AdapterExecutionContext(
            handoff_id=grant.handoff_id,
            task_id=grant.task_id,
            thread_id=grant.thread_id,
            run_id=grant.run_id,
            step_id=grant.step_id,
            target_agent_id=grant.target_agent_id,
            trace_id=grant.trace_id,
            context_ref=context.context_ref,
            input_digest=context.input_digest,
            expected_postconditions=context.expected_postconditions,
            idempotency_key=grant.idempotency_key,
            agent_id=self.agent_id,
            provider=self.provider,
            version=self.version,
        )
        try:
            execution = self._executor(execution_context)
        except Exception as error:
            raise ValueError("backend adapter execution failed") from error
        if not isinstance(execution, AdapterExecution):
            raise ValueError("backend adapter returned an invalid execution")
        if execution.status == "finished" and execution.verifier_verdict != "verified":
            status = "unknown"
        else:
            status = execution.status
        receipt = AdapterReceipt(
            schema_version="northstar.adapter-receipt.v1",
            handoff_id=grant.handoff_id,
            task_id=grant.task_id,
            thread_id=grant.thread_id,
            run_id=grant.run_id,
            step_id=grant.step_id,
            target_agent_id=grant.target_agent_id,
            trace_id=grant.trace_id,
            status=status,
            output_digest=execution.output_digest,
            artifact_refs=execution.artifact_refs,
            verifier_verdict=execution.verifier_verdict,
            error_class=None if status in {"finished", "unknown"} else "backend_execution",
            idempotency_key=grant.idempotency_key,
        )
        self._results[grant.idempotency_key] = (fingerprint, receipt)
        return receipt


@dataclass(frozen=True)
class AdapterExecutionContext:
    handoff_id: str
    task_id: str
    thread_id: str
    run_id: str
    step_id: str
    target_agent_id: str
    trace_id: str
    context_ref: str
    input_digest: str
    expected_postconditions: tuple[str, ...]
    idempotency_key: str
    agent_id: str
    provider: str
    version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "handoff_id": self.handoff_id,
            "task_id": self.task_id,
            "thread_id": self.thread_id,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "target_agent_id": self.target_agent_id,
            "trace_id": self.trace_id,
            "context_ref": self.context_ref,
            "input_digest": self.input_digest,
            "expected_postconditions": list(self.expected_postconditions),
            "idempotency_key": self.idempotency_key,
            "agent_id": self.agent_id,
            "provider": self.provider,
            "version": self.version,
        }
