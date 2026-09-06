"""Local-only multi-backend canary for the Northstar interop boundary.

The canary uses fake executors only. It proves that a single host-authorized
run can hand off three bounded steps across three registered backend identities,
while the host retains control of policy, workspace, expiry, idempotency, and
final verification.
"""
from __future__ import annotations

import hashlib
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from authorization import HostPolicy, authorize_run, verify_authorization
from binding import sign_binding, verify_binding
from handoff import (
    HandoffValidation,
    authorize_handoff,
    sign_attestation,
    verify_attestation,
    verify_handoff_grant,
)
from interop_adapter import (
    AdapterExecution,
    AdapterReceipt,
    BackendAdapter,
    ContextEnvelope,
)
from interop_contract import (
    AgentAttestation,
    AgentProfile,
    AgentRegistry,
    HandoffRequest,
)
from workspace import WorkspaceBroker

BINDING_SECRET = b"canary-binding-secret"
AUTHORIZATION_SECRET = b"canary-authorization-secret"
ATTESTATION_SECRET = b"canary-attestation-secret"
HANDOFF_SECRET = b"canary-handoff-secret"
DERIVATION_SECRET = b"canary-derivation-secret"
_POLICY_REVISION = "policy-canary-1"


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _request(
    *,
    handoff_id: str,
    source: str,
    target: str,
    step_id: str,
    capabilities: list[str],
    postconditions: list[str],
    depth: int,
    deadline: int = 1_700,
) -> HandoffRequest:
    return HandoffRequest.from_dict(
        {
            "schema_version": "northstar.handoff-request.v1",
            "handoff_id": handoff_id,
            "task_id": "task-canary-001",
            "thread_id": "thread-canary-001",
            "run_id": "run-canary-001",
            "actor_id": "actor-canary-001",
            "workspace_id": "workspace-canary-001",
            "policy_revision": _POLICY_REVISION,
            "source_agent_id": source,
            "target_agent_id": target,
            "step_id": step_id,
            "trace_id": "trace-canary-001",
            "input_digest": "sha256:" + "a" * 64,
            "requested_capabilities": capabilities,
            "expected_postconditions": postconditions,
            "delegation_depth": depth,
            "deadline_at": deadline,
            "requested_at": 1_000,
            "idempotency_key": f"{handoff_id}-attempt-1",
        }
    )


def _attestation(*, agent_id: str, step_id: str, depth: int, expiry: int) -> AgentAttestation:
    return AgentAttestation.from_dict(
        {
            "schema_version": "northstar.agent-attestation.v1",
            "task_id": "task-canary-001",
            "thread_id": "thread-canary-001",
            "run_id": "run-canary-001",
            "actor_id": "actor-canary-001",
            "workspace_id": "workspace-canary-001",
            "policy_revision": _POLICY_REVISION,
            "agent_id": agent_id,
            "step_id": step_id,
            "trace_id": "trace-canary-001",
            "input_digest": "sha256:" + "a" * 64,
            "capabilities": ["workspace:read", "workspace:write"],
            "delegation_depth": depth,
            "expires_at": expiry,
        }
    )


def _registry() -> AgentRegistry:
    registry = AgentRegistry()
    for agent_id, provider in (
        ("orchestrator", "northstar"),
        ("claude-code", "anthropic"),
        ("codex", "openai"),
        ("hermes", "community"),
    ):
        registry.register(
            AgentProfile.from_dict(
                {
                    "schema_version": "northstar.agent-profile.v1",
                    "agent_id": agent_id,
                    "provider": provider,
                    "version": "canary-v1",
                    "capabilities": ["workspace:read", "workspace:write"],
                }
            )
        )
    return registry


def _verify_artifacts(workspace: Path, *, tamper_result: bool) -> tuple[bool, tuple[str, ...]]:
    errors: list[str] = []
    try:
        workspace_info = workspace.lstat()
        if stat.S_IMODE(workspace_info.st_mode) != 0o700:
            errors.append("workspace is not private")
        if stat.S_ISLNK(workspace_info.st_mode) or not stat.S_ISDIR(workspace_info.st_mode):
            errors.append("workspace is not a regular directory")
    except OSError:
        errors.append("workspace is unavailable")
        return False, tuple(errors)

    expected = {
        "plan.json": '{"strategy":"test-first","owner":"claude-code"}\n',
        "result.txt": "fixed by codex\n",
    }
    for name, expected_content in expected.items():
        path = workspace / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            errors.append(f"artifact missing: {name}")
            continue
        except OSError:
            errors.append(f"artifact unavailable: {name}")
            continue
        if stat.S_ISLNK(info.st_mode):
            errors.append(f"artifact symlink: {name}")
            continue
        if not stat.S_ISREG(info.st_mode):
            errors.append(f"artifact not regular: {name}")
            continue
        actual = path.read_text(encoding="utf-8")
        if actual != expected_content:
            errors.append(f"artifact content mismatch: {name}")
    return not errors, tuple(errors)


@dataclass(frozen=True)
class CanaryOutcome:
    status: str
    verified: bool
    backend_ids: tuple[str, ...]
    receipt_statuses: tuple[str, ...]
    verifier_verdicts: tuple[str, ...]
    duplicate_side_effects: int
    handoff_count: int
    artifact_names: tuple[str, ...]
    codex_executor_calls: int
    errors: tuple[str, ...]


def run_canary(
    root: str | Path,
    *,
    replay_codex: bool = False,
    tamper_result: bool = False,
    review_verdict: str = "verified",
    current_policy_revision: str = _POLICY_REVISION,
) -> CanaryOutcome:
    if review_verdict not in {"verified", "unknown"}:
        raise ValueError("review_verdict must be verified or unknown")
    if current_policy_revision != _POLICY_REVISION:
        raise ValueError("current policy revision is not the canary policy")
    if not isinstance(replay_codex, bool) or not isinstance(tamper_result, bool):
        raise ValueError("canary options must be boolean")

    root_path = Path(root).absolute()
    root_path.mkdir(parents=True, exist_ok=True)
    run = {
        "schema_version": "northstar.run.v1",
        "run_id": "run-canary-001",
        "actor_id": "actor-canary-001",
        "workspace_id": "workspace-canary-001",
        "task_kind": "implementation",
        "prompt": "Execute the isolated canary workflow.",
        "timeout_ms": 10_000,
        "requested_capabilities": ["workspace:read", "workspace:write"],
        "parent_run_id": None,
    }
    binding = {
        "schema_version": run["schema_version"],
        "run_id": run["run_id"],
        "actor_id": run["actor_id"],
        "workspace_id": run["workspace_id"],
        "expires_at": 1_900,
    }
    root_token = authorize_run(
        run,
        verify_binding(sign_binding(binding, BINDING_SECRET), BINDING_SECRET, now=1_000),
        HostPolicy.from_mapping(
            _POLICY_REVISION,
            {run["actor_id"]: ["workspace:read", "workspace:write"]},
        ),
        now=1_000,
        secret=AUTHORIZATION_SECRET,
        grant_ttl_seconds=500,
    )
    workspace = WorkspaceBroker(
        root_path / "broker-state",
        binding_secret=BINDING_SECRET,
        authorization_secret=AUTHORIZATION_SECRET,
        derivation_secret=DERIVATION_SECRET,
    ).allocate(
        run,
        sign_binding(binding, BINDING_SECRET),
        root_token,
        current_policy_revision=_POLICY_REVISION,
        now=1_001,
    ).path

    registry = _registry()
    root_validation = verify_authorization(root_token, AUTHORIZATION_SECRET, now=1_001)
    source_validation = verify_attestation(
        sign_attestation(
            _attestation(agent_id="orchestrator", step_id="plan", depth=0, expiry=1_800),
            ATTESTATION_SECRET,
        ),
        ATTESTATION_SECRET,
        now=1_001,
    )

    requests = [
        _request(
            handoff_id="handoff-canary-001",
            source="orchestrator",
            target="claude-code",
            step_id="plan",
            capabilities=["workspace:read", "workspace:write"],
            postconditions=["plan_created"],
            depth=1,
            deadline=1_700,
        ),
        _request(
            handoff_id="handoff-canary-002",
            source="claude-code",
            target="codex",
            step_id="repair",
            capabilities=["workspace:read", "workspace:write"],
            postconditions=["result_created"],
            depth=2,
            deadline=1_600,
        ),
        _request(
            handoff_id="handoff-canary-003",
            source="codex",
            target="hermes",
            step_id="review",
            capabilities=["workspace:read"],
            postconditions=["result_verified"],
            depth=3,
            deadline=1_400,
        ),
    ]

    grants: list[str] = []
    parent_auth = root_validation
    parent_handoff: HandoffValidation | None = None
    source_agents = ["orchestrator", "claude-code", "codex"]
    source_steps = ["plan", "repair", "review"]
    source_depths = [0, 1, 2]
    source_expiries = [1_800, 1_600, 1_400]
    for index, request in enumerate(requests):
        source = verify_attestation(
            sign_attestation(
                _attestation(
                    agent_id=source_agents[index],
                    step_id=source_steps[index],
                    depth=source_depths[index],
                    expiry=source_expiries[index],
                ),
                ATTESTATION_SECRET,
            ),
            ATTESTATION_SECRET,
            now=1_001 + index,
        )
        token = authorize_handoff(
            request,
            parent_authorization=parent_auth if parent_handoff is None else None,
            parent_handoff=parent_handoff,
            source_attestation=source,
            registry=registry,
            current_policy_revision=current_policy_revision,
            now=1_001 + index,
            secret=HANDOFF_SECRET,
            grant_ttl_seconds=300,
        )
        grants.append(token)
        parent_auth = None
        parent_handoff = verify_handoff_grant(token, HANDOFF_SECRET, now=1_002 + index)

    side_effects: dict[str, int] = {"claude-code": 0, "codex": 0, "hermes": 0}

    def claude_executor(_context):
        side_effects["claude-code"] += 1
        plan_path = workspace / "plan.json"
        plan_path.write_text(
            '{"strategy":"test-first","owner":"claude-code"}\n', encoding="utf-8"
        )
        return AdapterExecution(
            status="finished",
            output_digest=_digest(plan_path),
            artifact_refs=("artifact:plan.json",),
            verifier_verdict="verified",
        )

    def codex_executor(_context):
        side_effects["codex"] += 1
        result_path = workspace / "result.txt"
        result_path.write_text(
            "tampered\n" if tamper_result else "fixed by codex\n", encoding="utf-8"
        )
        return AdapterExecution(
            status="finished",
            output_digest=_digest(result_path),
            artifact_refs=("artifact:result.txt",),
            verifier_verdict="verified",
        )

    def hermes_executor(_context):
        side_effects["hermes"] += 1
        result_path = workspace / "result.txt"
        return AdapterExecution(
            status="finished",
            output_digest=_digest(result_path),
            artifact_refs=("artifact:result.txt",),
            verifier_verdict=review_verdict,
        )

    adapters = [
        BackendAdapter(agent_id="claude-code", provider="anthropic", version="canary-v1", executor=claude_executor),
        BackendAdapter(agent_id="codex", provider="openai", version="canary-v1", executor=codex_executor),
        BackendAdapter(agent_id="hermes", provider="community", version="canary-v1", executor=hermes_executor),
    ]
    contexts = [
        ContextEnvelope.from_dict(
            {
                "schema_version": "northstar.context-envelope.v1",
                "context_ref": "ctx-plan-001",
                "input_digest": "sha256:" + "a" * 64,
                "expected_postconditions": ["plan_created"],
            }
        ),
        ContextEnvelope.from_dict(
            {
                "schema_version": "northstar.context-envelope.v1",
                "context_ref": "ctx-repair-001",
                "input_digest": "sha256:" + "a" * 64,
                "expected_postconditions": ["result_created"],
            }
        ),
        ContextEnvelope.from_dict(
            {
                "schema_version": "northstar.context-envelope.v1",
                "context_ref": "ctx-review-001",
                "input_digest": "sha256:" + "a" * 64,
                "expected_postconditions": ["result_verified"],
            }
        ),
    ]
    receipts: list[AdapterReceipt] = []
    for adapter, token, context in zip(adapters, grants, contexts):
        receipt = adapter.execute(
            token,
            context,
            handoff_secret=HANDOFF_SECRET,
            current_policy_revision=current_policy_revision,
            now=1_010,
        )
        receipts.append(receipt)
        if adapter.agent_id == "codex" and replay_codex:
            adapter.execute(
                token,
                context,
                handoff_secret=HANDOFF_SECRET,
                current_policy_revision=current_policy_revision,
                now=1_011,
            )

    independent_ok, errors = _verify_artifacts(workspace, tamper_result=tamper_result)
    receipt_statuses = tuple(receipt.status for receipt in receipts)
    verifier_verdicts = tuple(receipt.verifier_verdict for receipt in receipts)
    duplicate_side_effects = sum(max(0, count - 1) for count in side_effects.values())
    if review_verdict == "unknown":
        status = "unknown"
    elif not independent_ok:
        status = "failed"
    elif any(receipt.status != "finished" for receipt in receipts):
        status = "failed"
    else:
        status = "ok"
    return CanaryOutcome(
        status=status,
        verified=status == "ok",
        backend_ids=tuple(adapter.agent_id for adapter in adapters),
        receipt_statuses=receipt_statuses,
        verifier_verdicts=verifier_verdicts,
        duplicate_side_effects=duplicate_side_effects,
        handoff_count=len(grants),
        artifact_names=("plan.json", "result.txt"),
        codex_executor_calls=side_effects["codex"],
        errors=errors,
    )
