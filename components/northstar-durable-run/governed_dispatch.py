"""Route AgentLoop actions through the ActionGateway authorization chain.

The loop itself stays unaware of the gateway: a host binds one dispatcher
callable per action id, and every attempt is re-authorized against a fresh
ToolCall. Denials raise distinct exception kinds so the evidence stream can
tell "authorization refused" apart from "the tool ran and raised".
"""
from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable
from typing import Any

import re

from action_gateway import (
    ActionGateway,
    ToolCall,
    ToolExecutionFailed,
    ToolRefused,
    digest_arguments,
)
from agent_loop import ActionAwaitingApproval, ActionNotExecuted, AgentPlan, PlanStep

TOOL_CALL_SCHEMA_VERSION = "northstar.tool-call.v1"
_ID_RE = re.compile(r"^[^\s/\\\x00]+$")
_MAX_ID = 128


class UnboundAction(ActionNotExecuted, ValueError):
    """The dispatcher has no admitted plan step behind this call."""


class GovernanceDenied(ActionNotExecuted, ValueError):
    """The gateway refused the call: authorization, scope, contract, or tool."""


class ActionExecutionFailed(Exception):
    """The tool ran and raised: not a refusal, and not a pending approval.

    The loop treats a plain exception as "the action ran", records
    `step.action_failed`, and still allows an independent observer to decide
    what the world looks like. The failure kind is preserved in the class name
    so evidence stays readable, and the exception message is never copied.
    """


_KIND_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,48}$")


def _execution_failure(cause: BaseException) -> ActionExecutionFailed:
    kind = type(cause).__name__
    if not _KIND_RE.fullmatch(kind):
        kind = "ToolError"
    return type(f"{kind}ExecutionFailure", (ActionExecutionFailed,), {})(kind)


class ApprovalPending(ActionAwaitingApproval, ValueError):
    """A high-risk tool is waiting for approval, not failing.

    Waiting is a human time scale, so the loop must not spend the step's attempt
    budget on it; the step deadline is what bounds the wait.
    """


def _idempotency_key(step: PlanStep, attempt_id: str) -> str:
    """Keep a readable key when it fits; degrade to a digest instead of truncating."""
    candidate = f"{step.idempotency_key}:{attempt_id}"
    if len(candidate) <= _MAX_ID and _ID_RE.fullmatch(candidate):
        return candidate
    return "idem-" + hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:48]


class GovernedActionDispatcher:
    """Bind admitted plan steps to gateway-authorized tool execution."""

    def __init__(
        self,
        gateway: ActionGateway,
        *,
        authorization_token_provider: Callable[[], str],
        authorization_secret: bytes,
        now_provider: Callable[[], int] = lambda: int(time.time()),
        approval_provider: Callable[[ToolCall], str | None] | None = None,
    ):
        if not isinstance(gateway, ActionGateway):
            raise ValueError("gateway is invalid")
        if not callable(authorization_token_provider):
            raise ValueError("authorization_token_provider must be callable")
        if not isinstance(authorization_secret, bytes) or not authorization_secret:
            raise ValueError("authorization_secret must be non-empty bytes")
        if not callable(now_provider):
            raise ValueError("now_provider must be callable")
        if approval_provider is not None and not callable(approval_provider):
            raise ValueError("approval_provider must be callable")
        self._gateway = gateway
        self._token_provider = authorization_token_provider
        self._secret = authorization_secret
        self._now_provider = now_provider
        self._approval_provider = approval_provider
        self._steps: dict[str, tuple[AgentPlan, PlanStep]] = {}

    def register_plan(self, plan: AgentPlan) -> None:
        if not isinstance(plan, AgentPlan):
            raise ValueError("plan is invalid")
        for step in plan.steps:
            if step.step_id in self._steps:
                raise ValueError(f"step is already bound: {step.step_id}")
        for step in plan.steps:
            self._steps[step.step_id] = (plan, step)

    def bind(self, tool_name: str) -> Callable[[PlanStep, str], dict[str, Any]]:
        if not isinstance(tool_name, str) or not _ID_RE.fullmatch(tool_name):
            raise ValueError("tool_name is invalid")

        def action(step: PlanStep, attempt_id: str) -> dict[str, Any]:
            return self._dispatch(tool_name, step, attempt_id)

        return action

    def _dispatch(self, tool_name: str, step: PlanStep, attempt_id: str) -> dict[str, Any]:
        if not isinstance(step, PlanStep):
            raise UnboundAction("action requires an admitted plan step")
        if not isinstance(attempt_id, str) or not _ID_RE.fullmatch(attempt_id):
            raise UnboundAction("action attempt identity is invalid")
        bound = self._steps.get(step.step_id)
        if bound is None:
            raise UnboundAction(f"no admitted plan step is bound to {step.step_id}")
        plan, bound_step = bound
        if bound_step.action_id != tool_name or step.action_id != tool_name:
            raise UnboundAction("action id does not match the bound plan step")
        call = ToolCall.from_dict({
            "schema_version": TOOL_CALL_SCHEMA_VERSION,
            "task_id": plan.task_id,
            "thread_id": plan.thread_id,
            "run_id": plan.run_id,
            "step_id": step.step_id,
            "actor_id": plan.actor_id,
            "workspace_id": plan.workspace_id,
            "trace_id": plan.trace_id,
            "tool_name": tool_name,
            "resource_id": plan.workspace_id,
            "requested_scope": list(step.scope_snapshot),
            "arguments_digest": digest_arguments(step.input_payload),
            "idempotency_key": _idempotency_key(step, attempt_id),
            "deadline_at": step.deadline_at,
        })
        approval_token = self._approval_provider(call) if self._approval_provider else None
        spec = self._gateway.spec_for(tool_name)
        if approval_token is None and spec is not None and spec.risk_level == "high":
            # Distinguish waiting from refusing: the step has not run, so this
            # must not consume its attempt budget.
            raise ApprovalPending("approval is pending")
        try:
            result = self._gateway.execute(
                call,
                step.input_payload,
                authorization_token=self._token_provider(),
                authorization_secret=self._secret,
                current_policy_revision=plan.policy_revision,
                approval_token=approval_token,
                now=self._now_provider(),
            )
        except ToolRefused as error:
            # A tool-side refusal is still a refusal: it never executed.
            raise GovernanceDenied(type(error).__name__) from error
        except ToolExecutionFailed as error:
            # The tool ran and raised; the loop must see an execution failure,
            # not a refusal, so recovery through observation stays legal.
            raise _execution_failure(error.__cause__ or error) from error
        except Exception as error:
            # Denials stay fail-closed but remain distinguishable in evidence.
            raise GovernanceDenied(type(error).__name__) from error
        return result.output
