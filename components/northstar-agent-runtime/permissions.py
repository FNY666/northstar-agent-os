"""Three-layer permission gate: ``disallowed_tools`` → ``allowed_tools`` → mode.

The order is not negotiable, and the first layer always wins: a tool listed in
``disallowed_tools`` is denied even under ``bypassPermissions`` and even if a
hook would have approved it. The second layer auto-approves. The third layer is
``permission_mode`` plus, when the host supplied one, the ``can_use_tool``
approval callback.

Approval decisions are never cached and never replayed: every gated call
re-invokes the host callback with the exact call identity (``call_id`` plus a
``sha256`` digest of the canonical arguments), so a "yes" is scoped to exactly
one tool call and can never authorize a later call or different arguments.
This is the same structural rule as byquexo/agent-approval-gate's
``ApprovalGate`` ("the gate holds no state between calls", ``gate.ts``): no
``approveAll``, no session cache, no "remember my choice".

Safety direction: whenever the gate cannot reach a decision - unknown tool, no
host approval callback in ``default`` mode, a callback that raises - the answer
is **deny**, not "go ahead". Denying work is recoverable; executing work the
host never approved is not.

``Task`` is deliberately not treated as a mutating tool. Blanket-denying it by
name would mean no subagent is ever created, and the error would blame a tool
that was never the problem. Delegation is instead gated per tool inside the
subagent's declared tool set (:meth:`PermissionEngine.check_delegation`).

An optional structured *decision-model* path
(:mod:`decision_model`, SystemOne-style: state + typed questions ->
options + probabilities) can adjudicate the calls that would otherwise reach
the host callback: model ``allow``/``deny`` decides the call, model
``escalate`` or a model error falls through to the host callback. With no
model configured the gate is exactly the deterministic three layers above.
Every model-path verdict carries its full input -> output -> verdict chain
in ``PermissionDecision.decision_model_audit``.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable, Literal, Sequence

from decision_model import (
    DecisionModel,
    DecisionModelResult,
    DecisionPolicy,
    adjudicate,
    approval_questions,
    build_decision_audit,
    build_decision_state,
)

PermissionMode = Literal["default", "acceptEdits", "plan", "bypassPermissions"]

PERMISSION_MODES: tuple[PermissionMode, ...] = (
    "default",
    "acceptEdits",
    "plan",
    "bypassPermissions",
)

ToolKind = Literal["read", "edit", "exec", "task", "network", "other"]

#: Kinds that can change state outside the conversation.
MUTATING_KINDS: frozenset[str] = frozenset({"edit", "exec", "network", "other"})

DecisionSource = Literal[
    "disallowed_tools",
    "allowed_tools",
    "mode",
    "host_callback",
    "decision_model",
    "unknown_tool",
    "delegation_gate",
    "invalid_mode",
]


@dataclass(frozen=True)
class PermissionDecision:
    """The gate's verdict for one tool call."""

    allowed: bool
    source: DecisionSource = "mode"
    reason: str = ""
    rule: str = ""
    tool: str = ""
    #: Set only when the verdict came from the decision-model path: the full
    #: input -> output -> verdict chain (state, questions, probabilities,
    #: thresholds), ready to append to the audit feed.
    decision_model_audit: dict[str, Any] | None = None

    @property
    def text(self) -> str:
        return self.reason or ("allowed" if self.allowed else "denied")

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "tool": self.tool,
            "allowed": self.allowed,
            "source": self.source,
            "reason": self.reason,
            "rule": self.rule,
        }
        if self.decision_model_audit is not None:
            payload["decision_model_audit"] = self.decision_model_audit
        return payload


@dataclass(frozen=True)
class PermissionRequestContext:
    """What the host approval callback gets to see.

    ``call_id`` and ``arguments_digest`` pin the approval to the exact call:
    the host decides on this (tool, call id, arguments) triple and the
    decision is consumed for that call only. The engine never caches a
    decision, so reusing an old approval for new arguments fails closed by
    construction — the callback is simply asked again.
    """

    session_id: str = ""
    agent: str = "main"
    depth: int = 0
    turn_index: int = 0
    workspace: str = ""
    mode: str = "default"
    reason_hint: str = ""
    call_id: str = ""
    arguments_digest: str = ""
    data: dict[str, Any] = field(default_factory=dict)


def digest_arguments(arguments: Any) -> str:
    """Canonical ``sha256:<hex>`` digest of tool arguments.

    Same wire format as the durable-run approval tokens
    (``northstar.approval.v2/v3`` bind approvals to this digest), so a host
    can compare the digest it approved against the digest of the call being
    executed and refuse on any mismatch.
    """
    try:
        encoded = json.dumps(
            arguments if isinstance(arguments, dict) else {},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("tool arguments are not JSON-serialisable") from error
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class DelegationVerdict:
    """Per-tool result of gating a subagent's declared tool set."""

    agent: str = ""
    allowed: tuple[str, ...] = ()
    denied: tuple[tuple[str, str], ...] = ()
    checked: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.denied

    @property
    def summary(self) -> str:
        if self.ok:
            return f"delegation approved for {', '.join(self.allowed) or 'no tools'}"
        parts = [f"{name} ({reason})" for name, reason in self.denied]
        return "delegation denied for: " + "; ".join(parts)

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "allowed": list(self.allowed),
            "denied": [{"tool": name, "reason": reason} for name, reason in self.denied],
            "checked": list(self.checked),
            "ok": self.ok,
        }


def normalise_names(values: Iterable[str] | None) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        raise TypeError("tool lists must be sequences of names, not a bare string")
    seen: list[str] = []
    for value in values:
        name = str(value).strip()
        if name and name not in seen:
            seen.append(name)
    return tuple(seen)


def subtract(allowed: Iterable[str] | None, denied: Iterable[str] | None) -> tuple[str, ...]:
    """``--deny-tool`` semantics: subtract, never co-list.

    Keeping a name in both lists would trip the "same tool allowed and
    disallowed" guard instead of doing what the operator asked, so the CLI
    computes the allow list this way before the engine ever sees it.
    """
    denied_set = set(normalise_names(denied))
    return tuple(name for name in normalise_names(allowed) if name not in denied_set)


@dataclass(frozen=True)
class PermissionConfig:
    mode: PermissionMode = "default"
    allowed_tools: tuple[str, ...] = ()
    disallowed_tools: tuple[str, ...] = ()
    can_use_tool: Callable[[str, dict[str, Any], PermissionRequestContext], Any] | None = None
    #: Optional structured decision model (SystemOne-style: state + typed
    #: questions -> options + probabilities). When set, mutating calls that
    #: would otherwise go to the host callback are first offered to the
    #: model; ``allow``/``deny`` decide the call, ``escalate`` (or a model
    #: error) falls through to the existing host-callback path. ``None``
    #: means the deterministic gate path, unchanged.
    decision_model: DecisionModel | None = None
    decision_policy: DecisionPolicy = field(default_factory=DecisionPolicy)

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", validate_mode(self.mode))
        object.__setattr__(self, "allowed_tools", normalise_names(self.allowed_tools))
        object.__setattr__(self, "disallowed_tools", normalise_names(self.disallowed_tools))
        if self.can_use_tool is not None and not callable(self.can_use_tool):
            raise TypeError("can_use_tool must be callable")
        if self.decision_model is not None and not hasattr(self.decision_model, "decide"):
            raise TypeError("decision_model must provide a decide(state, questions) method")
        if not isinstance(self.decision_policy, DecisionPolicy):
            raise TypeError("decision_policy must be a DecisionPolicy")

    @property
    def overlap(self) -> tuple[str, ...]:
        """Names present in both lists; kept for diagnostics, deny always wins."""
        both = set(self.allowed_tools) & set(self.disallowed_tools)
        return tuple(sorted(both))


def validate_mode(mode: str) -> PermissionMode:
    if mode not in PERMISSION_MODES:
        raise ValueError(f"unknown permission mode {mode!r}; expected one of {', '.join(PERMISSION_MODES)}")
    return mode  # type: ignore[return-value]


class PermissionEngine:
    """Evaluates one tool call against the three layers."""

    def __init__(
        self,
        config: PermissionConfig | None = None,
        *,
        mode: PermissionMode = "default",
        allowed_tools: Iterable[str] | None = None,
        disallowed_tools: Iterable[str] | None = None,
        can_use_tool: Callable[[str, dict[str, Any], PermissionRequestContext], Any] | None = None,
        tool_kinds: dict[str, str] | None = None,
    ) -> None:
        if config is None:
            config = PermissionConfig(
                mode=mode,
                allowed_tools=allowed_tools or (),
                disallowed_tools=disallowed_tools or (),
                can_use_tool=can_use_tool,
            )
        self.config = config
        # Fallback kind map for callers that evaluate by name only (e.g. the
        # delegation gate, where no ToolSpec object is in hand).
        self._kinds: dict[str, str] = dict(tool_kinds or {})

    # -- layer helpers -----------------------------------------------------
    @property
    def mode(self) -> PermissionMode:
        return self.config.mode

    def knows(self, tool_name: str) -> bool:
        return tool_name in self._kinds

    def register_kind(self, tool_name: str, kind: str) -> None:
        self._kinds[tool_name] = kind

    def evaluate(
        self,
        tool_name: str,
        *,
        kind: str | None = None,
        mutating: bool | None = None,
        payload: dict[str, Any] | None = None,
        context: PermissionRequestContext | None = None,
        known: bool = True,
    ) -> PermissionDecision:
        """Run the three layers for one call.

        ``kind``/``mutating`` normally come from the tool's own
        :class:`~tools.ToolSpec`; the delegation gate passes only names, which is
        why the engine keeps a name→kind map as well.

        The engine keeps no approval state between calls: a gated call always
        re-invokes the host callback, so an approval granted for one
        (``call_id``, ``arguments_digest``) pair can never authorize another
        call. Reusing an old approval for new arguments fails closed because
        the callback is asked again, not because a cache is consulted.
        """
        resolved_kind = kind or self._kinds.get(tool_name) or "other"
        if resolved_kind not in {"read", "edit", "exec", "task", "network", "other"}:
            resolved_kind = "other"
        is_mutating = (resolved_kind in MUTATING_KINDS) if mutating is None else bool(mutating)

        if tool_name in set(self.config.disallowed_tools):
            return PermissionDecision(
                False,
                source="disallowed_tools",
                reason=f"{tool_name} is listed in disallowed_tools",
                rule="disallowed_tools",
                tool=tool_name,
            )
        if not known and resolved_kind != "task":
            return PermissionDecision(
                False,
                source="unknown_tool",
                reason=f"{tool_name} is not a registered tool, so no policy applies to it",
                rule="registered_tools",
                tool=tool_name,
            )
        if tool_name in set(self.config.allowed_tools):
            return PermissionDecision(
                True,
                source="allowed_tools",
                reason=f"{tool_name} is auto-approved by allowed_tools",
                rule="allowed_tools",
                tool=tool_name,
            )
        if self.config.mode == "bypassPermissions":
            return PermissionDecision(
                True,
                source="mode",
                reason=f"{tool_name} approved under permission_mode=bypassPermissions",
                rule="mode:bypassPermissions",
                tool=tool_name,
            )
        if self.config.mode == "plan":
            if is_mutating:
                return PermissionDecision(
                    False,
                    source="mode",
                    reason=f"plan mode is read-only; {tool_name} would change state",
                    rule="mode:plan",
                    tool=tool_name,
                )
            return PermissionDecision(
                True,
                source="mode",
                reason=f"{tool_name} is read-only, permitted in plan mode",
                rule="mode:plan",
                tool=tool_name,
            )
        if not is_mutating:
            return PermissionDecision(
                True,
                source="mode",
                reason=f"{tool_name} is read-only, permitted in {self.config.mode} mode",
                rule=f"mode:{self.config.mode}",
                tool=tool_name,
            )
        if self.config.mode == "acceptEdits" and resolved_kind == "edit":
            return PermissionDecision(
                True,
                source="mode",
                reason=f"{tool_name} is a workspace edit, auto-approved by acceptEdits",
                rule="mode:acceptEdits",
                tool=tool_name,
            )
        request = context or PermissionRequestContext(
            mode=self.config.mode, reason_hint=f"{tool_name} is mutating"
        )
        # The approver must always see the digest of the exact arguments being
        # decided on: if the caller did not pin it, derive it here so a
        # decision can never be detached from its arguments.
        if not request.arguments_digest:
            request = replace(
                request, arguments_digest=digest_arguments(payload or {})
            )
        if self.config.decision_model is not None:
            model_decision = self._evaluate_with_decision_model(
                tool_name, resolved_kind, is_mutating, request
            )
            if model_decision is not None:
                return model_decision
            # The model escalated or failed: fall through to the existing
            # host-callback path. The model path never grants on error.
        if self.config.can_use_tool is None:
            return PermissionDecision(
                False,
                source="mode",
                reason=(
                    f"{tool_name} changes state and this run has no host approval callback, "
                    f"so it is denied under permission_mode={self.config.mode}"
                ),
                rule=f"mode:{self.config.mode}:no_callback",
                tool=tool_name,
            )
        try:
            verdict = self.config.can_use_tool(tool_name, dict(payload or {}), request)
        except Exception as error:  # noqa: BLE001 - a broken approver must not grant access
            return PermissionDecision(
                False,
                source="host_callback",
                reason=f"host approval callback raised {type(error).__name__}; failing closed",
                rule="host_callback:error",
                tool=tool_name,
            )
        approved, note = _approval_verdict(verdict)
        if approved:
            return PermissionDecision(
                True,
                source="host_callback",
                reason=note or f"{tool_name} approved by host approval callback",
                rule="host_callback:allow",
                tool=tool_name,
            )
        return PermissionDecision(
            False,
            source="host_callback",
            reason=note or f"{tool_name} refused by host approval callback",
            rule="host_callback:deny",
            tool=tool_name,
        )

    def evaluate_spec(
        self,
        spec: Any,
        payload: dict[str, Any] | None = None,
        *,
        context: PermissionRequestContext | None = None,
        known: bool = True,
    ) -> PermissionDecision:
        return self.evaluate(
            spec.name,
            kind=spec.kind,
            mutating=spec.is_mutating,
            payload=payload,
            context=context,
            known=known,
        )

    # -- decision-model path -------------------------------------------------
    def _evaluate_with_decision_model(
        self,
        tool_name: str,
        kind: str,
        mutating: bool,
        request: PermissionRequestContext,
    ) -> PermissionDecision | None:
        """Offer the call to the structured decision model.

        Returns a decision for ``allow``/``deny`` outcomes, or ``None`` when
        the model escalates or fails -- the caller then falls through to the
        host-callback path. A broken model never grants access.
        """
        model = self.config.decision_model
        assert model is not None  # noqa: S101 - guarded by the caller
        state = build_decision_state(
            tool_name,
            kind=kind,
            mutating=mutating,
            context=request,
            payload_digest=request.arguments_digest,
        )
        questions = approval_questions()
        policy = self.config.decision_policy
        model_error: str | None = None
        try:
            result = model.decide(state, questions)
            outcome, reason = adjudicate(result, policy)
        except Exception as error:  # noqa: BLE001 - a broken model must not grant access
            result = DecisionModelResult(
                answers={}, model=getattr(model, "model_name", "")
            )
            outcome, reason = (
                "escalate",
                f"decision model raised {type(error).__name__}; "
                "deferring to host callback",
            )
            model_error = f"{type(error).__name__}: {error}"
        audit = build_decision_audit(
            state=state,
            questions=questions,
            result=result,
            policy=policy,
            outcome=outcome,
            reason=reason,
            model_error=model_error,
        )
        if outcome == "allow":
            return PermissionDecision(
                True,
                source="decision_model",
                reason=reason,
                rule="decision_model:allow",
                tool=tool_name,
                decision_model_audit=audit,
            )
        if outcome == "deny":
            return PermissionDecision(
                False,
                source="decision_model",
                reason=reason,
                rule="decision_model:deny",
                tool=tool_name,
                decision_model_audit=audit,
            )
        return None

    # -- delegation --------------------------------------------------------
    def check_delegation(
        self,
        agent: str,
        tool_names: Sequence[str],
        *,
        kinds: dict[str, str] | None = None,
        context: PermissionRequestContext | None = None,
        disallowed_extra: Iterable[str] = (),
    ) -> DelegationVerdict:
        """Gate a subagent by *each tool it declared*, not by the name ``Task``.

        A delegation is approved only when every tool the subagent may reach is
        approved here. That is what makes "read-only reviewer subagent" a real
        boundary instead of a prompt-level suggestion.
        """
        extra = set(normalise_names(disallowed_extra))
        allowed: list[str] = []
        denied: list[tuple[str, str]] = []
        checked: list[str] = []
        for name in normalise_names(tool_names):
            checked.append(name)
            if name in extra:
                denied.append((name, "disallowed for subagents by host policy"))
                continue
            kind = (kinds or self._kinds).get(name, "other")
            decision = self.evaluate(name, kind=kind, context=context)
            if decision.allowed:
                allowed.append(name)
            else:
                denied.append((name, decision.reason))
        return DelegationVerdict(agent=agent, allowed=tuple(allowed), denied=tuple(denied), checked=tuple(checked))


def _approval_verdict(verdict: Any) -> tuple[bool, str]:
    """Accept bool / "allow" / "deny" / {"allowed": bool, "reason": ...}."""
    if isinstance(verdict, bool):
        return verdict, ""
    if isinstance(verdict, str):
        text = verdict.strip().lower()
        if text in {"allow", "approve", "approved", "yes", "true"}:
            return True, ""
        if text in {"deny", "denied", "reject", "no", "false"}:
            return False, ""
        return False, f"unrecognised approval verdict {verdict!r}"
    if isinstance(verdict, dict):
        allowed = bool(verdict.get("allowed", verdict.get("allow", False)))
        reason = str(verdict.get("reason", "") or "")
        return allowed, reason
    allowed = getattr(verdict, "allowed", None)
    if isinstance(allowed, bool):
        return allowed, str(getattr(verdict, "reason", "") or "")
    return False, f"unrecognised approval verdict {type(verdict).__name__}"


__all__ = [
    "DelegationVerdict",
    "MUTATING_KINDS",
    "PERMISSION_MODES",
    "PermissionConfig",
    "PermissionDecision",
    "PermissionEngine",
    "PermissionMode",
    "PermissionRequestContext",
    "ToolKind",
    "digest_arguments",
    "normalise_names",
    "subtract",
    "validate_mode",
]
