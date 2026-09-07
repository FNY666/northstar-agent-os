"""Three-layer permission gate: ``disallowed_tools`` → ``allowed_tools`` → mode.

The order is not negotiable, and the first layer always wins: a tool listed in
``disallowed_tools`` is denied even under ``bypassPermissions`` and even if a
hook would have approved it. The second layer auto-approves. The third layer is
``permission_mode`` plus, when the host supplied one, the ``can_use_tool``
approval callback.

Safety direction: whenever the gate cannot reach a decision - unknown tool, no
host approval callback in ``default`` mode, a callback that raises - the answer
is **deny**, not "go ahead". Denying work is recoverable; executing work the
host never approved is not.

``Task`` is deliberately not treated as a mutating tool. Blanket-denying it by
name would mean no subagent is ever created, and the error would blame a tool
that was never the problem. Delegation is instead gated per tool inside the
subagent's declared tool set (:meth:`PermissionEngine.check_delegation`).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable, Literal, Sequence

from receipts import ApprovalLease, ApprovalLeaseLedger, ReceiptError, capability_for

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
    "approval_lease",
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
    capability: str = ""
    lease_id: str | None = None

    @property
    def text(self) -> str:
        return self.reason or ("allowed" if self.allowed else "denied")

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "allowed": self.allowed,
            "source": self.source,
            "reason": self.reason,
            "rule": self.rule,
            "capability": self.capability,
            "lease_id": self.lease_id,
        }


@dataclass(frozen=True)
class PermissionRequestContext:
    """What the host approval callback gets to see."""

    session_id: str = ""
    agent: str = "main"
    depth: int = 0
    turn_index: int = 0
    workspace: str = ""
    mode: str = "default"
    reason_hint: str = ""
    capability: str = ""
    data: dict[str, Any] = field(default_factory=dict)


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
    approval_leases: ApprovalLeaseLedger | None = None
    clock: Callable[[], int] = lambda: int(time.time())

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", validate_mode(self.mode))
        object.__setattr__(self, "allowed_tools", normalise_names(self.allowed_tools))
        object.__setattr__(self, "disallowed_tools", normalise_names(self.disallowed_tools))
        if self.can_use_tool is not None and not callable(self.can_use_tool):
            raise TypeError("can_use_tool must be callable")
        if self.approval_leases is not None and not isinstance(self.approval_leases, ApprovalLeaseLedger):
            raise TypeError("approval_leases must be an ApprovalLeaseLedger")
        if not callable(self.clock):
            raise TypeError("clock must be callable")

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
        approval_leases: ApprovalLeaseLedger | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if config is None:
            config = PermissionConfig(
                mode=mode,
                allowed_tools=allowed_tools or (),
                disallowed_tools=disallowed_tools or (),
                can_use_tool=can_use_tool,
                approval_leases=approval_leases,
                clock=clock or (lambda: int(time.time())),
            )
        elif approval_leases is not None or clock is not None:
            config = PermissionConfig(
                mode=config.mode,
                allowed_tools=config.allowed_tools,
                disallowed_tools=config.disallowed_tools,
                can_use_tool=config.can_use_tool,
                approval_leases=approval_leases if approval_leases is not None else config.approval_leases,
                clock=clock or config.clock,
            )
        self.config = config
        self.approval_leases = config.approval_leases
        self.clock = config.clock
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
        """
        resolved_kind = kind or self._kinds.get(tool_name) or "other"
        if resolved_kind not in {"read", "edit", "exec", "task", "network", "other"}:
            resolved_kind = "other"
        is_mutating = (resolved_kind in MUTATING_KINDS) if mutating is None else bool(mutating)
        capability = capability_for(resolved_kind, tool_name)

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
                    capability=capability,
                )
            return PermissionDecision(
                True,
                source="mode",
                reason=f"{tool_name} is read-only, permitted in plan mode",
                rule="mode:plan",
                tool=tool_name,
                capability=capability,
            )

        # A lease is checked after hard deny/plan boundaries and before the
        # mode's host callback. It is consumed exactly once here, at the point
        # of authorization, so replaying a model call cannot reuse it.
        if is_mutating and self.approval_leases is not None:
            lease_context = context or PermissionRequestContext(mode=self.config.mode)
            lease_context = _with_capability(lease_context, capability)
            try:
                consumed = self.approval_leases.consume(
                    session_id=lease_context.session_id,
                    workspace=lease_context.workspace,
                    capability=capability,
                    now=int(self.clock()),
                )
            except (ReceiptError, TypeError, ValueError) as error:
                return PermissionDecision(
                    False,
                    source="approval_lease",
                    reason=f"approval lease validation failed; failing closed ({error})",
                    rule="approval_lease:invalid",
                    tool=tool_name,
                    capability=capability,
                )
            if consumed is not None:
                return PermissionDecision(
                    True,
                    source="approval_lease",
                    reason=f"{tool_name} approved by capability lease {consumed.lease_id}",
                    rule="approval_lease:consume",
                    tool=tool_name,
                    capability=capability,
                    lease_id=consumed.lease_id,
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
        request = context or PermissionRequestContext(
            mode=self.config.mode, reason_hint=f"{tool_name} is mutating"
        )
        request = _with_capability(request, capability)
        try:
            verdict = self.config.can_use_tool(tool_name, dict(payload or {}), request)
        except Exception as error:  # noqa: BLE001 - a broken approver must not grant access
            return PermissionDecision(
                False,
                source="host_callback",
                reason=f"host approval callback raised {type(error).__name__}; failing closed",
                rule="host_callback:error",
                tool=tool_name,
                capability=capability,
            )

        try:
            lease = _lease_from_verdict(verdict)
        except (ReceiptError, TypeError, ValueError) as error:
            return PermissionDecision(
                False,
                source="approval_lease",
                reason=f"host capability lease is malformed; failing closed ({error})",
                rule="approval_lease:invalid",
                tool=tool_name,
                capability=capability,
            )
        if lease is not None:
            if self.approval_leases is None:
                return PermissionDecision(
                    False,
                    source="approval_lease",
                    reason="host returned a capability lease but this engine has no lease ledger",
                    rule="approval_lease:no_ledger",
                    tool=tool_name,
                    capability=capability,
                )
            approved, note = _approval_verdict(verdict)
            # A bare ApprovalLease is an approval; a mapping may explicitly
            # reject it. Never silently turn a denied host response into access.
            if isinstance(verdict, ApprovalLease):
                approved = True
            if not approved:
                return PermissionDecision(
                    False,
                    source="host_callback",
                    reason=note or f"{tool_name} refused by host approval callback",
                    rule="host_callback:deny",
                    tool=tool_name,
                    capability=capability,
                )
            try:
                existing = self.approval_leases.get(lease.lease_id)
                if existing is None:
                    self.approval_leases.add(lease)
                elif existing != lease:
                    raise ReceiptError("lease id is already bound to different claims")
                consumed = self.approval_leases.consume(
                    session_id=request.session_id,
                    workspace=request.workspace,
                    capability=capability,
                    now=int(self.clock()),
                )
            except (ReceiptError, TypeError, ValueError) as error:
                return PermissionDecision(
                    False,
                    source="approval_lease",
                    reason=f"host capability lease is invalid; failing closed ({error})",
                    rule="approval_lease:invalid",
                    tool=tool_name,
                    capability=capability,
                )
            if consumed is None:
                return PermissionDecision(
                    False,
                    source="approval_lease",
                    reason=f"host capability lease does not cover {capability} in this session/workspace or is expired",
                    rule="approval_lease:out_of_scope",
                    tool=tool_name,
                    capability=capability,
                )
            return PermissionDecision(
                True,
                source="approval_lease",
                reason=note or f"{tool_name} approved by capability lease {consumed.lease_id}",
                rule="approval_lease:consume",
                tool=tool_name,
                capability=capability,
                lease_id=consumed.lease_id,
            )

        approved, note = _approval_verdict(verdict)
        if approved:
            return PermissionDecision(
                True,
                source="host_callback",
                reason=note or f"{tool_name} approved by host approval callback",
                rule="host_callback:allow",
                tool=tool_name,
                capability=capability,
            )
        return PermissionDecision(
            False,
            source="host_callback",
            reason=note or f"{tool_name} refused by host approval callback",
            rule="host_callback:deny",
            tool=tool_name,
            capability=capability,
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


def _with_capability(context: PermissionRequestContext, capability: str) -> PermissionRequestContext:
    if context.capability == capability:
        return context
    return replace(context, capability=capability)


def _lease_from_verdict(verdict: Any) -> ApprovalLease | None:
    """Extract an optional lease without weakening legacy bool callbacks."""
    if isinstance(verdict, ApprovalLease):
        return verdict
    candidate: Any = None
    if isinstance(verdict, dict):
        candidate = verdict.get("lease") or verdict.get("approval_lease")
    else:
        candidate = getattr(verdict, "lease", None) or getattr(verdict, "approval_lease", None)
    if candidate is None:
        return None
    if isinstance(candidate, ApprovalLease):
        return candidate
    if isinstance(candidate, dict):
        return ApprovalLease.from_mapping(candidate)
    raise ReceiptError("host approval lease must be an ApprovalLease or object")


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
    "normalise_names",
    "subtract",
    "validate_mode",
]
