"""The ten lifecycle hooks, with terminal-deny semantics.

Events: ``PreToolUse`` (may veto or rewrite a tool input), ``PostToolUse``,
``PostToolUseFailure``, ``UserPromptSubmit`` (may inject context or refuse the
whole run), ``Stop`` (may refuse to end the run and feed a reason back as a new
user turn), ``SubagentStart``, ``SubagentStop``, ``PreCompact``, ``SessionStart``,
``SessionEnd``.

Two rules make this usable as a policy layer rather than a logging layer:

1. **deny is terminal.** The first deny for an event stops the chain, and no
   later hook can undo it. An ``allow`` from a hook that runs after a deny is
   recorded as ignored, never applied.
2. **a hook that crashes fails safe.** On a veto-capable event an exception is
   treated as a deny, because the alternative is executing work the host never
   approved. On observation-only events the exception is recorded and the run
   continues.

Hooks are plain callables. They receive a :class:`HookInput` and return
``None`` (no opinion), a :class:`HookResult`, a dict, or a bool.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Literal, Sequence

HookEvent = Literal[
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "UserPromptSubmit",
    "Stop",
    "SubagentStart",
    "SubagentStop",
    "PreCompact",
    "SessionStart",
    "SessionEnd",
]

HOOK_EVENTS: tuple[HookEvent, ...] = (
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "UserPromptSubmit",
    "Stop",
    "SubagentStart",
    "SubagentStop",
    "PreCompact",
    "SessionStart",
    "SessionEnd",
)

#: Events whose hooks may veto something. A deny on any other event is ignored.
#: SubagentStart is here so a host can keep a subagent from being created at all,
#: which is the only moment where refusing delegation is still cheap.
VETO_EVENTS: tuple[HookEvent, ...] = (
    "PreToolUse",
    "UserPromptSubmit",
    "SessionStart",
    "PreCompact",
    "SubagentStart",
)

#: Events where a rewritten/extra payload is meaningful.
INPUT_REWRITE_EVENTS: tuple[HookEvent, ...] = ("PreToolUse",)

#: Events where injected context is added to the conversation.
CONTEXT_INJECT_EVENTS: tuple[HookEvent, ...] = ("UserPromptSubmit", "SessionStart", "PreCompact")

#: Events where a hook may prevent progress instead of allowing it.
BLOCK_EVENTS: tuple[HookEvent, ...] = ("Stop", "SubagentStop")

HookDecisionKind = Literal["noop", "allow", "deny", "modify_input", "inject_context", "block"]


@dataclass(frozen=True)
class HookInput:
    """Everything a hook may inspect. Never carries secrets it did not ask for."""

    event: HookEvent
    session_id: str = ""
    turn_index: int = 0
    agent: str = "main"
    depth: int = 0
    tool_name: str = ""
    tool_use_id: str = ""
    tool_input: dict[str, Any] = field(default_factory=dict)
    tool_response: Any = None
    tool_is_error: bool = False
    prompt: str = ""
    error: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "event": self.event,
            "session_id": self.session_id,
            "turn_index": self.turn_index,
            "agent": self.agent,
            "depth": self.depth,
        }
        if self.tool_name:
            payload["tool_name"] = self.tool_name
            payload["tool_input"] = dict(self.tool_input)
        if self.prompt:
            payload["prompt"] = self.prompt
        if self.error:
            payload["error"] = self.error
        if self.data:
            payload["data"] = dict(self.data)
        return payload


@dataclass(frozen=True)
class HookResult:
    """One hook's opinion."""

    decision: HookDecisionKind = "noop"
    reason: str = ""
    payload: dict[str, Any] | None = None
    additional_context: str = ""
    updated_input: dict[str, Any] | None = None
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def is_deny(self) -> bool:
        return self.decision == "deny"

    @staticmethod
    def allow(reason: str = "") -> "HookResult":
        return HookResult(decision="allow", reason=reason)

    @staticmethod
    def deny(reason: str, **data: Any) -> "HookResult":
        return HookResult(decision="deny", reason=reason or "denied by hook", data=dict(data))

    @staticmethod
    def modify_input(payload: dict[str, Any], reason: str = "") -> "HookResult":
        if not isinstance(payload, dict):
            raise TypeError("modify_input requires a dict payload")
        return HookResult(decision="modify_input", reason=reason, updated_input=dict(payload))

    @staticmethod
    def inject(context: str, reason: str = "") -> "HookResult":
        return HookResult(decision="inject_context", reason=reason, additional_context=context)

    @staticmethod
    def block(reason: str) -> "HookResult":
        return HookResult(decision="block", reason=reason or "stop refused by hook")


def deny(reason: str, **data: Any) -> HookResult:
    return HookResult.deny(reason, **data)


def inject(context: str, reason: str = "") -> HookResult:
    return HookResult.inject(context, reason)


def block(reason: str) -> HookResult:
    return HookResult.block(reason)


def modify_input(payload: dict[str, Any], reason: str = "") -> HookResult:
    return HookResult.modify_input(payload, reason)


def _merge_data(payload: dict[str, Any]) -> dict[str, Any]:
    """Leftover hook keys plus an explicit ``data`` mapping."""
    merged = {key: item for key, item in payload.items() if key != "data"}
    explicit = payload.get("data")
    if isinstance(explicit, dict):
        merged.update(explicit)
    return merged


def coerce_result(value: Any) -> HookResult:
    """Normalise whatever a hook returned into a :class:`HookResult`."""
    if value is None:
        return HookResult()
    if isinstance(value, HookResult):
        return value
    if isinstance(value, bool):
        return HookResult(decision="allow") if value else HookResult(decision="deny", reason="hook returned False")
    if isinstance(value, dict):
        payload = dict(value)
        decision = str(payload.pop("decision", "") or "")
        reason = str(payload.pop("reason", "") or "")
        context = str(payload.pop("additional_context", "") or payload.pop("context", "") or "")
        updated = payload.pop("updated_input", None) or payload.pop("payload", None)
        if decision not in {"noop", "allow", "deny", "modify_input", "inject_context", "block"}:
            # Infer the intent so a hook that only wrote {"reason": ...} on a
            # Stop event still gets to block, and one that only wrote a reason on
            # PreToolUse still gets to deny.
            if reason:
                decision = "block"
            elif updated is not None:
                decision = "modify_input"
            elif context:
                decision = "inject_context"
            else:
                decision = "noop"
        if decision == "deny" and not reason:
            reason = "denied by hook"
        return HookResult(
            decision=decision,
            reason=reason,
            additional_context=context,
            updated_input=dict(updated) if isinstance(updated, dict) else None,
            data=_merge_data(payload),
        )
    return HookResult(decision="noop", reason=str(value))


@dataclass
class HookOutcome:
    """Aggregate verdict for one event across the whole hook chain."""

    event: str = ""
    denied: bool = False
    deny_reason: str = ""
    denied_by: str = ""
    updated_input: dict[str, Any] | None = None
    additional_context: list[str] = field(default_factory=list)
    blocked: bool = False
    block_reason: str = ""
    fired: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    ignored: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def context(self) -> str:
        return "\n".join(part for part in self.additional_context if part)

    @property
    def denied_by_hook(self) -> bool:
        return self.denied

    def as_dict(self) -> dict[str, Any]:
        return {
            "event": self.event,
            "denied": self.denied,
            "deny_reason": self.deny_reason,
            "denied_by": self.denied_by,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "fired": list(self.fired),
            "skipped": list(self.skipped),
            "ignored": list(self.ignored),
            "errors": list(self.errors),
            "rewrote_input": self.updated_input is not None,
        }


@dataclass
class _Registration:
    event: HookEvent
    hook: Callable[[HookInput], Any]
    name: str
    tool: str | None = None
    agent: str | None = None


class HookRegistry:
    """Ordered hook chains keyed by event."""

    def __init__(self, registrations: Iterable[_Registration] = ()) -> None:
        self._chains: dict[HookEvent, list[_Registration]] = {event: [] for event in HOOK_EVENTS}
        for registration in registrations:
            self._append(registration)

    # -- registration ------------------------------------------------------
    def register(
        self,
        event: str,
        hook: Callable[[HookInput], Any] | None = None,
        *,
        name: str = "",
        tool: str | None = None,
        agent: str | None = None,
    ):
        """Register a hook, directly or as a decorator.

        ``tool`` restricts a PreToolUse/PostToolUse hook to one tool name, which
        is how hosts write per-tool policy without string-matching inside the hook.
        """
        if event not in HOOK_EVENTS:
            raise ValueError(f"unknown hook event {event!r}; expected one of {', '.join(HOOK_EVENTS)}")
        if hook is None:  # decorator form
            def decorate(function: Callable[[HookInput], Any]) -> Callable[[HookInput], Any]:
                self._append(_Registration(event, function, name or function.__qualname__, tool, agent))
                return function

            return decorate
        if not callable(hook):
            raise TypeError("hook must be callable")
        self._append(_Registration(event, hook, name or getattr(hook, "__qualname__", repr(hook)), tool, agent))
        return hook

    def _append(self, registration: _Registration) -> None:
        self._chains.setdefault(registration.event, []).append(registration)

    def extend(self, other: "HookRegistry") -> "HookRegistry":
        """Copy another registry's hooks into this one (subagents share policy)."""
        if isinstance(other, HookRegistry):
            for registrations in other._chains.values():
                for registration in registrations:
                    self._append(registration)
        return self

    def hooks_for(self, event: str, *, tool_name: str = "", agent: str = "main") -> list[_Registration]:
        found: list[_Registration] = []
        for registration in self._chains.get(event, ()):  # type: ignore[arg-type]
            if registration.tool and registration.tool != tool_name:
                continue
            if registration.agent and registration.agent != agent:
                continue
            found.append(registration)
        return found

    def counts(self) -> dict[str, int]:
        return {event: len(self._chains.get(event, ())) for event in HOOK_EVENTS}

    def total(self) -> int:
        return sum(self.counts().values())

    @property
    def events_with_hooks(self) -> tuple[str, ...]:
        return tuple(event for event, count in self.counts().items() if count)

    # -- firing ------------------------------------------------------------
    def fire(
        self,
        event: HookEvent,
        hook_input: HookInput,
        *,
        extra_hooks: Sequence[Callable[[HookInput], Any]] = (),
    ) -> HookOutcome:
        """Run every matching hook in order. Deny is terminal."""
        if event not in HOOK_EVENTS:
            raise ValueError(f"unknown hook event {event!r}")
        outcome = HookOutcome(event=event)
        registrations = list(self.hooks_for(event, tool_name=hook_input.tool_name, agent=hook_input.agent))
        for position, hook in enumerate(extra_hooks):
            registrations.append(_Registration(event, hook, f"extra[{position}]", None, None))
        for index, registration in enumerate(registrations):
            try:
                result = coerce_result(registration.hook(hook_input))
            except Exception as error:  # noqa: BLE001 - a hook must not kill the run
                outcome.errors.append(f"{registration.name}: {type(error).__name__}: {error}")
                if event in VETO_EVENTS:
                    # Fail safe: an unreadable verdict is a veto, not a green light.
                    outcome.denied = True
                    outcome.deny_reason = f"hook {registration.name} raised {type(error).__name__}; veto-capable events fail closed"
                    outcome.denied_by = registration.name
                    outcome.skipped.extend(other.name for other in registrations[index + 1 :])
                    return outcome
                continue
            outcome.fired.append(registration.name)
            if result.decision == "deny":
                if event not in VETO_EVENTS:
                    outcome.ignored.append(f"{registration.name} (deny is not applicable to {event})")
                    continue
                outcome.denied = True
                outcome.deny_reason = result.reason
                outcome.denied_by = registration.name
                outcome.data.update(result.data)
                # Anything after a deny is skipped: the verdict cannot be overturned.
                outcome.skipped.extend(other.name for other in registrations[registrations.index(registration) + 1 :])
                return outcome
            if result.decision == "modify_input":
                if event in INPUT_REWRITE_EVENTS and result.updated_input is not None:
                    outcome.updated_input = dict(result.updated_input)
                else:
                    outcome.ignored.append(f"{registration.name} (input rewrite not applicable)")
                continue
            if result.decision == "inject_context":
                if result.additional_context:
                    if event in CONTEXT_INJECT_EVENTS:
                        outcome.additional_context.append(result.additional_context)
                    else:
                        outcome.ignored.append(f"{registration.name} (context inject not applicable)")
                continue
            if result.decision == "block":
                if event in BLOCK_EVENTS:
                    outcome.blocked = True
                    outcome.block_reason = result.reason or "stop refused by hook"
                    outcome.data.update(result.data)
                    # A block is also terminal: later hooks get nothing to argue with.
                    outcome.skipped.extend(other.name for other in registrations[registrations.index(registration) + 1 :])
                    return outcome
                outcome.ignored.append(f"{registration.name} (block not applicable to {event})")
                continue
        return outcome


def empty_registry() -> HookRegistry:
    return HookRegistry()


__all__ = [
    "BLOCK_EVENTS",
    "CONTEXT_INJECT_EVENTS",
    "HOOK_EVENTS",
    "INPUT_REWRITE_EVENTS",
    "VETO_EVENTS",
    "HookEvent",
    "HookInput",
    "HookOutcome",
    "HookRegistry",
    "HookResult",
    "block",
    "coerce_result",
    "deny",
    "empty_registry",
    "inject",
    "modify_input",
]
