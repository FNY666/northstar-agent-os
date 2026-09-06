"""Governance hooks.

Ten hook events, each a list of host-registered callables fired in
registration order:

- ``PreToolUse``         veto a tool call (deny) or rewrite its input (``updated_input``)
- ``PostToolUse``        inspect a successful result; a deny converts it into a failure
- ``PostToolUseFailure`` inspect a failed result; a deny appends its reason
- ``UserPromptSubmit``   inject context (``additional_context``) or deny the whole run
- ``Stop``               deny = refuse the end; the reason is fed back as a new user turn
- ``SubagentStart``      fired before a subagent runs; a deny prevents the spawn
- ``SubagentStop``       fired after a subagent ends (a deny is recorded, not actionable)
- ``PreCompact``         fired before compaction; ``skip=True`` (or deny) defers it
- ``SessionStart``       fired at run start
- ``SessionEnd``         fired at run end, including failed runs

Terminality: **the first deny is terminal** — later hooks are not called and
cannot overturn it. A hook that raises is treated as a deny (fail-safe).

Hook callables receive the event payload as a dict and may return
``None`` (no opinion), a :class:`HookDecision`, or a plain mapping with the
keys ``allowed``/``deny``, ``reason``, ``updated_input``, ``additional_context``,
``skip``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

HOOK_NAMES: tuple[str, ...] = (
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

HookName = str  # validated against HOOK_NAMES at registration time

HookFn = Callable[[dict[str, Any]], Optional[Any]]


@dataclass
class HookDecision:
    allowed: bool = True
    reason: str = ""
    updated_input: Optional[dict[str, Any]] = None  # PreToolUse rewrite
    additional_context: Optional[str] = None  # UserPromptSubmit injection
    skip: bool = False  # PreCompact: skip compaction this time

    @classmethod
    def deny(cls, reason: str = "") -> "HookDecision":
        return cls(allowed=False, reason=reason)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "HookDecision":
        allowed = bool(value.get("allowed", True))
        if value.get("deny"):
            allowed = False
        updated = value.get("updated_input")
        context = value.get("additional_context")
        return cls(
            allowed=allowed,
            reason=str(value.get("reason", "") or ""),
            updated_input=dict(updated) if isinstance(updated, Mapping) else None,
            additional_context=context if isinstance(context, str) and context else None,
            skip=bool(value.get("skip", False)),
        )


def _coerce_decision(result: Any) -> Optional[HookDecision]:
    if result is None:
        return None
    if isinstance(result, HookDecision):
        return result
    if isinstance(result, Mapping):
        return HookDecision.from_mapping(result)
    raise ValueError(f"hook must return None, HookDecision, or a mapping; got {type(result).__name__}")


class HookRegistry:
    def __init__(self) -> None:
        self._hooks: dict[str, list[HookFn]] = {name: [] for name in HOOK_NAMES}

    def add(self, name: str, fn: HookFn) -> None:
        if name not in HOOK_NAMES:
            raise ValueError(f"unknown hook: {name!r}; expected one of {sorted(HOOK_NAMES)}")
        self._hooks[name].append(fn)

    def registered(self, name: str) -> int:
        if name not in HOOK_NAMES:
            raise ValueError(f"unknown hook: {name!r}")
        return len(self._hooks[name])

    def fire(self, name: str, payload: Mapping[str, Any]) -> HookDecision:
        """Run all hooks for ``name`` in order.

        Returns the accumulated decision. The first deny is terminal: the
        moment a hook denies, later hooks are not called and cannot
        overturn it. A hook that raises is treated as a deny.
        """
        if name not in HOOK_NAMES:
            raise ValueError(f"unknown hook: {name!r}")
        decision = HookDecision()
        for fn in self._hooks[name]:
            try:
                result = _coerce_decision(fn(dict(payload)))
            except Exception as exc:  # fail-safe: a broken hook denies
                return HookDecision.deny(f"hook raised {type(exc).__name__}: {exc}")
            if result is None:
                continue
            if not result.allowed:
                return result  # terminal deny
            if result.updated_input is not None:
                decision.updated_input = result.updated_input
            if result.additional_context:
                decision.additional_context = (
                    f"{decision.additional_context}\n{result.additional_context}"
                    if decision.additional_context
                    else result.additional_context
                )
            if result.skip:
                decision.skip = True
        return decision
