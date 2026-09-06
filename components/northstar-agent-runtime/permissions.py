"""Three-tier permission gate.

Evaluation order for a tool call:

1. ``disallowed_tools`` — always wins, even in ``bypassPermissions`` mode.
2. ``allowed_tools`` — auto-approved, in any mode.
3. ``permission_mode`` plus an optional ``can_use_tool`` callback:

   - ``default``          read tools pass; mutating tools (edit/exec) require
                          the host's ``can_use_tool`` callback; **no callback
                          means deny** — failing safe is refusing, never
                          executing.
   - ``acceptEdits``      read and edit tools pass; other mutating (exec)
                          tools are handled like ``default``.
   - ``plan``             mutating tools are denied outright; the callback is
                          not consulted for them.
   - ``bypassPermissions`` everything passes (except disallowed).

Delegation is special-cased: the ``Task`` tool is *not* judged by its own
name. It is approved only if every tool in the declared subagent's tool set
passes this same gate, and only within ``max_subagent_depth``. The denial
message names the offending declared tool, never just "Task".
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Sequence

PERMISSION_MODES: tuple[str, ...] = ("default", "acceptEdits", "plan", "bypassPermissions")

TOOL_KINDS: tuple[str, ...] = ("read", "edit", "exec", "delegate")

# Kinds that mutate the world. "delegate" is governed via the declared
# subagent tool set, not as a mutating tool of its own.
MUTATING_KINDS = frozenset({"edit", "exec"})

# can_use_tool(tool_name, tool_input, permission_mode) -> bool | {"approved": bool, "reason": str}
CanUseTool = Callable[[str, dict[str, Any], str], Any]


@dataclass(frozen=True)
class PermissionDecision:
    allowed: bool
    reason: str = ""


class PermissionGate:
    def __init__(
        self,
        allowed_tools: Sequence[str] = (),
        disallowed_tools: Sequence[str] = (),
        permission_mode: str = "default",
        can_use_tool: Optional[CanUseTool] = None,
        tool_kinds: Optional[Mapping[str, str]] = None,
        subagents: Optional[Mapping[str, Any]] = None,
        depth: int = 0,
        max_subagent_depth: int = 1,
    ) -> None:
        if permission_mode not in PERMISSION_MODES:
            raise ValueError(f"unknown permission_mode: {permission_mode!r}")
        allowed = frozenset(allowed_tools)
        disallowed = frozenset(disallowed_tools)
        overlap = allowed & disallowed
        if overlap:
            raise ValueError(f"tools present in both allowed and disallowed lists: {sorted(overlap)}")
        self.allowed_tools = allowed
        self.disallowed_tools = disallowed
        self.permission_mode = permission_mode
        self.can_use_tool = can_use_tool
        self._tool_kinds = dict(tool_kinds or {})
        if subagents is None:
            self._subagents: dict[str, Any] = {}
        elif isinstance(subagents, Mapping):
            self._subagents = dict(subagents)
        else:  # AgentRegistry or any iterable of definitions
            self._subagents = {agent.name: agent for agent in subagents}
        self.depth = int(depth)
        self.max_subagent_depth = int(max_subagent_depth)

    def check_tool(self, tool_name: str, tool_kind: str, tool_input: Mapping[str, Any]) -> PermissionDecision:
        tool_input = dict(tool_input or {})

        # Tier 1: disallowed always wins.
        if tool_name in self.disallowed_tools:
            return PermissionDecision(False, f"tool '{tool_name}' is disallowed")

        # Tier 2: explicit allow auto-approves in every mode.
        if tool_name in self.allowed_tools:
            return PermissionDecision(True, f"tool '{tool_name}' is explicitly allowed")

        # Delegation is gated by the declared tool set and the depth backstop
        # in every mode: max_subagent_depth is a structural limit, not a
        # permission mode, so even bypassPermissions cannot nest deeper.
        if tool_kind == "delegate":
            return self._check_delegate(tool_input)

        if self.permission_mode == "bypassPermissions":
            return PermissionDecision(True)

        if tool_kind == "read":
            return PermissionDecision(True)

        # Mutating tool (edit or exec).
        if self.permission_mode == "acceptEdits" and tool_kind == "edit":
            return PermissionDecision(True, f"mutating edit auto-approved by acceptEdits mode")
        if self.permission_mode == "plan":
            return PermissionDecision(False, f"plan mode does not permit mutating tool '{tool_name}'")

        # default mode (and exec under acceptEdits): host approval required.
        if self.can_use_tool is None:
            return PermissionDecision(
                False,
                f"mutating tool '{tool_name}' requires approval; no can_use_tool callback "
                "provided (fail-safe: deny, never execute)",
            )
        try:
            verdict = self.can_use_tool(tool_name, tool_input, self.permission_mode)
        except Exception as exc:  # a broken callback must not approve
            return PermissionDecision(False, f"can_use_tool callback raised {type(exc).__name__}: {exc}")
        if isinstance(verdict, Mapping):
            approved = bool(verdict.get("approved", verdict.get("allow", False)))
            reason = str(verdict.get("reason", "") or "")
        else:
            approved = bool(verdict)
            reason = ""
        if approved:
            return PermissionDecision(True, reason or f"host approved '{tool_name}'")
        return PermissionDecision(False, reason or f"host denied '{tool_name}'")

    def _check_delegate(self, tool_input: dict[str, Any]) -> PermissionDecision:
        name = tool_input.get("agent")
        if not isinstance(name, str) or not name.strip():
            return PermissionDecision(False, "delegation requires a non-empty 'agent' string")
        definition = self._subagents.get(name)
        if definition is None:
            return PermissionDecision(False, f"unknown agent '{name}'")

        # Backstop: the child would run at depth+1.
        if self.depth + 1 > self.max_subagent_depth:
            return PermissionDecision(
                False,
                f"delegation not permitted at depth {self.depth} "
                f"(max_subagent_depth={self.max_subagent_depth})",
            )

        # Gate the subagent's *declared* tool set, one tool at a time.
        for tool in definition.tools:
            kind = self._tool_kinds.get(tool)
            if kind is None:
                return PermissionDecision(
                    False, f"subagent '{name}' declares tool '{tool}' which is not available in this context"
                )
            if tool == "Task":
                # The subagent would run at depth+1; its own delegation would
                # create depth+2. Backstop nesting with max_subagent_depth.
                if (self.depth + 2) > self.max_subagent_depth:
                    return PermissionDecision(
                        False,
                        f"subagent '{name}' may not delegate further "
                        f"(max_subagent_depth={self.max_subagent_depth})",
                    )
                continue
            decision = self.check_tool(tool, kind, {})
            if not decision.allowed:
                return PermissionDecision(
                    False,
                    f"subagent '{name}' declares tool '{tool}' which is not approved: {decision.reason}",
                )
        return PermissionDecision(True, f"subagent '{name}' declares only approved tools")
