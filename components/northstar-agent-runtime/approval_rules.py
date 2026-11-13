"""Standing approval rules: approval as data, not a callback.

Microsoft Agent Framework's ``ToolApprovalMiddleware``
(``python/packages/core/agent_framework/_harness/_tool_approval.py``) makes the
approval decision part of the agent loop's *state*: a ``ToolApprovalRule`` says
"always approve this tool, with these arguments", the rules live in the
session, and a resumed run finds them again.  The point is that the answer to
"may I run this?" is **data** that survives the process, not a live callback
that must be re-asked.

Northstar has the live approval path (``permissions.py`` ->
``approval_chain.py`` -> a signed receipt -> the edge gate).  This module does
**not** touch it.  It provides the piece that was missing: a rule that can be
written down, serialised, carried in a checkpoint's ``extra`` field or a
session record, and read back.

Argument matching
-----------------
A rule pins a subset of a tool call's arguments.  The polarity is the same as
Claude Code's input validation - **tolerate extra keys, require the pinned
ones**:

* a call that carries the rule's pinned keys with the right values matches,
  whatever else it carries;
* a call that is **missing** a pinned key does not match;
* a call whose pinned key holds a different value, or a different type, does
  not match.

A rule with no pinned arguments matches every call to that tool.  This is
deliberately *not* the same rule as MSAF's ``_arguments_match``, which
requires the argument sets to be the same size; a standing rule that only
matched calls with exactly those arguments would stop working the moment a
tool grew a parameter, and a rule that ignored extra keys would widen as the
tool widened.  Pinning a subset keeps the rule narrow and stable.

Honest scope
------------
Nothing here is wired into the live approval gate.  The rules are data that
can be built, matched, serialised and carried; connecting them to
``permissions.py`` is a separate piece of work (see the report's open items).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

#: Version pin for the serialised rule shape.
APPROVAL_RULES_VERSION = "northstar.approval-rules.v1"


class ApprovalRuleError(ValueError):
    """A rule or state that cannot be trusted to authorise anything."""


@dataclass(frozen=True)
class ToolApprovalRule:
    """A standing rule: approve calls to ``tool_name`` that match.

    ``arguments`` pins a subset of the call's arguments.  ``None`` means the
    rule matches every call to the tool; a mapping pins the named keys.
    """

    tool_name: str
    arguments: Mapping[str, Any] | None = None
    #: Optional boundary label (a server, a host).  A rule only matches a call
    #: carrying the same label.
    server_label: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.tool_name, str) or not self.tool_name.strip():
            raise ApprovalRuleError("tool_name must be a non-empty string")
        if self.arguments is not None:
            if not isinstance(self.arguments, Mapping):
                raise ApprovalRuleError("arguments must be a mapping or None")
            object.__setattr__(self, "arguments", dict(self.arguments))
        if self.server_label is not None and not isinstance(self.server_label, str):
            raise ApprovalRuleError("server_label must be a string or None")

    def matches(self, tool_name: str, arguments: Mapping[str, Any] | None = None, *, server_label: str | None = None) -> bool:
        """True when this rule authorises a call to ``tool_name``."""
        if tool_name != self.tool_name:
            return False
        if self.server_label != server_label:
            return False
        if self.arguments is None:
            return True
        return _arguments_match(self.arguments, arguments or {})

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"tool_name": self.tool_name}
        if self.arguments is not None:
            payload["arguments"] = dict(self.arguments)
        if self.server_label is not None:
            payload["server_label"] = self.server_label
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ToolApprovalRule":
        if not isinstance(payload, Mapping):
            raise ApprovalRuleError("a tool approval rule must be a mapping")
        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str):
            raise ApprovalRuleError("tool approval rule tool_name must be a string")
        raw_arguments = payload.get("arguments")
        if raw_arguments is not None and not isinstance(raw_arguments, Mapping):
            raise ApprovalRuleError("tool approval rule arguments must be a mapping or None")
        server_label = payload.get("server_label")
        if server_label is not None and not isinstance(server_label, str):
            raise ApprovalRuleError("tool approval rule server_label must be a string or None")
        return cls(
            tool_name=tool_name,
            arguments=dict(raw_arguments) if raw_arguments is not None else None,
            server_label=server_label,
        )


def _arguments_match(pinned: Mapping[str, Any], actual: Mapping[str, Any]) -> bool:
    """True when ``actual`` carries every pinned key with the pinned value.

    Extra keys in ``actual`` are tolerated; a missing pinned key, a different
    value, or a different type fails.
    """
    for key, expected in pinned.items():
        if key not in actual:
            return False
        found = actual[key]
        if type(found) is not type(expected):
            # A pinned ``1`` must not match a call's ``True``: bool is a subclass
            # of int, and a rule that matched would authorise a different call.
            return False
        if found != expected:
            return False
    return True


@dataclass
class ToolApprovalState:
    """The rules a session carries, and the approval pair it has open.

    The state is plain data: it serialises to a dict, and it comes back from a
    dict.  A checkpoint's ``extra`` field or a session record can carry it, so
    a resumed run finds the same rules the run it continues had.
    """

    rules: list[ToolApprovalRule] = field(default_factory=list)
    #: Approval requests still waiting for a human answer.
    queued_approval_requests: list[dict[str, Any]] = field(default_factory=list)
    #: Approval answers already collected.
    collected_approval_responses: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.rules = [
            rule if isinstance(rule, ToolApprovalRule) else ToolApprovalRule.from_dict(rule)
            for rule in self.rules
        ]
        self.queued_approval_requests = [dict(item) for item in self.queued_approval_requests]
        self.collected_approval_responses = [dict(item) for item in self.collected_approval_responses]

    def add_rule(self, rule: ToolApprovalRule | Mapping[str, Any]) -> ToolApprovalRule:
        """Add a rule; a repeated rule for the same tool *replaces* the earlier one.

        One standing rule per tool: a second "always approve Read, path /a"
        supersedes the first "always approve Read, path /b", so the state
        never carries two contradictory rules for one tool.
        """
        resolved = rule if isinstance(rule, ToolApprovalRule) else ToolApprovalRule.from_dict(rule)
        self.rules = [item for item in self.rules if item.tool_name != resolved.tool_name]
        self.rules.append(resolved)
        return resolved

    def authorises(
        self,
        tool_name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        server_label: str | None = None,
    ) -> bool:
        """True when any rule in the state authorises this call."""
        return any(
            rule.matches(tool_name, arguments, server_label=server_label) for rule in self.rules
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": APPROVAL_RULES_VERSION,
            "rules": [rule.as_dict() for rule in self.rules],
            "queued_approval_requests": [dict(item) for item in self.queued_approval_requests],
            "collected_approval_responses": [dict(item) for item in self.collected_approval_responses],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ToolApprovalState":
        if not isinstance(payload, Mapping):
            raise ApprovalRuleError("tool approval state must be a mapping")
        raw_rules = payload.get("rules") or []
        if not isinstance(raw_rules, Sequence) or isinstance(raw_rules, (str, bytes)):
            raise ApprovalRuleError("tool approval state rules must be a list")
        queued = payload.get("queued_approval_requests") or []
        collected = payload.get("collected_approval_responses") or []
        if not isinstance(queued, Sequence) or isinstance(queued, (str, bytes)):
            raise ApprovalRuleError("queued_approval_requests must be a list")
        if not isinstance(collected, Sequence) or isinstance(collected, (str, bytes)):
            raise ApprovalRuleError("collected_approval_responses must be a list")
        return cls(
            rules=[ToolApprovalRule.from_dict(item) if isinstance(item, Mapping) else item for item in raw_rules],
            queued_approval_requests=[dict(item) for item in queued],
            collected_approval_responses=[dict(item) for item in collected],
        )


__all__ = [
    "APPROVAL_RULES_VERSION",
    "ApprovalRuleError",
    "ToolApprovalRule",
    "ToolApprovalState",
]
