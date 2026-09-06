"""Subagent definitions.

A subagent is a declaration, not a process: name, system prompt, a tool
subset, optional model/provider, and its own turn and budget limits. The
agent loop instantiates one on a ``Task`` tool call.

Delegation permission is checked against the declared ``tools`` tuple (see
``permissions.PermissionGate``), never against the name ``Task``. By default
no agent declares ``Task``; ``max_subagent_depth`` is the backstop that keeps
nesting bounded even when one does.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

READ_ONLY_TOOLS: tuple[str, ...] = ("Read", "Grep", "List")

EVALUATOR_SYSTEM_PROMPT = (
    "You are an acceptance evaluator. You may only inspect: Read, Grep, and List. "
    "Compare the claim in the task against the actual evidence in the workspace. "
    "If the evidence fully supports the claim, reply with exactly PASS on the first line, "
    "then the supporting evidence. Otherwise reply with exactly FAIL on the first line, "
    "then the gap. If the evidence is missing, incomplete, or ambiguous, reply FAIL. "
    "Default to FAIL when unsure: a false PASS is worse than a false FAIL."
)


@dataclass(frozen=True)
class SubagentDefinition:
    name: str
    description: str
    system: str
    tools: tuple[str, ...]
    model: str | None = None
    provider: Any | None = None  # a Provider instance; None = inherit the parent's
    max_turns: int = 30
    max_budget_usd: float | None = None


def evaluator_agent(**overrides: Any) -> SubagentDefinition:
    """A read-only acceptance evaluator with default-FAIL semantics.

    Its declared tool set is read-only, so in ``default`` permission mode it
    passes the delegation gate without any host callback.
    """
    base: dict[str, Any] = {
        "name": "evaluator",
        "description": "Read-only acceptance evaluator; verdicts PASS/FAIL, defaults to FAIL.",
        "system": EVALUATOR_SYSTEM_PROMPT,
        "tools": READ_ONLY_TOOLS,
    }
    base.update(overrides)
    base["tools"] = tuple(base["tools"])
    return SubagentDefinition(**base)


class AgentRegistry:
    """Named lookup of subagent definitions."""

    def __init__(self, agents: Mapping[str, SubagentDefinition] | Iterable[SubagentDefinition] = ()) -> None:
        self._agents: dict[str, SubagentDefinition] = {}
        for agent in (agents.values() if isinstance(agents, Mapping) else agents):
            self.add(agent)

    def add(self, agent: SubagentDefinition) -> None:
        if not isinstance(agent, SubagentDefinition):
            raise ValueError("AgentRegistry.add expects a SubagentDefinition")
        if not isinstance(agent.name, str) or not agent.name.strip():
            raise ValueError("subagent name must be a non-empty string")
        self._agents[agent.name] = agent

    def get(self, name: str) -> SubagentDefinition | None:
        return self._agents.get(name)

    def names(self) -> tuple[str, ...]:
        return tuple(self._agents)

    def __iter__(self):
        return iter(self._agents.values())

    def __len__(self) -> int:
        return len(self._agents)

    def __contains__(self, name: object) -> bool:
        return name in self._agents
