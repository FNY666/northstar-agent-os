"""Subagent definitions, the delegation rules around them, and acceptance semantics.

A subagent is a second governed run: its own transcript, its own tool subset, its
own turn and budget ceilings, optionally a different provider. What it is *not* is
a permission escape hatch - every tool the subagent declared is pushed through the
parent's permission gate by name (see
:meth:`~permissions.PermissionEngine.check_delegation`), and delegation does not
nest unless the host explicitly asks for it.

The bundled evaluator agent carries the acceptance semantics the runtime enforces
on its behalf: read-only tools, no delegation, and **default FAIL** - an
unparseable, unjustified, or contradicted PASS is a FAIL, never a pass.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Literal, Mapping, Sequence

from permissions import PERMISSION_MODES, PermissionMode

Acceptance = Literal["PASS", "FAIL"]

DEFAULT_AGENT = "general"

#: Read-only tools a subagent may hold without tripping the workspace gate.
READ_ONLY_TOOLS: tuple[str, ...] = ("Read", "Grep", "LS", "DescribeTools")


@dataclass(frozen=True)
class AgentDefinition:
    """One delegatable specialist."""

    name: str = DEFAULT_AGENT
    description: str = ""
    prompt: str = ""
    tools: tuple[str, ...] = READ_ONLY_TOOLS
    disallowed_tools: tuple[str, ...] = ()
    permission_mode: PermissionMode = "default"
    model: str = ""
    provider: str = ""
    max_turns: int = 6
    max_tool_calls: int | None = 12
    max_budget_usd: float | None = None
    allow_delegation: bool = False
    #: Evaluator agents must land on an explicit verdict or the run reports FAIL.
    require_verdict: bool = False
    acceptance_criteria: tuple[str, ...] = ()
    #: Compaction threshold for the subagent's own transcript (tokens).
    compaction_threshold_tokens: int | None = None
    read_only_enforced: bool = True
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("an agent definition needs a name")
        if self.permission_mode not in PERMISSION_MODES:
            raise ValueError(f"agent {self.name}: unknown permission mode {self.permission_mode!r}")
        if self.max_turns < 1:
            raise ValueError(f"agent {self.name}: max_turns must be positive")
        if isinstance(self.tools, str):
            raise TypeError(f"agent {self.name}: tools must be a sequence of names")
        if not self.tools:
            raise ValueError(f"agent {self.name}: an agent with no tools cannot do anything")

    @property
    def is_read_only(self) -> bool:
        return set(self.disallowed_tools) >= {"Write", "Edit"} or all(
            tool in READ_ONLY_TOOLS or tool == "CodexReadOnly" for tool in self.tools
        )

    def system_prompt(self, *, parent_cwd: str = "") -> str:
        parts = [
            f"You are the Northstar {self.name} subagent: {self.description}".strip(),
            self.prompt.strip(),
        ]
        if self.read_only_enforced:
            parts.append(
                "You are read-only. You may inspect and report, never modify. Any write you "
                "attempt will be refused by the runtime, so state the change you would make "
                "instead of trying to make it."
            )
        if self.require_verdict:
            parts.append(VERDICT_INSTRUCTIONS)
        if self.acceptance_criteria:
            listed = "\n".join(f"- [ ] {criterion}" for criterion in self.acceptance_criteria)
            parts.append(f"Evaluate every criterion below; an unchecked criterion forbids a PASS:\n{listed}")
        if parent_cwd:
            parts.append(f"Workspace: {parent_cwd}")
        return "\n\n".join(part for part in parts if part)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "tools": list(self.tools),
            "disallowed_tools": list(self.disallowed_tools),
            "permission_mode": self.permission_mode,
            "model": self.model,
            "provider": self.provider,
            "max_turns": self.max_turns,
            "max_tool_calls": self.max_tool_calls,
            "max_budget_usd": self.max_budget_usd,
            "allow_delegation": self.allow_delegation,
            "require_verdict": self.require_verdict,
            "acceptance_criteria": list(self.acceptance_criteria),
            "read_only_enforced": self.read_only_enforced,
            "tags": list(self.tags),
        }

    def override(self, **changes: Any) -> "AgentDefinition":
        clean = {key: value for key, value in changes.items() if value is not None and key in self.__dataclass_fields__}
        return replace(self, **clean)


VERDICT_INSTRUCTIONS = (
    "Finish with a verdict block. Emit exactly one line of the form "
    "`VERDICT: PASS` or `VERDICT: FAIL`, and list each criterion as "
    "`- [x] <criterion>` (verified) or `- [ ] <criterion>` (not verified). "
    "A PASS you cannot support with evidence is worse than a FAIL: when in doubt, FAIL."
)


# ---------------------------------------------------------------------------
# Verdict parsing: default FAIL
# ---------------------------------------------------------------------------

_VERDICT_LINE = re.compile(r"(?im)^\s*(?:final\s+)?verdict\s*[:=]\s*(?P<verdict>pass|fail(?:ed)?|accept(?:ed)?|reject(?:ed)?)\b\s*(?P<reason>.*)$")
_CRITERION_LINE = re.compile(r"(?im)^\s*(?:[-*]|\d+\.)\s*\[(?P<mark>[ xX✓✔-])\]\s*(?P<text>.+?)\s*$")
_KEYWORD_PASS = re.compile(r"(?i)\b(pass|accepted|approve)\b")
_KEYWORD_FAIL = re.compile(r"(?i)\b(fail|failed|reject|blocked)\b")
MINIMUM_JUSTIFICATION_CHARS = 40


@dataclass(frozen=True)
class CriterionResult:
    criterion: str = ""
    verified: bool = False
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"criterion": self.criterion, "verified": self.verified, "detail": self.detail}


@dataclass(frozen=True)
class Verdict:
    """Acceptance decision, with the reasons that produced it."""

    acceptance: Acceptance = "FAIL"
    explicit: bool = False
    reasons: tuple[str, ...] = ()
    criteria: tuple[CriterionResult, ...] = ()
    raw: str = ""
    agent: str = ""

    @property
    def passed(self) -> bool:
        return self.acceptance == "PASS"

    @property
    def unverified_criteria(self) -> tuple[str, ...]:
        return tuple(item.criterion for item in self.criteria if not item.verified)

    def as_dict(self) -> dict[str, Any]:
        return {
            "acceptance": self.acceptance,
            "explicit": self.explicit,
            "reasons": list(self.reasons),
            "criteria": [item.as_dict() for item in self.criteria],
            "unverified_criteria": list(self.unverified_criteria),
            "agent": self.agent,
        }

    def render(self) -> str:
        head = f"ACCEPTANCE: {self.acceptance}" + ("" if self.explicit else " (default; no explicit verdict)")
        lines = [head]
        lines.extend(f"- {reason}" for reason in self.reasons)
        if self.unverified_criteria:
            lines.append("- unverified criteria: " + ", ".join(self.unverified_criteria))
        return "\n".join(lines)


def parse_criteria(text: str) -> tuple[CriterionResult, ...]:
    results: list[CriterionResult] = []
    for match in _CRITERION_LINE.finditer(text or ""):
        mark = (match.group("mark") or " ").strip()
        verified = mark.lower() in {"x", "✓", "✔"}
        results.append(CriterionResult(criterion=match.group("text").strip(), verified=verified))
    return tuple(results)


def parse_verdict(text: Any, *, criteria: Sequence[str] = (), agent: str = "") -> Verdict:
    """Extract an acceptance verdict, defaulting to FAIL.

    A PASS survives only when it is explicit, uncontradicted, justified, and -
    when the caller supplied acceptance criteria - when every criterion is marked
    verified in the answer. Any other shape of "looks fine to me" is a FAIL, which
    is what makes the evaluator usable as a gate.
    """
    body = text if isinstance(text, str) else str(text or "")
    reasons: list[str] = []
    marks = [match for match in _VERDICT_LINE.finditer(body)]
    found_criteria = parse_criteria(body)
    explicit = bool(marks)
    if not explicit:
        reasons.append("no `VERDICT: PASS|FAIL` line was produced, so the default verdict applies")
        return Verdict("FAIL", explicit=False, reasons=tuple(reasons), criteria=found_criteria, raw=body, agent=agent)
    verdicts = {str(match.group("verdict")).lower() for match in marks}
    if any(word in verdicts for word in {"fail", "failed", "reject", "rejected"}):
        reasons.append("an explicit FAIL was recorded" + (f": {marks[-1].group('reason').strip()}" if marks[-1].group("reason") else ""))
        return Verdict("FAIL", explicit=True, reasons=tuple(reasons), criteria=found_criteria, raw=body, agent=agent)
    acceptance_pass = any(word in verdicts for word in {"pass", "accept", "accepted", "approve"})
    if not acceptance_pass:  # pragma: no cover - defensive
        reasons.append("the verdict line could not be read as a PASS")
        return Verdict("FAIL", explicit=True, reasons=tuple(reasons), criteria=found_criteria, raw=body, agent=agent)
    justification = _VERDICT_LINE.sub("", body).strip()
    if len(justification) < MINIMUM_JUSTIFICATION_CHARS:
        reasons.append(
            "a PASS must cite the evidence it rests on; the answer is too thin to audit "
            f"({len(justification)} chars of justification)"
        )
    wanted = [criterion for criterion in criteria if isinstance(criterion, str) and criterion.strip()]
    if wanted:
        reported = {item.criterion.lower(): item.verified for item in found_criteria}
        unresolved: list[str] = []
        verified_any = 0
        for criterion in wanted:
            match_key = next((key for key in reported if criterion.lower() in key or key in criterion.lower()), None)
            if match_key is None:
                unresolved.append(criterion)
            elif reported[match_key]:
                verified_any += 1
        if unresolved:
            reasons.append("no verification line for: " + ", ".join(unresolved))
        if verified_any < len(wanted):
            reasons.append(f"{len(wanted) - verified_any} of {len(wanted)} acceptance criteria are not marked verified")
    if reasons:
        return Verdict("FAIL", explicit=True, reasons=tuple(reasons), criteria=found_criteria, raw=body, agent=agent)
    return Verdict("PASS", explicit=True, reasons=("explicit PASS with every criterion verified",), criteria=found_criteria, raw=body, agent=agent)


# ---------------------------------------------------------------------------
# Built-ins and registry
# ---------------------------------------------------------------------------


def general_agent() -> AgentDefinition:
    """Full-capability worker: the shape a host normally runs."""
    return AgentDefinition(
        name="general",
        description="general-purpose worker that can inspect and change the workspace",
        prompt=(
            "Carry out the delegated task with the smallest set of tool calls that "
            "answers it, then report what changed and what you did not verify."
        ),
        tools=("Read", "Grep", "LS", "Write", "Edit", "DescribeTools"),
        permission_mode="default",
        max_turns=12,
        max_tool_calls=40,
        allow_delegation=False,
        read_only_enforced=False,
        tags={"builtin", "general"},
    )


def explorer_agent() -> AgentDefinition:
    """Read-only investigator: the safe default for "go look at this"."""
    return AgentDefinition(
        name="explorer",
        description="read-only investigator for mapping unfamiliar code",
        prompt=(
            "Locate the relevant files, quote the exact lines that matter with path:line "
            "references, and state what you could not determine."
        ),
        tools=READ_ONLY_TOOLS,
        disallowed_tools=("Write", "Edit"),
        permission_mode="default",
        max_turns=8,
        max_tool_calls=30,
        read_only_enforced=True,
        tags={"builtin", "read-only"},
    )


def planner_agent() -> AgentDefinition:
    """Plan-mode specialist: produces a proposal, touches nothing."""
    return AgentDefinition(
        name="planner",
        description="produces an implementation plan under plan-mode read-only rules",
        prompt=(
            "Produce a sequenced plan with the files each step touches and the check that "
            "proves each step. Never attempt a modification: plan mode refuses it."
        ),
        tools=READ_ONLY_TOOLS,
        disallowed_tools=("Write", "Edit"),
        permission_mode="plan",
        max_turns=6,
        max_tool_calls=20,
        tags={"builtin", "read-only", "plan"},
    )


def evaluator_agent(criteria: Sequence[str] = ()) -> AgentDefinition:
    """Acceptance gate with default-FAIL semantics.

    Only read tools, no delegation, and a verdict that must be explicit,
    justified, and criterion-complete to count as a PASS.
    """
    return AgentDefinition(
        name="evaluator",
        description="acceptance evaluator that must justify a PASS and defaults to FAIL",
        prompt=(
            "Judge the work against the acceptance criteria and the evidence you can read. "
            "Quote path:line evidence for each criterion. Do not modify anything."
        ),
        tools=READ_ONLY_TOOLS,
        disallowed_tools=("Write", "Edit", "Task"),
        permission_mode="plan",
        model="",
        max_turns=6,
        max_tool_calls=16,
        allow_delegation=False,
        require_verdict=True,
        acceptance_criteria=tuple(str(item) for item in criteria),
        read_only_enforced=True,
        tags={"builtin", "read-only", "acceptance"},
    )


def builtin_agents() -> dict[str, AgentDefinition]:
    return {
        definition.name: definition
        for definition in (general_agent(), explorer_agent(), planner_agent(), evaluator_agent())
    }


class AgentRegistry:
    """Name-keyed agent definitions with a well-known default."""

    def __init__(self, definitions: Iterable[AgentDefinition] = (), *, default: str = DEFAULT_AGENT) -> None:
        self._definitions: dict[str, AgentDefinition] = {}
        self.default_name = default
        for definition in definitions:
            self.register(definition)

    def register(self, definition: AgentDefinition, *, replace_existing: bool = True) -> AgentDefinition:
        if not isinstance(definition, AgentDefinition):
            raise TypeError("registry accepts AgentDefinition instances")
        if definition.name in self._definitions and not replace_existing:
            raise ValueError(f"agent {definition.name!r} already exists")
        self._definitions[definition.name] = definition
        return definition

    def get(self, name: str) -> AgentDefinition | None:
        return self._definitions.get(name)

    def require(self, name: str) -> AgentDefinition:
        definition = self._definitions.get(name)
        if definition is None:
            raise KeyError(f"unknown agent {name!r}; known agents: {', '.join(self.names()) or '(none)'}")
        return definition

    def default(self) -> AgentDefinition:
        return self._definitions.get(self.default_name) or general_agent()

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._definitions))

    def __contains__(self, name: object) -> bool:
        return name in self._definitions

    def __len__(self) -> int:
        return len(self._definitions)

    def __iter__(self):
        return iter(self._definitions[name] for name in self.names())

    def describe(self) -> list[dict[str, Any]]:
        return [definition.as_dict() for definition in self]

    def as_mapping(self) -> Mapping[str, AgentDefinition]:
        return dict(self._definitions)


def builtin_registry() -> AgentRegistry:
    return AgentRegistry(builtin_agents().values())


__all__ = [
    "Acceptance",
    "AgentDefinition",
    "AgentRegistry",
    "CriterionResult",
    "DEFAULT_AGENT",
    "READ_ONLY_TOOLS",
    "Verdict",
    "builtin_agents",
    "builtin_registry",
    "evaluator_agent",
    "explorer_agent",
    "general_agent",
    "parse_criteria",
    "parse_verdict",
    "planner_agent",
]
