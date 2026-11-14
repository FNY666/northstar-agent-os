"""Effort scaling: task complexity -> parallelism budget (orchestrator-worker).

Northstar had ``planner_gates.py`` (plan shape), ``budget.py`` (money),
``compute_budget.py`` (signed compute ceilings), ``agents.py`` (subagent
definitions) and ``multi_agent.py`` (a coordination ledger) -- but no
*explicit* mapping from "how hard is this task" to "how much parallelism
should the host spend". This module is that mapping.

Source of the mechanism (Anthropic Engineering, "How we built our
multi-agent research system", Jeremy Hadfield et al., 2025-06-13,
https://www.anthropic.com/research/multi-agent-research-system). Verbatim
rules from that article are marked ``[Anthropic]`` below; everything else is
a Northstar extension and marked ``[Northstar]``.

[Anthropic] Effort-scaling table (query complexity -> agent count):

    "Simple fact-finding requires just 1 agent with 3-10 tool calls"
    "direct comparisons might need 2-4 subagents with 10-15 calls each"
    "complex research might use more than 10 subagents with clearly divided
    responsibilities"

[Anthropic] Two levels of parallelization:

    "the lead agent spins up 3-5 subagents in parallel rather than serially"
    "the subagents use 3+ tools in parallel"
    "These changes cut research time by up to 90% for complex queries"

[Anthropic] Where multi-agent fits -- and where it does not:

    "multi-agent systems excel at valuable tasks that involve heavy
    parallelization"
    "information that exceeds single context windows"
    "require all agents to share the same context"
    "involve many dependencies between agents are not a good fit for
    multi-agent systems today"
    "most coding tasks involve fewer truly parallelizable tasks than research"

[Anthropic] Compression via subagents:

    "Subagents facilitate compression by operating in parallel with their own
    context windows"

[Anthropic] Token economics (background only, NOT an acceptance criterion
of this slice):

    "agents typically use about 4x more tokens than chat interactions"
    "multi-agent systems use about 15x more tokens than chats"

[Anthropic] Orchestrator-prompt sensitivity:

    "small changes to the lead agent can unpredictably change how subagents
    behave"

Northstar extensions (NOT Anthropic content):

- [Northstar] ``classify_complexity`` -- the rule that turns a Northstar
  task description (independent directions, information volume vs. a single
  context window, tool complexity, dependency degree) into
  Simple/Moderate/Complex. Anthropic states the *bands*; it does not ship a
  Northstar-shaped classifier.
- [Northstar] The tool-call budget interface (per-agent band, total ceiling,
  ``clamp`` against a remaining call budget) -- the seam where this mapping
  meets ``budget.py`` / ``agents.py`` ceilings. This module never imports or
  mutates those modules; it only computes the numbers a host should enforce.
- [Northstar] The window-card degradation rule: when the requested parallel
  scale exceeds the host's context-window card cap, the mapping is degraded
  *for this call only* to the number of cards. The cap itself is never
  changed here.
- [Northstar] The concrete subagent counts picked inside Anthropic's bands
  (Moderate -> 4, Complex -> 12) and the two-tier bump rule of the
  classifier.

Public API:

- ``TaskSignals`` -- the four complexity inputs plus the three
  applicability inputs.
- ``classify_complexity(signals)`` -> ``ComplexityAssessment`` (tier +
  reasons).
- ``check_applicability(signals)`` -> ``Applicability`` (multi-agent
  applicable? degradation reasons).
- ``EFFORT_SCALING_TABLE`` / ``effort_scaling_for(tier)`` -> ``EffortScaling``
  (the Anthropic bands).
- ``parallel_plan_for(scaling, window_cards=...)`` -> ``ParallelPlan``
  (the two levels of parallelization + the card degradation).
- ``plan_effort(signals, ...)`` -> ``EffortPlan`` -- the whole mapping in
  one call.

Honest scope: this module computes a mapping. It spawns no agent, runs no
LLM, spends no budget and changes no cap. The parallelism it returns is a
*declared plan*, not an observed execution.

Version pin: ``effort-scaling.v1`` / schema pin
``northstar.effort-scaling.v1``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Tuple

#: Version pin for this module's record shapes.
EFFORT_SCALING_VERSION = "effort-scaling.v1"

#: Schema pin carried by the plan records.
EFFORT_SCALING_SCHEMA = "northstar.effort-scaling.v1"

# --- complexity tiers --------------------------------------------------------

COMPLEXITY_SIMPLE = "simple"
COMPLEXITY_MODERATE = "moderate"
COMPLEXITY_COMPLEX = "complex"

#: The three tiers, weakest first.
COMPLEXITIES: Tuple[str, ...] = (
    COMPLEXITY_SIMPLE,
    COMPLEXITY_MODERATE,
    COMPLEXITY_COMPLEX,
)

_TIER_RANK = {
    COMPLEXITY_SIMPLE: 0,
    COMPLEXITY_MODERATE: 1,
    COMPLEXITY_COMPLEX: 2,
}

# --- dependency degrees ------------------------------------------------------

DEPENDENCY_NONE = "none"
DEPENDENCY_SOME = "some"
DEPENDENCY_HIGH = "high"

#: The three dependency degrees, weakest first.
DEPENDENCY_LEVELS: Tuple[str, ...] = (
    DEPENDENCY_NONE,
    DEPENDENCY_SOME,
    DEPENDENCY_HIGH,
)

# --- classifier thresholds (all [Northstar]) ---------------------------------

#: At most this many independent directions keeps a task in the Simple band.
SIMPLE_MAX_DIRECTIONS = 1

#: At most this many independent directions keeps a task in the Moderate band.
MODERATE_MAX_DIRECTIONS = 4

#: A task offering at least this many distinct complex tools is bumped one tier.
COMPLEX_TOOL_COMPLEXITY = 3

#: The host's context-window card cap. This module never changes it.
WINDOW_CARD_LIMIT = 3

#: Concrete subagent count used when mapping Anthropic's Moderate band.
MODERATE_DEFAULT_SUBAGENTS = 4

#: Concrete subagent count used when mapping Anthropic's Complex band.
COMPLEX_DEFAULT_SUBAGENTS = 12

# --- Anthropic numbers (verbatim, see module docstring) ---------------------

#: [Anthropic] "the lead agent spins up 3-5 subagents in parallel".
LEAD_PARALLEL_SPAWN_MIN = 3
LEAD_PARALLEL_SPAWN_MAX = 5

#: [Anthropic] "the subagents use 3+ tools in parallel".
TOOLS_PER_SUBAGENT_MIN = 3


class EffortScalingError(ValueError):
    """Raised when a mapping input is malformed (fail-closed)."""


def _check_positive_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise EffortScalingError(f"{name} must be a positive int, got {value!r}")
    return value


def _check_non_negative_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EffortScalingError(f"{name} must be a non-negative int, got {value!r}")
    return value


# --- inputs ------------------------------------------------------------------


@dataclass(frozen=True)
class TaskSignals:
    """The declared shape of a Northstar task, as the classifier sees it.

    Complexity inputs:

    - ``independent_directions``: how many genuinely independent lines of
      investigation the task has.
    - ``info_exceeds_context_window``: whether the information needed exceeds
      a single context window.
    - ``tool_complexity``: how many distinct complex tools the task needs.
    - ``dependency_degree``: ``none`` / ``some`` / ``high``.

    Applicability inputs (the multi-agent gate):

    - ``shared_context_required``: every agent must see the same context.
    - ``truly_parallelizable``: the work can actually be split and run at the
      same time.
    """

    independent_directions: int = 1
    info_exceeds_context_window: bool = False
    tool_complexity: int = 1
    dependency_degree: str = DEPENDENCY_NONE
    shared_context_required: bool = False
    truly_parallelizable: bool = True

    def __post_init__(self) -> None:
        _check_non_negative_int("independent_directions", self.independent_directions)
        _check_non_negative_int("tool_complexity", self.tool_complexity)
        if self.dependency_degree not in DEPENDENCY_LEVELS:
            raise EffortScalingError(
                f"dependency_degree must be one of {list(DEPENDENCY_LEVELS)}, "
                f"got {self.dependency_degree!r}"
            )
        for flag in (
            "info_exceeds_context_window",
            "shared_context_required",
            "truly_parallelizable",
        ):
            if not isinstance(getattr(self, flag), bool):
                raise EffortScalingError(f"{flag} must be a bool")

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "independent_directions": self.independent_directions,
            "info_exceeds_context_window": self.info_exceeds_context_window,
            "tool_complexity": self.tool_complexity,
            "dependency_degree": self.dependency_degree,
            "shared_context_required": self.shared_context_required,
            "truly_parallelizable": self.truly_parallelizable,
        }


# --- classification ----------------------------------------------------------


@dataclass(frozen=True)
class ComplexityAssessment:
    """The graded tier plus the reasons that produced it."""

    complexity: str
    reasons: Tuple[str, ...] = ()
    signals: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.complexity not in COMPLEXITIES:
            raise EffortScalingError(
                f"complexity must be one of {list(COMPLEXITIES)}, got {self.complexity!r}"
            )
        object.__setattr__(self, "reasons", tuple(self.reasons))
        object.__setattr__(self, "signals", dict(self.signals))

    @property
    def rank(self) -> int:
        """0 for simple, 1 for moderate, 2 for complex."""
        return _TIER_RANK[self.complexity]

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "complexity": self.complexity,
            "reasons": list(self.reasons),
            "signals": dict(self.signals),
            "schema": EFFORT_SCALING_SCHEMA,
        }


def classify_complexity(signals: TaskSignals) -> ComplexityAssessment:
    """Grade a task as simple / moderate / complex. [Northstar]

    The rule, stated so it is testable:

    1. Start at ``simple``.
    2. ``independent_directions`` in ``[2, 4]`` raises the tier to
       ``moderate``; ``>= 5`` raises it to ``complex``.
    3. ``info_exceeds_context_window`` raises the tier to at least
       ``moderate``.
    4. ``tool_complexity >= 3`` raises the tier one step (capped at
       ``complex``).
    5. ``dependency_degree == "high"`` caps the tier at ``moderate`` -- a
       task whose agents all depend on each other is not a "complex
       research" shape.

    The band edges are inclusive on both ends: exactly 1 direction is
    simple, exactly 2 is moderate, exactly 4 is moderate, exactly 5 is
    complex.
    """
    if not isinstance(signals, TaskSignals):
        raise EffortScalingError("signals must be a TaskSignals instance")

    reasons = []
    directions = signals.independent_directions
    if directions <= SIMPLE_MAX_DIRECTIONS:
        tier = COMPLEXITY_SIMPLE
        reasons.append(
            f"{directions} independent direction(s): at most {SIMPLE_MAX_DIRECTIONS}, "
            "so the task stays in the simple band"
        )
    elif directions <= MODERATE_MAX_DIRECTIONS:
        tier = COMPLEXITY_MODERATE
        reasons.append(
            f"{directions} independent directions: between {SIMPLE_MAX_DIRECTIONS + 1} "
            f"and {MODERATE_MAX_DIRECTIONS}, so the task lands in the moderate band"
        )
    else:
        tier = COMPLEXITY_COMPLEX
        reasons.append(
            f"{directions} independent directions: more than {MODERATE_MAX_DIRECTIONS}, "
            "so the task lands in the complex band"
        )

    if signals.info_exceeds_context_window:
        reasons.append(
            "the information needed exceeds a single context window, which "
            "raises the tier to at least moderate"
        )
        if tier == COMPLEXITY_SIMPLE:
            tier = COMPLEXITY_MODERATE

    if signals.tool_complexity >= COMPLEX_TOOL_COMPLEXITY:
        reasons.append(
            f"{signals.tool_complexity} distinct complex tools (at least "
            f"{COMPLEX_TOOL_COMPLEXITY}): raises the tier one step"
        )
        if tier == COMPLEXITY_SIMPLE:
            tier = COMPLEXITY_MODERATE
        elif tier == COMPLEXITY_MODERATE:
            tier = COMPLEXITY_COMPLEX

    if signals.dependency_degree == DEPENDENCY_HIGH:
        reasons.append(
            "high dependency degree: the tier is capped at moderate because "
            "agents with many inter-dependencies are not a research shape"
        )
        if tier == COMPLEXITY_COMPLEX:
            tier = COMPLEXITY_MODERATE

    return ComplexityAssessment(
        complexity=tier,
        reasons=tuple(reasons),
        signals=signals.as_dict(),
    )


# --- the Anthropic effort-scaling table --------------------------------------


@dataclass(frozen=True)
class EffortScaling:
    """One row of Anthropic's effort-scaling table, plus its Northstar mapping.

    The ``min_*`` / ``max_*`` fields are Anthropic's numbers verbatim; the
    ``subagent_count`` / ``tools_per_subagent`` fields are this slice's
    concrete choice inside those bands.
    """

    complexity: str
    #: Anthropic: agent count band ("1", "2-4", "10+").
    agent_band: str
    #: Anthropic: tool calls per agent band.
    tool_calls_band: str
    #: Concrete subagent count chosen inside the band.
    subagent_count: int
    #: Concrete per-subagent tool-call count chosen inside the band.
    tools_per_subagent: int
    #: Anthropic's prose for the row (verbatim).
    source_quote: str
    #: How the row's work is divided among the agents.
    division_of_labour: str = ""

    def __post_init__(self) -> None:
        if self.complexity not in COMPLEXITIES:
            raise EffortScalingError(
                f"complexity must be one of {list(COMPLEXITIES)}, got {self.complexity!r}"
            )
        _check_positive_int("subagent_count", self.subagent_count)
        _check_non_negative_int("tools_per_subagent", self.tools_per_subagent)

    @property
    def is_multi_agent(self) -> bool:
        """True when the row asks for more than one agent."""
        return self.subagent_count > 1

    def total_tool_calls(self) -> int:
        """The row's total tool-call ceiling across all agents."""
        return self.subagent_count * self.tools_per_subagent

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "complexity": self.complexity,
            "agent_band": self.agent_band,
            "tool_calls_band": self.tool_calls_band,
            "subagent_count": self.subagent_count,
            "tools_per_subagent": self.tools_per_subagent,
            "source_quote": self.source_quote,
            "division_of_labour": self.division_of_labour,
            "total_tool_calls": self.total_tool_calls(),
            "schema": EFFORT_SCALING_SCHEMA,
        }


#: [Anthropic] The effort-scaling table, with Anthropic's bands verbatim.
EFFORT_SCALING_TABLE: Mapping[str, EffortScaling] = {
    COMPLEXITY_SIMPLE: EffortScaling(
        complexity=COMPLEXITY_SIMPLE,
        agent_band="1",
        tool_calls_band="3-10",
        subagent_count=1,
        tools_per_subagent=3,
        source_quote="Simple fact-finding requires just 1 agent with 3-10 tool calls",
        division_of_labour="one agent does the whole task; no subagent is spawned",
    ),
    COMPLEXITY_MODERATE: EffortScaling(
        complexity=COMPLEXITY_MODERATE,
        agent_band="2-4",
        tool_calls_band="10-15",
        subagent_count=MODERATE_DEFAULT_SUBAGENTS,
        tools_per_subagent=10,
        source_quote=(
            "direct comparisons might need 2-4 subagents with 10-15 calls each"
        ),
        division_of_labour=(
            "2-4 subagents with clearly divided responsibilities: each one owns "
            "one direction of the comparison"
        ),
    ),
    COMPLEXITY_COMPLEX: EffortScaling(
        complexity=COMPLEXITY_COMPLEX,
        agent_band="10+",
        tool_calls_band="not stated in the source",
        subagent_count=COMPLEX_DEFAULT_SUBAGENTS,
        tools_per_subagent=10,
        source_quote=(
            "complex research might use more than 10 subagents with clearly "
            "divided responsibilities"
        ),
        division_of_labour=(
            "10+ subagents with clearly divided responsibilities: each one owns "
            "a slice of the search space and returns a compressed finding"
        ),
    ),
}


def effort_scaling_for(complexity: str) -> EffortScaling:
    """The table row for a tier. [Anthropic] bands, [Northstar] counts."""
    if complexity not in EFFORT_SCALING_TABLE:
        raise EffortScalingError(
            f"unknown complexity {complexity!r}; known: {list(COMPLEXITIES)}"
        )
    return EFFORT_SCALING_TABLE[complexity]


# --- applicability gate --------------------------------------------------------

#: Degradation reason: every agent must share the same context.
REASON_SHARED_CONTEXT = "shared_context_required"
#: Degradation reason: many dependencies between agents.
REASON_DEPENDENCIES = "agent_dependencies"
#: Degradation reason: the work cannot actually be run in parallel.
REASON_NOT_PARALLELIZABLE = "not_truly_parallelizable"


@dataclass(frozen=True)
class Applicability:
    """Whether a multi-agent shape fits this task at all.

    ``applicable`` is False when at least one Anthropic-documented
    disqualifier holds; ``reasons`` then names every one of them.
    """

    applicable: bool
    reasons: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.applicable, bool):
            raise EffortScalingError("applicable must be a bool")
        object.__setattr__(self, "reasons", tuple(self.reasons))

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "applicable": self.applicable,
            "reasons": list(self.reasons),
            "schema": EFFORT_SCALING_SCHEMA,
        }


def check_applicability(signals: TaskSignals) -> Applicability:
    """The multi-agent gate. [Anthropic] disqualifiers, [Northstar] plumbing.

    Anthropic names three shapes where a multi-agent system is the wrong
    tool (verbatim in the module docstring):

    - agents that "require all agents to share the same context";
    - tasks that "involve many dependencies between agents";
    - work that is not truly parallelizable.

    When any of them holds, the caller must fall back to a single agent.
    """
    if not isinstance(signals, TaskSignals):
        raise EffortScalingError("signals must be a TaskSignals instance")

    reasons = []
    if signals.shared_context_required:
        reasons.append(REASON_SHARED_CONTEXT)
    if signals.dependency_degree == DEPENDENCY_HIGH:
        reasons.append(REASON_DEPENDENCIES)
    if not signals.truly_parallelizable:
        reasons.append(REASON_NOT_PARALLELIZABLE)

    return Applicability(applicable=not reasons, reasons=tuple(reasons))


# --- two-level parallelization ------------------------------------------------


@dataclass(frozen=True)
class ParallelPlan:
    """The two levels of parallelization, plus any card degradation.

    Level 1 -- ``parallel_spawn_count``: how many subagents the lead agent
    creates at the same time ("the lead agent spins up 3-5 subagents in
    parallel rather than serially"). For a single-agent row it is 1.

    Level 2 -- ``tools_per_subagent``: how many tools each subagent uses at
    the same time ("the subagents use 3+ tools in parallel").

    ``degraded`` is True when the requested scale exceeded the host's
    context-window card cap and the mapping was reduced *for this call
    only*. The cap itself is never touched.
    """

    subagent_count: int
    tools_per_subagent: int
    parallel_spawn_count: int
    window_cards: int
    degraded: bool = False
    degradation_reasons: Tuple[str, ...] = ()
    requested_subagent_count: int = 0

    def __post_init__(self) -> None:
        _check_positive_int("subagent_count", self.subagent_count)
        _check_non_negative_int("tools_per_subagent", self.tools_per_subagent)
        _check_positive_int("parallel_spawn_count", self.parallel_spawn_count)
        _check_positive_int("window_cards", self.window_cards)
        object.__setattr__(self, "degradation_reasons", tuple(self.degradation_reasons))

    @property
    def scale(self) -> Tuple[int, int]:
        """The ``(subagent_count, tools_per_subagent)`` pair."""
        return (self.subagent_count, self.tools_per_subagent)

    @property
    def total_tool_calls(self) -> int:
        return self.subagent_count * self.tools_per_subagent

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "subagent_count": self.subagent_count,
            "tools_per_subagent": self.tools_per_subagent,
            "parallel_spawn_count": self.parallel_spawn_count,
            "window_cards": self.window_cards,
            "degraded": self.degraded,
            "degradation_reasons": list(self.degradation_reasons),
            "requested_subagent_count": self.requested_subagent_count,
            "total_tool_calls": self.total_tool_calls,
            "schema": EFFORT_SCALING_SCHEMA,
        }


def parallel_plan_for(
    scaling: EffortScaling,
    *,
    window_cards: int = WINDOW_CARD_LIMIT,
) -> ParallelPlan:
    """Map a table row onto the two levels of parallelization.

    [Anthropic] Level 1: the lead agent spawns ``3-5`` subagents in
    parallel; for a row that asks for fewer subagents than that, the lead
    spawns exactly as many as the row asks for.

    [Anthropic] Level 2: each subagent uses ``3+`` tools in parallel. A row
    whose own per-agent tool band is narrower than 3 (the Simple row's
    "3-10 tool calls") is clamped up to the parallel floor of 3, because a
    single-agent row performs its calls in parallel with itself.

    [Northstar] Card degradation: when ``scaling.subagent_count`` exceeds
    ``window_cards``, the plan is reduced to ``window_cards`` subagents and
    the degradation is recorded. The cap is not changed by this module.
    """
    if not isinstance(scaling, EffortScaling):
        raise EffortScalingError("scaling must be an EffortScaling instance")
    _check_positive_int("window_cards", window_cards)

    requested = scaling.subagent_count
    subagents = requested
    reasons: list = []

    if requested > window_cards:
        subagents = window_cards
        reasons.append(
            f"requested {requested} subagents exceeds the {window_cards} "
            f"context-window cards; degraded to {window_cards} for this call "
            "only (the cap itself is unchanged)"
        )

    if subagents <= 1:
        parallel_spawn = 1
    elif subagents < LEAD_PARALLEL_SPAWN_MIN:
        parallel_spawn = subagents
        reasons.append(
            f"only {subagents} subagent(s) fit, below Anthropic's "
            f"{LEAD_PARALLEL_SPAWN_MIN}-5 parallel spawn band"
        )
    else:
        parallel_spawn = min(LEAD_PARALLEL_SPAWN_MAX, subagents)

    tools = max(scaling.tools_per_subagent, TOOLS_PER_SUBAGENT_MIN)

    return ParallelPlan(
        subagent_count=subagents,
        tools_per_subagent=tools,
        parallel_spawn_count=parallel_spawn,
        window_cards=window_cards,
        degraded=requested > window_cards,
        degradation_reasons=tuple(reasons),
        requested_subagent_count=requested,
    )


# --- the whole mapping in one call --------------------------------------------


@dataclass(frozen=True)
class EffortPlan:
    """The complete mapping for one task.

    ``multi_agent`` is False when the applicability gate closed; the plan
    then holds a single agent plus the degradation reasons -- it never
    hard-codes a multi-agent shape onto an inapplicable task.
    """

    assessment: ComplexityAssessment
    applicability: Applicability
    scaling: EffortScaling
    parallel: ParallelPlan
    multi_agent: bool
    degradation_reasons: Tuple[str, ...] = ()
    remaining_tool_call_budget: Optional[int] = None
    tool_calls_clamped: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "degradation_reasons", tuple(self.degradation_reasons))

    @property
    def scale(self) -> Tuple[int, int]:
        """The ``(subagent_count, tools_per_subagent)`` pair actually planned."""
        return self.parallel.scale

    @property
    def parallel_spawn_count(self) -> int:
        """How many subagents the lead agent creates at the same time."""
        return self.parallel.parallel_spawn_count

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "assessment": self.assessment.as_dict(),
            "applicability": self.applicability.as_dict(),
            "scaling": self.scaling.as_dict(),
            "parallel": self.parallel.as_dict(),
            "multi_agent": self.multi_agent,
            "degradation_reasons": list(self.degradation_reasons),
            "remaining_tool_call_budget": self.remaining_tool_call_budget,
            "tool_calls_clamped": self.tool_calls_clamped,
            "scale": list(self.scale),
            "schema": EFFORT_SCALING_SCHEMA,
        }


def plan_effort(
    signals: TaskSignals,
    *,
    window_cards: int = WINDOW_CARD_LIMIT,
    remaining_tool_call_budget: Optional[int] = None,
) -> EffortPlan:
    """Grade the task, gate it, map it, and (optionally) clamp the budget.

    The order matters and is the point:

    1. ``classify_complexity`` grades the task.
    2. ``check_applicability`` decides whether a multi-agent shape fits at
       all. When it does not, the plan is a single agent and the reasons
       are recorded -- the tier is *not* silently honoured.
    3. ``effort_scaling_for`` gives the table row.
    4. ``parallel_plan_for`` gives the two levels of parallelization and
       applies the card degradation.

    [Northstar] ``remaining_tool_call_budget`` is the seam to
    ``budget.py`` / ``agents.py`` ceilings: when the row's total tool-call
    count exceeds what is left, the per-agent tool count is clamped down
    and ``tool_calls_clamped`` is set. This module never touches a budget
    object; it only computes the number a host should enforce.
    """
    if not isinstance(signals, TaskSignals):
        raise EffortScalingError("signals must be a TaskSignals instance")
    if remaining_tool_call_budget is not None:
        _check_non_negative_int(
            "remaining_tool_call_budget", remaining_tool_call_budget
        )

    assessment = classify_complexity(signals)
    applicability = check_applicability(signals)
    scaling = effort_scaling_for(assessment.complexity)

    if not applicability.applicable:
        single = EffortScaling(
            complexity=scaling.complexity,
            agent_band="1",
            tool_calls_band=scaling.tool_calls_band,
            subagent_count=1,
            tools_per_subagent=scaling.tools_per_subagent,
            source_quote=scaling.source_quote,
            division_of_labour=(
                "single agent: the multi-agent shape does not fit this task"
            ),
        )
        parallel = ParallelPlan(
            subagent_count=1,
            tools_per_subagent=single.tools_per_subagent,
            parallel_spawn_count=1,
            window_cards=window_cards,
            degraded=True,
            degradation_reasons=applicability.reasons,
            requested_subagent_count=scaling.subagent_count,
        )
        return EffortPlan(
            assessment=assessment,
            applicability=applicability,
            scaling=single,
            parallel=parallel,
            multi_agent=False,
            degradation_reasons=applicability.reasons,
        )

    parallel = parallel_plan_for(scaling, window_cards=window_cards)

    clamped = False
    remaining = remaining_tool_call_budget
    if remaining is not None and parallel.total_tool_calls > remaining:
        clamped = True
        per_agent = remaining // parallel.subagent_count
        tools = max(1, min(parallel.tools_per_subagent, per_agent))
        parallel = ParallelPlan(
            subagent_count=parallel.subagent_count,
            tools_per_subagent=tools,
            parallel_spawn_count=parallel.parallel_spawn_count,
            window_cards=parallel.window_cards,
            degraded=True,
            degradation_reasons=parallel.degradation_reasons
            + (
                f"the row's {parallel.total_tool_calls} tool calls exceed the "
                f"remaining budget of {remaining}; clamped to {tools} per agent",
            ),
            requested_subagent_count=parallel.requested_subagent_count,
        )
        remaining = remaining

    return EffortPlan(
        assessment=assessment,
        applicability=applicability,
        scaling=scaling,
        parallel=parallel,
        multi_agent=parallel.subagent_count > 1,
        degradation_reasons=parallel.degradation_reasons,
        remaining_tool_call_budget=remaining,
        tool_calls_clamped=clamped,
    )


__all__ = [
    "COMPLEXITIES",
    "COMPLEXITY_COMPLEX",
    "COMPLEXITY_MODERATE",
    "COMPLEXITY_SIMPLE",
    "COMPLEX_DEFAULT_SUBAGENTS",
    "COMPLEX_TOOL_COMPLEXITY",
    "DEPENDENCY_HIGH",
    "DEPENDENCY_LEVELS",
    "DEPENDENCY_NONE",
    "DEPENDENCY_SOME",
    "EFFORT_SCALING_SCHEMA",
    "EFFORT_SCALING_TABLE",
    "EFFORT_SCALING_VERSION",
    "LEAD_PARALLEL_SPAWN_MAX",
    "LEAD_PARALLEL_SPAWN_MIN",
    "MODERATE_DEFAULT_SUBAGENTS",
    "REASON_DEPENDENCIES",
    "REASON_NOT_PARALLELIZABLE",
    "REASON_SHARED_CONTEXT",
    "TOOLS_PER_SUBAGENT_MIN",
    "WINDOW_CARD_LIMIT",
    "Applicability",
    "ComplexityAssessment",
    "EffortPlan",
    "EffortScaling",
    "EffortScalingError",
    "ParallelPlan",
    "TaskSignals",
    "check_applicability",
    "classify_complexity",
    "effort_scaling_for",
    "parallel_plan_for",
    "plan_effort",
]


def main() -> None:
    """Drive the three real paths end to end."""
    simple = plan_effort(TaskSignals(independent_directions=1, tool_complexity=1))
    assert simple.assessment.complexity == COMPLEXITY_SIMPLE
    assert simple.scaling.subagent_count == 1
    assert simple.scale == (1, 3)
    assert not simple.multi_agent

    complex_task = plan_effort(
        TaskSignals(
            independent_directions=9,
            info_exceeds_context_window=True,
            tool_complexity=4,
        )
    )
    assert complex_task.assessment.complexity == COMPLEXITY_COMPLEX
    assert complex_task.scaling.subagent_count >= 10
    assert 3 <= complex_task.parallel_spawn_count <= 5
    assert complex_task.parallel.tools_per_subagent >= 3
    assert complex_task.parallel.degraded  # 12 subagents vs 3 cards
    assert complex_task.parallel.subagent_count == WINDOW_CARD_LIMIT

    inapplicable = plan_effort(
        TaskSignals(
            independent_directions=9,
            shared_context_required=True,
            dependency_degree=DEPENDENCY_HIGH,
            truly_parallelizable=False,
        )
    )
    assert not inapplicable.multi_agent
    assert inapplicable.parallel.subagent_count == 1
    assert len(inapplicable.degradation_reasons) == 3

    print("effort-scaling OK: classify, map, gate, degrade")


if __name__ == "__main__":
    main()
