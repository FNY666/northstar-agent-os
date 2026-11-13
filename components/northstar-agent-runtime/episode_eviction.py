"""CWL structured context eviction: typed episodes, dependency DAG, and a
deterministic graduated eviction policy.

Source (verbatim points, all from arXiv:2606.11213, "Beyond Compaction:
Structured Context Eviction for Long-Horizon Agents", Andrew Semenov &
Svyatoslav Dorofeev, Kiz8, 2026-04-21):

* CWL (Context Window Lifecycle) has three elements: typed episodes, an
  explicit dependency graph, and a graduated eviction policy that is
  deterministic and never calls the model.
* The agent marks the trajectory with one delimiter tool whose schema is
  ``action`` "start"|"end", ``name`` (required on start), ``type``
  "expl"|"act" (required on start), ``dependencies`` (required when starting
  an "act"; must reference names of earlier "expl" chunks) and ``description``
  (required when ending an "expl" chunk, rejected when ending an "act" chunk).
* Exploratory episodes gather information; on close the agent supplies a
  summary description which is the only content retained after full eviction.
  Action episodes are the agent's actual work, their effects are durable in
  the environment, "making them the first candidates for eviction".
* The episode graph is a DAG ``G = (V, E)`` where an edge ``(u, v)`` means
  action episode ``v`` declared a dependency on exploratory episode ``u``.
  Compression removes nodes but never alters edges.  Invariants: acyclicity
  (dependencies may only reference already-closed episodes), typed edges (all
  edges run expl -> act; act->act and expl->expl "are not expressible in the
  protocol"), and prologue protection (everything predating the first
  ``start`` call is a protected prologue, "not eligible for eviction under any
  circumstances").  Active episodes (started, not ended) are "never eligible
  for eviction".
* Algorithm 1: while the counted tokens exceed the budget, pick the oldest
  ACT episode among the candidates, or the oldest EXPL episode if no ACT
  exists; candidates are closed, non-prologue, non-active episodes whose
  dependents are all fully evicted; an exploratory episode is eligible only
  once every action episode that depends on it has been fully evicted.
* Eviction levels, least destructive first: reasoning-trace stripping
  (exploratory only), bulk-output stripping, intermediate-artifact stripping,
  full episode removal.  The budget is re-checked after each level.
* User turns are preserved exactly at every level; if the budget cannot be
  met without touching user turns, the system surfaces the condition rather
  than degrading silently.
* The token budget ceiling is ``tau = 80,000`` tokens (about 30% of the
  evaluated models' context window).

Northstar extensions (designed here, not from the paper):

* the **receipt** shape (``EvictionReceipt``: episodes touched, levels
  applied, tokens freed, budget met or not) is Northstar's,
* the **integration point** with ``compaction.py`` (eviction first, summary as
  the fallback) is Northstar's -- the paper does not describe it,
* token counting uses Northstar's existing yardstick,
  ``context_budget.estimate_text_tokens`` (four UTF-8 bytes per token),
* the **single active episode** rule (a delimiter ``start`` while another
  episode is active is refused) is Northstar's: the paper says the protocol
  supports "only single linear episode streams plus dependency edges", but
  does not spell out the refusal, so Northstar refuses it rather than
  guessing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from context_budget import estimate_text_tokens

__all__ = [
    "DEFAULT_TOKEN_BUDGET",
    "DelimiterError",
    "Episode",
    "EpisodeGraph",
    "EpisodeGraphError",
    "EvictionLevel",
    "EvictionPolicy",
    "EvictionReceipt",
    "EXPL",
    "ACT",
    "STATUS_OPEN",
    "STATUS_CLOSED",
    "STATUS_EVICTED",
    "count_tokens",
    "evict_to_budget",
    "parse_delimiter_call",
]

#: The paper's budget ceiling: "tau = 80,000 tokens ... roughly 30% of the
#: evaluated models' context window".
DEFAULT_TOKEN_BUDGET = 80_000

EXPL = "expl"
ACT = "act"
EPISODE_TYPES = (EXPL, ACT)

STATUS_OPEN = "open"
STATUS_CLOSED = "closed"
STATUS_EVICTED = "evicted"


class EpisodeGraphError(RuntimeError):
    """An episode-graph invariant was violated.  Fail closed."""


class DelimiterError(EpisodeGraphError):
    """A delimiter call violated the paper's schema.  Fail closed."""


class EvictionLevel:
    """The four eviction levels, least destructive first.

    Names follow the paper's ordering: reasoning-trace stripping (exploratory
    only), bulk-output stripping, intermediate-artifact stripping, full
    episode removal.
    """

    STRIP_REASONING = "STRIP_REASONING"
    STRIP_BULK_OUTPUT = "STRIP_BULK_OUTPUT"
    STRIP_INTERMEDIATE = "STRIP_INTERMEDIATE"
    REMOVE_EPISODE = "REMOVE_EPISODE"

    #: The paper's order, least destructive first.
    ORDER = (
        STRIP_REASONING,
        STRIP_BULK_OUTPUT,
        STRIP_INTERMEDIATE,
        REMOVE_EPISODE,
    )


#: Rule texts used by the delimiter validation.  Each rejected call must
#: report which rule it broke.
RULE_ACTION = "action must be 'start' or 'end'"
RULE_START_NAME = "start requires a non-empty name"
RULE_START_TYPE = "start requires type 'expl' or 'act'"
RULE_EXPL_NO_DEPS = "expl start must not declare dependencies"
RULE_ACT_DEPS = "act start requires a non-empty dependencies list"
RULE_DEPS_TYPE = "dependencies must be a list of strings"
RULE_DEP_REF = (
    "dependency must reference an existing, closed 'expl' episode "
    "(edges run expl -> act)"
)
RULE_EXPL_DESC = "expl end requires a description"
RULE_ACT_DESC = "act end rejects a description"
RULE_ACTIVE = "an episode is already active; close it before starting another"
RULE_NO_ACTIVE = "there is no active episode to end"
RULE_WRONG_ACTIVE = "end names a different episode than the active one"


@dataclass
class Episode:
    """One typed episode of the trajectory.

    The token split mirrors the paper's eviction levels: a ``expl`` episode
    may carry a reasoning trace, any episode may carry bulk output (search
    results, directory listings) and intermediate artifacts (file reads, bash
    commands and outputs), and everything else is *core* content -- for an
    ``expl`` episode the core is the description the agent supplied on close,
    which the paper keeps as "the only content retained after full eviction".
    """

    name: str
    type: str
    dependencies: list[str] = field(default_factory=list)
    description: str | None = None
    status: str = STATUS_OPEN
    prologue: bool = False
    seq: int = 0
    reasoning_tokens: int = 0
    bulk_output_tokens: int = 0
    intermediate_tokens: int = 0
    core_tokens: int = 0
    levels_applied: list[str] = field(default_factory=list)

    @property
    def token_count(self) -> int:
        return (
            self.reasoning_tokens
            + self.bulk_output_tokens
            + self.intermediate_tokens
            + self.core_tokens
        )

    @property
    def active(self) -> bool:
        return self.status == STATUS_OPEN

    @property
    def evicted(self) -> bool:
        return self.status == STATUS_EVICTED

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "dependencies": list(self.dependencies),
            "description": self.description,
            "status": self.status,
            "prologue": self.prologue,
            "seq": self.seq,
            "token_count": self.token_count,
            "levels_applied": list(self.levels_applied),
        }


def parse_delimiter_call(call: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one delimiter tool call against the paper's schema.

    Returns the normalized call on success.  Raises :class:`DelimiterError`
    naming the broken rule otherwise -- the call is refused, never repaired.
    """

    if not isinstance(call, Mapping):
        raise DelimiterError(f"{RULE_ACTION}: call must be a mapping, got {type(call).__name__}")
    action = call.get("action")
    if action not in ("start", "end"):
        raise DelimiterError(f"{RULE_ACTION}: got {action!r}")
    name = call.get("name")
    etype = call.get("type")
    deps = call.get("dependencies")
    description = call.get("description")

    if action == "start":
        if not isinstance(name, str) or not name.strip():
            raise DelimiterError(f"{RULE_START_NAME}: got {name!r}")
        if etype not in EPISODE_TYPES:
            raise DelimiterError(f"{RULE_START_TYPE}: got {etype!r}")
        if deps is None:
            deps = []
        if not isinstance(deps, (list, tuple)):
            raise DelimiterError(f"{RULE_DEPS_TYPE}: got {type(deps).__name__}")
        deps = list(deps)
        for dep in deps:
            if not isinstance(dep, str) or not dep.strip():
                raise DelimiterError(f"{RULE_DEPS_TYPE}: got {dep!r}")
        if etype == EXPL and deps:
            raise DelimiterError(f"{RULE_EXPL_NO_DEPS}: got {deps!r}")
        if etype == ACT and not deps:
            raise DelimiterError(f"{RULE_ACT_DEPS}")
        if description is not None:
            raise DelimiterError("start rejects a description; description belongs to expl end")
        return {
            "action": "start",
            "name": name,
            "type": etype,
            "dependencies": deps,
            "description": None,
        }

    # action == "end"
    if name is not None and (not isinstance(name, str) or not name.strip()):
        raise DelimiterError(f"{RULE_START_NAME}: got {name!r}")
    return {
        "action": "end",
        "name": name,
        "type": None,
        "dependencies": [],
        "description": description,
    }


@dataclass
class UserTurn:
    """A user turn.  Never evictable (paper P3: user content is inviolable)."""

    text: str
    tokens: int = 0
    seq: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {"tokens": self.tokens, "seq": self.seq}


class EpisodeGraph:
    """The append-only typed DAG of episodes.

    Invariants enforced here (paper, "Beyond Compaction"):

    * **Acyclicity** -- a dependency may only reference an already-closed
      episode, so a cycle cannot form.
    * **Typed edges** -- every edge runs expl -> act.  act->act and
      expl->expl "are not expressible in the protocol".
    * **Prologue protection** -- content predating the first ``start`` is
      flagged ``prologue`` and is never eligible for eviction.
    * **Active protection** -- an episode that has been started but not ended
      is never eligible for eviction.
    """

    def __init__(self) -> None:
        self._episodes: dict[str, Episode] = {}
        self._order: list[str] = []
        self._user_turns: list[UserTurn] = []
        self._seq = 0

    # ------------------------------------------------------------------
    # construction
    # ------------------------------------------------------------------
    def add_prologue(self, *, name: str = "__prologue__", tokens: int = 0) -> Episode:
        """Record the protected prologue (system prompt, tool definitions,
        initial user turns).  It is closed and never evictable."""

        if name in self._episodes:
            raise EpisodeGraphError(f"duplicate episode name {name!r}")
        self._seq += 1
        ep = Episode(
            name=name,
            type=EXPL,
            dependencies=[],
            description="prologue",
            status=STATUS_CLOSED,
            prologue=True,
            seq=self._seq,
            core_tokens=int(tokens),
        )
        self._episodes[name] = ep
        self._order.append(name)
        return ep

    def add_episode(
        self,
        name: str,
        type: str,
        *,
        dependencies: Sequence[str] = (),
        reasoning_tokens: int = 0,
        bulk_output_tokens: int = 0,
        intermediate_tokens: int = 0,
        core_tokens: int = 0,
        status: str = STATUS_OPEN,
    ) -> Episode:
        """Add an episode to the graph.

        ``dependencies`` are validated here: each must name an existing,
        closed ``expl`` episode, and the new episode must be an ``act``
        (edges run expl -> act only).
        """

        if not isinstance(name, str) or not name.strip():
            raise EpisodeGraphError(f"episode name must be a non-empty string, got {name!r}")
        if type not in EPISODE_TYPES:
            raise EpisodeGraphError(f"episode type must be 'expl' or 'act', got {type!r}")
        if name in self._episodes:
            raise EpisodeGraphError(f"duplicate episode name {name!r}")
        if status not in (STATUS_OPEN, STATUS_CLOSED):
            raise EpisodeGraphError(f"episode status must be open or closed, got {status!r}")
        if type == EXPL and dependencies:
            # "Exploration episodes never declare dependencies, by design."
            raise EpisodeGraphError(
                f"{RULE_DEP_REF}: episode {name!r} is 'expl' and may not declare "
                "dependencies (edges run expl -> act)"
            )
        if dependencies:
            if type != ACT:
                raise EpisodeGraphError(
                    f"{RULE_DEP_REF}: episode {name!r} is {type!r} and may not "
                    "declare dependencies (edges run expl -> act)"
                )
            for dep in dependencies:
                self._require_closed_expl(dep, f"episode {name!r}")
        self._seq += 1
        ep = Episode(
            name=name,
            type=type,
            dependencies=list(dependencies),
            status=status,
            seq=self._seq,
            reasoning_tokens=int(reasoning_tokens),
            bulk_output_tokens=int(bulk_output_tokens),
            intermediate_tokens=int(intermediate_tokens),
            core_tokens=int(core_tokens),
        )
        self._episodes[name] = ep
        self._order.append(name)
        if status == STATUS_CLOSED:
            self._validate_dependencies(ep)
        return ep

    def close_episode(self, name: str, *, description: str | None = None) -> Episode:
        """Close an episode.

        An ``expl`` episode requires a description (the paper: the
        description "is the only content retained after full eviction"); an
        ``act`` episode rejects one.
        """

        ep = self.require(name)
        if ep.status != STATUS_OPEN:
            raise EpisodeGraphError(f"episode {name!r} is {ep.status}, not active")
        if ep.type == EXPL:
            if not isinstance(description, str) or not description.strip():
                raise DelimiterError(f"{RULE_EXPL_DESC}: episode {name!r}")
            ep.description = description
        else:
            if description is not None:
                raise DelimiterError(f"{RULE_ACT_DESC}: episode {name!r}")
        ep.status = STATUS_CLOSED
        self._validate_dependencies(ep)
        return ep

    def add_dependency(self, source: str, target: str) -> Episode:
        """Add the edge ``(source, target)``: ``target`` (an act) depends on
        ``source`` (a closed expl).  Invariants are enforced, not assumed.
        """

        src = self.require(source)
        tgt = self.require(target)
        if src.type != EXPL:
            raise EpisodeGraphError(
                f"{RULE_DEP_REF}: dependency source {source!r} is {src.type!r}, "
                "only 'expl' episodes can be depended on"
            )
        if tgt.type != ACT:
            raise EpisodeGraphError(
                f"{RULE_DEP_REF}: dependency target {target!r} is {tgt.type!r}, "
                "only 'act' episodes may declare dependencies"
            )
        if src.status != STATUS_CLOSED:
            raise EpisodeGraphError(
                f"{RULE_DEP_REF}: dependency source {source!r} is {src.status}, "
                "dependencies may only reference already-closed episodes"
            )
        if source not in tgt.dependencies:
            tgt.dependencies.append(source)
        return tgt

    def add_user_turn(self, text: str) -> UserTurn:
        """Record a user turn.  User turns are not episodes and are never
        evicted (paper P3)."""

        self._seq += 1
        turn = UserTurn(text=text, tokens=estimate_text_tokens(text), seq=self._seq)
        self._user_turns.append(turn)
        return turn

    def set_tokens(
        self,
        name: str,
        *,
        reasoning_tokens: int = 0,
        bulk_output_tokens: int = 0,
        intermediate_tokens: int = 0,
        core_tokens: int = 0,
    ) -> Episode:
        """Attach the token weight of an episode's content parts.

        The split mirrors the paper's eviction levels: reasoning trace,
        bulk output (search results, listings), intermediate artifacts
        (file reads, bash commands and outputs) and core content.
        """

        ep = self.require(name)
        ep.reasoning_tokens = int(reasoning_tokens)
        ep.bulk_output_tokens = int(bulk_output_tokens)
        ep.intermediate_tokens = int(intermediate_tokens)
        ep.core_tokens = int(core_tokens)
        return ep

    # ------------------------------------------------------------------
    # delimiter protocol
    # ------------------------------------------------------------------
    def handle_delimiter(self, call: Mapping[str, Any]) -> Episode:
        """Apply one validated delimiter call to the graph.

        The schema check is :func:`parse_delimiter_call`; this method adds
        the graph-level rules (one active episode at a time, dependencies
        must reference closed expl episodes).
        """

        parsed = parse_delimiter_call(call)
        if parsed["action"] == "start":
            etype = parsed["type"]
            deps = parsed["dependencies"]
            if etype == ACT:
                for dep in deps:
                    self._require_closed_expl(dep, f"episode {parsed['name']!r}")
            elif deps:
                raise DelimiterError(
                    f"{RULE_EXPL_NO_DEPS}: episode {parsed['name']!r} declared "
                    f"dependencies {deps!r}"
                )
            active = self.active_episode()
            if active is not None:
                raise DelimiterError(
                    f"{RULE_ACTIVE}: {active.name!r} is still active"
                )
            return self.add_episode(
                parsed["name"],
                etype,
                dependencies=deps,
            )

        active = self.active_episode()
        if active is None:
            raise DelimiterError(f"{RULE_NO_ACTIVE}")
        if parsed["name"] and parsed["name"] != active.name:
            raise DelimiterError(
                f"{RULE_WRONG_ACTIVE}: active episode is {active.name!r}, "
                f"end named {parsed['name']!r}"
            )
        return self.close_episode(active.name, description=parsed["description"])

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------
    def require(self, name: str) -> Episode:
        try:
            return self._episodes[name]
        except KeyError:
            raise EpisodeGraphError(f"unknown episode {name!r}") from None

    def get(self, name: str) -> Episode | None:
        return self._episodes.get(name)

    def active_episode(self) -> Episode | None:
        for name in self._order:
            ep = self._episodes[name]
            if ep.status == STATUS_OPEN:
                return ep
        return None

    def episodes(self) -> list[Episode]:
        return [self._episodes[name] for name in self._order]

    def user_turns(self) -> list[UserTurn]:
        return list(self._user_turns)

    def dependents(self, name: str) -> list[str]:
        """Names of the episodes that depend on ``name`` (the out-edges)."""

        return [
            ep.name
            for ep in self.episodes()
            if name in ep.dependencies and ep.status != STATUS_EVICTED
        ]

    def user_turn_tokens(self) -> int:
        return sum(turn.tokens for turn in self._user_turns)

    def token_count(self) -> int:
        return count_tokens(self)

    def as_dict(self) -> dict[str, Any]:
        return {
            "episodes": [ep.as_dict() for ep in self.episodes()],
            "user_turns": [turn.as_dict() for turn in self._user_turns],
            "tokens": count_tokens(self),
        }

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------
    def _require_closed_expl(self, name: str, context: str) -> Episode:
        ep = self._episodes.get(name)
        if ep is None:
            raise DelimiterError(
                f"{RULE_DEP_REF}: {context} depends on {name!r}, which does not exist"
            )
        if ep.type != EXPL:
            raise DelimiterError(
                f"{RULE_DEP_REF}: {context} depends on {name!r}, "
                f"which is {ep.type!r}, not 'expl'"
            )
        if ep.status != STATUS_CLOSED:
            raise DelimiterError(
                f"{RULE_DEP_REF}: {context} depends on {name!r}, "
                f"which is {ep.status}, not closed"
            )
        return ep

    def _validate_dependencies(self, ep: Episode) -> None:
        for dep in ep.dependencies:
            self._require_closed_expl(dep, f"episode {ep.name!r}")


# ----------------------------------------------------------------------
# token accounting
# ----------------------------------------------------------------------
def count_tokens(graph: EpisodeGraph) -> int:
    """Total token count of a graph: episodes + user turns.

    User turns count toward the budget but are never evictable, so a budget
    that cannot be met without touching them is reported as unmeetable
    rather than silently degraded.
    """

    total = sum(ep.token_count for ep in graph.episodes())
    return total + graph.user_turn_tokens()


def evictable_tokens(graph: EpisodeGraph) -> int:
    """Tokens that eviction may still free: everything except the protected
    prologue, active episodes and user turns."""

    total = 0
    for ep in graph.episodes():
        if ep.prologue or ep.active or ep.evicted:
            continue
        total += ep.token_count
    return total


# ----------------------------------------------------------------------
# eviction policy
# ----------------------------------------------------------------------
@dataclass
class EvictionReceipt:
    """Northstar's eviction receipt (a Northstar extension, not the paper).

    Records what was touched, at which levels, how many tokens were freed
    and whether the budget was met.
    """

    budget: int
    tokens_before: int
    tokens_after: int
    tokens_freed: int = 0
    budget_met: bool = False
    episodes_touched: list[str] = field(default_factory=list)
    levels_applied: list[str] = field(default_factory=list)
    unmeetable: bool = False
    unmeetable_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "budget": self.budget,
            "tokens_before": self.tokens_before,
            "tokens_after": self.tokens_after,
            "tokens_freed": self.tokens_freed,
            "budget_met": self.budget_met,
            "episodes_touched": list(self.episodes_touched),
            "levels_applied": list(self.levels_applied),
            "unmeetable": self.unmeetable,
            "unmeetable_reason": self.unmeetable_reason,
        }


class EvictionPolicy:
    """Algorithm 1 of the paper: graduated, deterministic, model-free.

    Each round performs the *smallest* eviction that can move the graph and
    then re-counts; the loop stops as soon as the budget is met.  When no
    candidate is left the policy reports the condition as unmeetable instead
    of degrading silently.
    """

    def __init__(self, *, budget: int = DEFAULT_TOKEN_BUDGET) -> None:
        if isinstance(budget, bool) or not isinstance(budget, int) or budget <= 0:
            raise ValueError("budget must be a positive int")
        self.budget = budget

    # ------------------------------------------------------------------
    def candidates(self, graph: EpisodeGraph) -> list[Episode]:
        """Episodes eligible for eviction right now.

        A candidate is closed, not prologue, not active, and -- for an
        ``expl`` episode -- has no live dependent: "an exploratory episode u
        is eligible only if every action episode v with (u, v) in E has
        already been fully evicted".
        """

        out: list[Episode] = []
        for ep in graph.episodes():
            if ep.prologue or ep.active or ep.evicted:
                continue
            if ep.type == EXPL and graph.dependents(ep.name):
                continue
            out.append(ep)
        return out

    def select_target(self, graph: EpisodeGraph) -> Episode | None:
        """The oldest eligible ACT episode, or the oldest eligible EXPL
        episode when no ACT is eligible."""

        cands = [ep for ep in self.candidates(graph) if self._next_level(ep) is not None]
        if not cands:
            return None
        acts = [ep for ep in cands if ep.type == ACT]
        if acts:
            return min(acts, key=lambda ep: ep.seq)
        return min(cands, key=lambda ep: ep.seq)

    def evict_to_budget(self, graph: EpisodeGraph) -> EvictionReceipt:
        """Evict until the graph fits the budget, or until nothing is left
        to evict."""

        before = count_tokens(graph)
        receipt = EvictionReceipt(
            budget=self.budget,
            tokens_before=before,
            tokens_after=before,
            budget_met=before <= self.budget,
        )
        if receipt.budget_met:
            return receipt

        while True:
            target = self.select_target(graph)
            if target is None:
                break
            level = self._next_level(target)
            if level is None:
                break
            freed = self._apply_level(target, level)
            target.levels_applied.append(level)
            receipt.levels_applied.append(level)
            if target.name not in receipt.episodes_touched:
                receipt.episodes_touched.append(target.name)
            receipt.tokens_freed += freed
            after = count_tokens(graph)
            receipt.tokens_after = after
            if after <= self.budget:
                receipt.budget_met = True
                break

        if not receipt.budget_met:
            receipt.unmeetable = True
            receipt.unmeetable_reason = self._unmeetable_reason(graph)
        return receipt

    # ------------------------------------------------------------------
    def _next_level(self, ep: Episode) -> str | None:
        """The next applicable level for one episode, least destructive
        first: reasoning trace (expl only), bulk output, intermediate
        artifact, then full removal.

        One level per round: the paper re-checks the budget "after each
        applicable strip", so a round applies exactly one level.
        """

        if ep.evicted:
            return None
        for level in EvictionLevel.ORDER:
            if self._level_applicable(ep, level):
                return level
        return None

    def _level_applicable(self, ep: Episode, level: str) -> bool:
        if level == EvictionLevel.STRIP_REASONING:
            return ep.type == EXPL and ep.reasoning_tokens > 0
        if level == EvictionLevel.STRIP_BULK_OUTPUT:
            return ep.bulk_output_tokens > 0
        if level == EvictionLevel.STRIP_INTERMEDIATE:
            return ep.intermediate_tokens > 0
        if level == EvictionLevel.REMOVE_EPISODE:
            # Removal frees the episode itself, not only its tokens: an
            # episode whose parts were already stripped is still a live
            # dependent, and removing it is what unblocks its explorers.
            return not ep.evicted
        return False

    def _apply_level(self, ep: Episode, level: str) -> int:
        if level == EvictionLevel.STRIP_REASONING:
            freed = ep.reasoning_tokens
            ep.reasoning_tokens = 0
            return freed
        if level == EvictionLevel.STRIP_BULK_OUTPUT:
            freed = ep.bulk_output_tokens
            ep.bulk_output_tokens = 0
            return freed
        if level == EvictionLevel.STRIP_INTERMEDIATE:
            freed = ep.intermediate_tokens
            ep.intermediate_tokens = 0
            return freed
        if level == EvictionLevel.REMOVE_EPISODE:
            freed = ep.token_count
            ep.reasoning_tokens = 0
            ep.bulk_output_tokens = 0
            ep.intermediate_tokens = 0
            ep.core_tokens = 0
            ep.status = STATUS_EVICTED
            return freed
        return 0

    def _unmeetable_reason(self, graph: EpisodeGraph) -> str:
        protected = []
        for ep in graph.episodes():
            if ep.prologue:
                protected.append(f"prologue {ep.name!r}")
            elif ep.active:
                protected.append(f"active episode {ep.name!r}")
        if graph.user_turn_tokens():
            protected.append(
                f"{graph.user_turn_tokens()} user-turn tokens "
                "(user content is inviolable)"
            )
        if protected:
            return (
                "budget cannot be met without touching protected content: "
                + "; ".join(protected)
            )
        return "no eligible candidate remains"


def evict_to_budget(
    graph: EpisodeGraph, budget: int = DEFAULT_TOKEN_BUDGET
) -> EvictionReceipt:
    """Module-level convenience wrapper around :class:`EvictionPolicy`."""

    return EvictionPolicy(budget=budget).evict_to_budget(graph)
