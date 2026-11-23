"""Planner gates: subgoal ceiling, plan proposal, and critic-gated planning.

A planner that can spawn unbounded subgoals is a planner that can never be
budgeted, audited, or stopped. This module puts three hard gates in front of
any plan before an executor may touch it:

* **Subgoal ceiling** (``MAX_SUBGOALS``): a plan proposes at most five
  subgoals. Depth is how runaway behavior hides; the ceiling makes every
  plan small enough to review, price, and kill. ``propose_plan`` raises
  instead of truncating — silent truncation would change what the planner
  asked for without telling anyone.
* **Plan proposal validation**: subgoal ids must be unique, every
  ``depends_on`` edge must name a subgoal in the same plan, and
  ``estimated_steps`` must be a positive, bounded integer. A plan that
  cannot even name its own parts is not a plan.
* **Critic-gated planning**: a ``Critic`` reviews every proposal and
  returns a verdict — ``APPROVE``, ``NEEDS_REVISION``, or ``REJECT`` —
  with machine-readable reasons. The critic rejects:

  - **circular dependencies** — subgoal A waits on B waits on A; nothing
    can ever run first;
  - **unbounded loops** — a repeating subgoal with no iteration cap, or an
    ``estimated_steps`` that exceeds ``MAX_ESTIMATED_STEPS``;
  - **missing failure handling** — a subgoal with no ``on_failure``
    strategy. A plan that never says what happens when a step fails is a
    plan that fails open.

  Verdict precedence is fixed: any rejection reason wins over revision
  reasons, and any revision reason wins over approval. The critic is
  deterministic and offline: no wall-clock, no model calls, no network.

Honest scope: these are structural gates on the *shape* of a plan, not a
judgment of whether the plan is wise. A well-formed plan can still be a
bad idea; the critic checks that it is at least a *bounded, acyclic,
failure-aware* bad idea, so the runtime can price it, audit it, and stop
it. Semantic review of plan content belongs to a human approver or a
domain policy, not here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Mapping, Sequence

#: Hard ceiling on the number of subgoals in a single plan proposal.
#: The planner must decompose further work into follow-up plans, each of
#: which passes the gates again — depth becomes visible instead of hidden.
MAX_SUBGOALS = 5

#: Hard ceiling on the planner's own step estimate. A plan that claims more
#: steps than this is either unbounded or unpriceable; either way it does
#: not run.
MAX_ESTIMATED_STEPS = 200


class PlanError(ValueError):
    """Base class for plan-construction errors. Never raised directly."""


class TooManySubgoals(PlanError):
    """Raised when a proposal exceeds ``MAX_SUBGOALS``."""


class InvalidPlan(PlanError):
    """Raised when a proposal is structurally invalid."""


@dataclass(frozen=True)
class Subgoal:
    """One step of a plan.

    ``depends_on`` names other subgoal ids in the same plan that must
    complete first. ``on_failure`` names the failure-handling strategy for
    this subgoal (e.g. ``"abort"``, ``"retry:3"``, ``"escalate"``); an empty
    string means the planner said nothing about failure, which the critic
    treats as a defect. A subgoal with ``repeat=True`` runs until its exit
    condition holds and therefore *must* carry ``max_iterations`` — a
    repeating subgoal without a cap is an unbounded loop.
    """

    id: str
    description: str
    depends_on: tuple[str, ...] = ()
    on_failure: str = ""
    repeat: bool = False
    max_iterations: int | None = None

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "description": self.description,
            "depends_on": list(self.depends_on),
            "on_failure": self.on_failure,
            "repeat": self.repeat,
            "max_iterations": self.max_iterations,
        }


@dataclass(frozen=True)
class PlanProposal:
    """A planner's proposal: one goal, a bounded list of subgoals, a step estimate."""

    goal: str
    subgoals: tuple[Subgoal, ...]
    estimated_steps: int

    def as_dict(self) -> dict:
        return {
            "goal": self.goal,
            "subgoals": [s.as_dict() for s in self.subgoals],
            "estimated_steps": self.estimated_steps,
        }

    def subgoal_ids(self) -> tuple[str, ...]:
        return tuple(s.id for s in self.subgoals)


def _coerce_subgoals(subgoals: Iterable[Subgoal]) -> tuple[Subgoal, ...]:
    items = tuple(subgoals)
    for s in items:
        if not isinstance(s, Subgoal):
            raise InvalidPlan(
                f"plan subgoals must be Subgoal instances, got {type(s).__name__}"
            )
    return items


def propose_plan(
    goal: str,
    subgoals: Iterable[Subgoal],
    estimated_steps: int,
) -> PlanProposal:
    """Build a validated :class:`PlanProposal`.

    Raises :class:`TooManySubgoals` when ``len(subgoals)`` exceeds
    ``MAX_SUBGOALS`` — never silently truncates. Raises
    :class:`InvalidPlan` for an empty/blank goal, duplicate subgoal ids,
    ``depends_on`` edges naming unknown ids, a self-dependency, a
    non-positive or non-integer ``estimated_steps``, or an
    ``estimated_steps`` above ``MAX_ESTIMATED_STEPS``.
    """
    if not isinstance(goal, str) or not goal.strip():
        raise InvalidPlan("plan goal must be a non-empty string")
    items = _coerce_subgoals(subgoals)
    if len(items) > MAX_SUBGOALS:
        raise TooManySubgoals(
            f"plan proposes {len(items)} subgoals, ceiling is {MAX_SUBGOALS}; "
            "split into follow-up plans"
        )
    if isinstance(estimated_steps, bool) or not isinstance(estimated_steps, int):
        raise InvalidPlan("estimated_steps must be an integer")
    if estimated_steps <= 0:
        raise InvalidPlan("estimated_steps must be positive")
    if estimated_steps > MAX_ESTIMATED_STEPS:
        raise InvalidPlan(
            f"estimated_steps {estimated_steps} exceeds ceiling {MAX_ESTIMATED_STEPS}"
        )
    ids = [s.id for s in items]
    if len(set(ids)) != len(ids):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        raise InvalidPlan(f"duplicate subgoal ids: {dupes}")
    known = set(ids)
    for s in items:
        for dep in s.depends_on:
            if dep == s.id:
                raise InvalidPlan(f"subgoal {s.id!r} depends on itself")
            if dep not in known:
                raise InvalidPlan(
                    f"subgoal {s.id!r} depends on unknown subgoal {dep!r}"
                )
    return PlanProposal(goal=goal, subgoals=items, estimated_steps=estimated_steps)


class CriticVerdict(Enum):
    """The critic's verdict on a plan proposal."""

    APPROVE = "approve"
    NEEDS_REVISION = "needs_revision"
    REJECT = "reject"


@dataclass(frozen=True)
class CriticReview:
    """The critic's verdict plus machine-readable reasons.

    ``reasons`` uses a fixed vocabulary so callers can match on it:
    ``circular-dependency``, ``unbounded-loop``, ``unbounded-estimate``,
    ``missing-failure-handling``.
    """

    verdict: CriticVerdict
    reasons: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {"verdict": self.verdict.value, "reasons": list(self.reasons)}


def find_cycle(subgoals: Sequence[Subgoal]) -> tuple[str, ...] | None:
    """Return one dependency cycle as a tuple of subgoal ids, or ``None``.

    Depth-first search over ``depends_on`` edges; the returned tuple starts
    and ends at the same id (e.g. ``("a", "b", "a")``).
    """
    graph: dict[str, tuple[str, ...]] = {s.id: s.depends_on for s in subgoals}
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {s.id: WHITE for s in subgoals}
    stack: list[str] = []

    def visit(node: str) -> tuple[str, ...] | None:
        color[node] = GRAY
        stack.append(node)
        for dep in graph.get(node, ()):
            if dep not in color:
                continue
            if color[dep] == GRAY:
                start = stack.index(dep)
                return tuple(stack[start:] + [dep])
            if color[dep] == WHITE:
                hit = visit(dep)
                if hit is not None:
                    return hit
        stack.pop()
        color[node] = BLACK
        return None

    for s in subgoals:
        if color[s.id] == WHITE:
            hit = visit(s.id)
            if hit is not None:
                return hit
    return None


class Critic:
    """Structural critic for plan proposals.

    ``review`` is deterministic and total: it never raises on a
    well-formed :class:`PlanProposal` and always returns a
    :class:`CriticReview`. Verdict precedence is fixed — any
    ``REJECT`` reason beats ``NEEDS_REVISION``, which beats ``APPROVE``.
    """

    #: Reason vocabulary emitted in ``CriticReview.reasons``.
    REASON_CIRCULAR = "circular-dependency"
    REASON_UNBOUNDED_LOOP = "unbounded-loop"
    REASON_UNBOUNDED_ESTIMATE = "unbounded-estimate"
    REASON_MISSING_FAILURE = "missing-failure-handling"

    def review(self, plan: PlanProposal) -> CriticReview:
        if not isinstance(plan, PlanProposal):
            raise TypeError(
                f"Critic.review expects PlanProposal, got {type(plan).__name__}"
            )
        reject: list[str] = []
        revise: list[str] = []

        cycle = find_cycle(plan.subgoals)
        if cycle is not None:
            reject.append(f"{self.REASON_CIRCULAR}:{'->'.join(cycle)}")

        for s in plan.subgoals:
            if s.repeat and (s.max_iterations is None or s.max_iterations <= 0):
                reject.append(f"{self.REASON_UNBOUNDED_LOOP}:{s.id}")
        if plan.estimated_steps > MAX_ESTIMATED_STEPS:
            reject.append(
                f"{self.REASON_UNBOUNDED_ESTIMATE}:{plan.estimated_steps}"
            )

        missing = [s.id for s in plan.subgoals if not s.on_failure.strip()]
        if missing:
            revise.append(f"{self.REASON_MISSING_FAILURE}:{','.join(missing)}")

        if reject:
            return CriticReview(CriticVerdict.REJECT, tuple(reject))
        if revise:
            return CriticReview(CriticVerdict.NEEDS_REVISION, tuple(revise))
        return CriticReview(CriticVerdict.APPROVE, ())

    def plan_is_runnable(self, plan: PlanProposal) -> bool:
        """True only when the critic approves the plan outright."""
        return self.review(plan).verdict is CriticVerdict.APPROVE


def gate_plan(plan: PlanProposal, critic: Critic | None = None) -> CriticReview:
    """Convenience gate: run the critic and return its review.

    Executors should call this (or ``Critic.review``) and proceed only on
    ``CriticVerdict.APPROVE``.
    """
    return (critic or Critic()).review(plan)


if __name__ == "__main__":
    critic = Critic()
    good = propose_plan(
        "summarize inbox",
        [
            Subgoal(id="fetch", description="fetch messages", on_failure="abort"),
            Subgoal(
                id="summarize",
                description="summarize threads",
                depends_on=("fetch",),
                on_failure="escalate",
            ),
        ],
        estimated_steps=10,
    )
    review = critic.review(good)
    assert review.verdict is CriticVerdict.APPROVE, review
    print(f"planner-gates OK: ceiling={MAX_SUBGOALS}, critic approves well-formed plan")
