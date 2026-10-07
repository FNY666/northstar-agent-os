"""Planner + per-call budget composition: a plan must be priced to be proposed.

``planner_gates`` keeps plans structurally bounded; ``per_call_budget``
keeps individual calls and the run ceiling in dollars. This module wires
them together so a planner cannot propose what the run cannot afford:

* **Structure first** — ``propose_plan`` still validates shape. Structural
  defects raise ``PlanRefused`` with ``guard="structure"`` instead of the
  raw ``PlanError``; the planner sees one uniform refusal contract.
* **Critic second** — a plan that is not ``APPROVE``d is refused with
  ``guard="critic"``. Only approved plans reach the money.
* **Budget last** — every subgoal must carry a priced cost. An unpriced
  subgoal is refused, not defaulted to zero: a planner that cannot say
  what a step costs cannot ask for it. Per-call ceilings apply per
  subgoal; the run ceiling applies to the plan total.

Two-phase accounting closes the double-spend window between proposing a
plan and executing it:

* ``propose`` **reserves** the plan's cost on the gate's own ledger. Two
  plans that each fit the budget alone but not together cannot both be
  proposed — the second proposal sees the first's reservation and is
  refused with ``guard="budget"``.
* ``commit`` converts a reservation into real charges on the underlying
  ``PerCallBudget`` (subgoals in proposal order, then the planner's own
  generation cost). It re-verifies against the live budget first: if
  another path spent the money meanwhile, ``commit`` fails closed with
  ``BudgetExhausted`` instead of overdrawing.
* ``release`` abandons a reservation without charging (plan never run).

The planner's own generation cost (``planner_cost_usd``) is priced too:
a plan must pay for the thinking that produced it. The default is 0.0,
which means "the host already charged the planner's model call itself".

Honest scope: the reservation ledger is in-memory and gate-local — a
crash between ``propose`` and ``commit`` loses the reservation, and
another gate instance on the same budget would double-book. The host
owns crash durability and must not share one budget across gates. Cost
estimates are the planner's claims; the gate enforces them, it does not
audit their accuracy (that is the executor's ``observe_model`` job).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from per_call_budget import BudgetExhausted, PerCallBudget
from planner_gates import (
    Critic,
    CriticReview,
    CriticVerdict,
    PlanError,
    PlanProposal,
    Subgoal,
    gate_plan,
    propose_plan,
)

#: Module version pin. Bump on any behavior change.
PLANNER_BUDGET_COMBO_VERSION = "planner-budget-combo.v1"

#: Schema pin for serialized gated plans.
SCHEMA_PIN = "northstar.planner-budget-combo.v1"

GUARD_STRUCTURE = "structure"
GUARD_CRITIC = "critic"
GUARD_BUDGET = "budget"


class PlanRefused(Exception):
    """The planner+budget gate refused a plan proposal.

    Attributes:
        guard: which guard refused — ``"structure"``, ``"critic"``, or
            ``"budget"``.
        reason: machine-readable reason string.
    """

    def __init__(self, guard: str, reason: str) -> None:
        self.guard = guard
        self.reason = reason
        super().__init__(f"plan refused by {guard} guard: {reason}")


@dataclass(frozen=True)
class PlanCost:
    """Priced cost of one subgoal: its call type and estimated USD cost."""

    subgoal_id: str
    call_type: str
    estimated_cost_usd: float

    def as_dict(self) -> dict:
        return {
            "subgoal_id": self.subgoal_id,
            "call_type": self.call_type,
            "estimated_cost_usd": self.estimated_cost_usd,
        }


@dataclass(frozen=True)
class GatedPlan:
    """An approved, priced, reserved plan proposal.

    ``costs`` is in proposal (subgoal) order. ``total_cost_usd``
    includes ``planner_cost_usd``. The plan is *reserved* on the gate,
    not yet charged — call ``commit`` to charge, ``release`` to drop.
    """

    plan: PlanProposal
    costs: tuple[PlanCost, ...]
    planner_cost_usd: float
    total_cost_usd: float
    gate_seq: int
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "plan": self.plan.as_dict(),
            "costs": [c.as_dict() for c in self.costs],
            "planner_cost_usd": self.planner_cost_usd,
            "total_cost_usd": self.total_cost_usd,
            "gate_seq": self.gate_seq,
            "schema": self.schema,
        }


def _check_number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PlanRefused(GUARD_BUDGET, f"{name} must be a number, got {type(value).__name__}")
    result = float(value)
    if result < 0:
        raise PlanRefused(GUARD_BUDGET, f"{name} must be non-negative, got {result}")
    return result


class PlannerBudgetGate:
    """Composes planner gates with per-call budget enforcement.

    The gate holds the reservation ledger; the underlying
    ``PerCallBudget`` holds the real charges. One gate per budget —
    sharing a budget across gates defeats the reservation.
    """

    def __init__(self, budget: PerCallBudget, critic: Critic | None = None) -> None:
        if not isinstance(budget, PerCallBudget):
            raise TypeError(
                f"budget must be PerCallBudget, got {type(budget).__name__}"
            )
        if critic is not None and not isinstance(critic, Critic):
            raise TypeError(
                f"critic must be Critic or None, got {type(critic).__name__}"
            )
        self._budget = budget
        self._critic = critic or Critic()
        self._reserved_usd: float = 0.0
        self._reservations: dict[int, float] = {}
        self._next_seq: int = 0

    @property
    def reserved_usd(self) -> float:
        """Total USD currently reserved by uncommitted proposals."""
        return self._reserved_usd

    @property
    def outstanding(self) -> int:
        """Number of uncommitted reservations."""
        return len(self._reservations)

    def _effective_remaining(self) -> float | None:
        """Run-budget remaining minus this gate's reservations."""
        remaining = self._budget.remaining
        if remaining is None:
            return None
        return remaining - self._reserved_usd

    def propose(
        self,
        goal: str,
        subgoals: tuple[Subgoal, ...] | list[Subgoal],
        estimated_steps: int,
        costs: Mapping[str, float],
        call_types: Mapping[str, str] | None = None,
        planner_cost_usd: float = 0.0,
    ) -> GatedPlan:
        """Propose a plan; price it; reserve its cost.

        Raises:
            TypeError: ``costs`` is not a mapping (programming error).
            PlanRefused: structure / critic / budget guard refused.
        """
        # Guard 1: structure.
        try:
            plan = propose_plan(goal, subgoals, estimated_steps)
        except PlanError as exc:
            raise PlanRefused(GUARD_STRUCTURE, str(exc)) from exc

        # Guard 2: critic.
        review: CriticReview = self._critic.review(plan)
        if review.verdict is not CriticVerdict.APPROVE:
            raise PlanRefused(
                GUARD_CRITIC,
                f"critic verdict {review.verdict.value}: {','.join(review.reasons)}",
            )

        # Guard 3: budget.
        if not isinstance(costs, Mapping):
            raise TypeError(
                f"costs must be a mapping of subgoal id to USD, got {type(costs).__name__}"
            )
        call_types = call_types or {}
        if not isinstance(call_types, Mapping):
            raise TypeError(
                f"call_types must be a mapping or None, got {type(call_types).__name__}"
            )
        planner_cost = _check_number(planner_cost_usd, "planner_cost_usd")

        ids = [s.id for s in plan.subgoals]
        priced: list[PlanCost] = []
        for sid in ids:
            if sid not in costs:
                raise PlanRefused(GUARD_BUDGET, f"unpriced subgoal {sid!r}")
            cost = _check_number(costs[sid], f"costs[{sid!r}]")
            ctype = call_types.get(sid, "tool")
            if not isinstance(ctype, str):
                raise PlanRefused(
                    GUARD_BUDGET, f"call_types[{sid!r}] must be a string"
                )
            priced.append(PlanCost(subgoal_id=sid, call_type=ctype, estimated_cost_usd=cost))
        extra = sorted(set(costs) - set(ids))
        if extra:
            raise PlanRefused(
                GUARD_BUDGET, f"costs name unknown subgoals: {extra}"
            )

        # Per-call ceilings, then run ceiling against reservations.
        for pc in priced:
            ceiling = self._budget.per_call_ceilings.get(pc.call_type)
            if ceiling is None:
                raise PlanRefused(
                    GUARD_BUDGET, f"unknown call_type {pc.call_type!r}"
                )
            if pc.estimated_cost_usd > ceiling:
                raise PlanRefused(
                    GUARD_BUDGET,
                    f"subgoal {pc.subgoal_id!r} ${pc.estimated_cost_usd:.6f} "
                    f"exceeds per-call ceiling ${ceiling:.6f} for {pc.call_type!r}",
                )
        planner_ceiling = self._budget.per_call_ceilings.get("model")
        if planner_ceiling is not None and planner_cost > planner_ceiling:
            raise PlanRefused(
                GUARD_BUDGET,
                f"planner_cost_usd ${planner_cost:.6f} exceeds per-call "
                f"ceiling ${planner_ceiling:.6f} for 'model'",
            )

        total = planner_cost + sum(pc.estimated_cost_usd for pc in priced)
        remaining = self._effective_remaining()
        if remaining is not None and total > remaining:
            raise PlanRefused(
                GUARD_BUDGET,
                f"plan total ${total:.6f} exceeds effective remaining "
                f"${remaining:.6f} (run budget minus reservations)",
            )

        seq = self._next_seq
        self._next_seq += 1
        self._reserved_usd += total
        self._reservations[seq] = total
        return GatedPlan(
            plan=plan,
            costs=tuple(priced),
            planner_cost_usd=planner_cost,
            total_cost_usd=total,
            gate_seq=seq,
        )

    def commit(self, gated: GatedPlan) -> list:
        """Convert a reservation into real charges on the budget.

        Charges the planner's generation cost (as a ``"model"`` call)
        first, then subgoals in proposal order. Re-verifies against the
        live budget: raises ``BudgetExhausted`` (and leaves the
        reservation in place) if the money moved meanwhile.

        Raises:
            TypeError: not a ``GatedPlan``.
            KeyError: unknown or already-committed reservation.
            BudgetExhausted: live budget no longer fits the plan.
        """
        if not isinstance(gated, GatedPlan):
            raise TypeError(
                f"commit expects GatedPlan, got {type(gated).__name__}"
            )
        if gated.gate_seq not in self._reservations:
            raise KeyError(
                f"no outstanding reservation for gate_seq {gated.gate_seq}"
            )
        charges: list = []
        try:
            if gated.planner_cost_usd > 0:
                charges.append(
                    self._budget.check_and_charge("model", gated.planner_cost_usd)
                )
            for pc in gated.costs:
                charges.append(
                    self._budget.check_and_charge(pc.call_type, pc.estimated_cost_usd)
                )
        except BudgetExhausted:
            # Reservation stays: the plan can be retried after funds free up,
            # or released. Partial charges are NOT rolled back — the budget
            # is the ledger of record and every charge happened.
            raise
        reserved = self._reservations.pop(gated.gate_seq)
        self._reserved_usd -= reserved
        return charges

    def release(self, gated: GatedPlan) -> None:
        """Abandon a reservation without charging (plan never executed).

        Raises:
            TypeError: not a ``GatedPlan``.
            KeyError: unknown or already-committed reservation.
        """
        if not isinstance(gated, GatedPlan):
            raise TypeError(
                f"release expects GatedPlan, got {type(gated).__name__}"
            )
        reserved = self._reservations.pop(gated.gate_seq)
        self._reserved_usd -= reserved

    def review(self, plan: PlanProposal) -> CriticReview:
        """Expose the critic review (same as ``gate_plan``)."""
        return gate_plan(plan, self._critic)


if __name__ == "__main__":
    budget = PerCallBudget(max_budget_usd=1.0)
    gate = PlannerBudgetGate(budget)
    gated = gate.propose(
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
        costs={"fetch": 0.001, "summarize": 0.02},
        call_types={"fetch": "tool", "summarize": "model"},
        planner_cost_usd=0.005,
    )
    assert abs(gated.total_cost_usd - 0.026) < 1e-9, gated.total_cost_usd
    assert abs(gate.reserved_usd - 0.026) < 1e-9
    gate.commit(gated)
    assert gate.outstanding == 0
    print(
        f"planner-budget-combo OK: total=${gated.total_cost_usd:.6f}, "
        f"spent=${budget.total_spent_usd:.6f}"
    )
