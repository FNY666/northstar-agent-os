"""Per-call budget enforcement for model/tool/memory calls.

The run-level :class:`budget.Budget` accumulates cost from provider usage
reports and is checked at turn boundaries in ``loop.py``
(``_ceiling_stop``). That leaves a gap: a single turn can fire many tool
calls or memory operations with no spend check between them, and one
runaway call can blow the whole run budget before the next checkpoint.

This module closes the gap with a per-call gate. Every model, tool, and
memory call is *estimated* before it runs; the call is refused when the
estimate does not fit. Two ceilings apply, both fail-closed:

* **run ceiling** — ``max_budget_usd`` for the whole run. A call whose
  estimate would push total spend over the ceiling is refused.
* **per-call ceiling** — a per-type cap on a *single* call's estimate
  (model $0.10, tool $0.01, memory $0.001). A single call estimated above
  its type ceiling is refused even when the run budget has room, so one
  misbehaving call cannot consume the budget in one shot.

Estimates are charged up front via :meth:`PerCallBudget.check_and_charge`;
actual model-call costs are reconciled afterwards through
:meth:`PerCallBudget.observe_model`, which delegates to the underlying
:class:`budget.Budget`. The pre-charge is deliberately conservative:
it is better to refuse a call that might have fit than to let a call
through that blows the ceiling.

Honest scope: estimates are estimates. A tool whose estimate was $0.005
may in reality cost the provider $0.02 (or nothing, for a local tool) —
the gate bounds *estimated* spend, not metered provider invoices. The
per-call gate is a pre-check, not an accounting system; it does not
replace the run-level budget, it makes the run-level budget enforceable
between checkpoints. Unknown call types fail closed (``ValueError``),
never defaulting to the cheapest tier.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from budget import Budget

#: Call types the per-call gate recognises. Anything else is rejected.
CALL_TYPES: tuple[str, ...] = ("model", "tool", "memory_read", "memory_write")

#: Fail-closed per-call estimate ceilings in USD. A single call estimated
#: above its type ceiling is refused regardless of remaining run budget.
PER_CALL_CEILINGS: dict[str, float] = {
    "model": 0.10,
    "tool": 0.01,
    "memory_read": 0.001,
    "memory_write": 0.001,
}

#: Which ceiling refused the call: the per-call estimate cap or the run total.
CEILING_PER_CALL = "per_call"
CEILING_RUN = "run"


class BudgetExhausted(Exception):
    """Raised when a call does not fit the budget.

    Attributes:
        call_type: the refused call's type (one of :data:`CALL_TYPES`).
        needed: the call's estimated cost in USD.
        available: the remaining run budget in USD (``None`` when the run
            has no ceiling — in that case the refusal came from the
            per-call ceiling).
        ceiling: :data:`CEILING_PER_CALL` or :data:`CEILING_RUN`, naming
            which ceiling refused the call.
    """

    def __init__(
        self,
        call_type: str,
        needed: float,
        available: float | None,
        ceiling: str,
    ) -> None:
        self.call_type = call_type
        self.needed = needed
        self.available = available
        self.ceiling = ceiling
        if ceiling == CEILING_PER_CALL:
            detail = (
                f"estimated ${needed:.6f} exceeds the per-call ceiling "
                f"for {call_type!r}"
            )
        else:
            detail = (
                f"estimated ${needed:.6f} exceeds remaining run budget "
                f"(${available:.6f} left)"
                if available is not None
                else f"estimated ${needed:.6f} does not fit the run budget"
            )
        super().__init__(f"budget exhausted for {call_type} call: {detail}")


@dataclass
class CallCharge:
    """One recorded per-call charge."""

    call_type: str
    estimated_cost_usd: float
    remaining_after_usd: float | None


@dataclass
class PerCallBudget:
    """Per-call gate over a run :class:`budget.Budget`.

    ``check_and_charge`` is the only way to spend: it estimates first,
    refuses when the estimate does not fit, and records the charge when it
    does. Model-call actuals are reconciled via ``observe_model``.
    """

    max_budget_usd: float | None = None
    per_call_ceilings: dict[str, float] = field(
        default_factory=lambda: dict(PER_CALL_CEILINGS)
    )
    _budget: Budget = field(default_factory=Budget, repr=False)
    charges: list[CallCharge] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        if self.max_budget_usd is not None:
            if isinstance(self.max_budget_usd, bool) or not isinstance(
                self.max_budget_usd, (int, float)
            ):
                raise ValueError("max_budget_usd must be a number or None")
            if self.max_budget_usd <= 0:
                raise ValueError("max_budget_usd must be positive when set")
        unknown = set(self.per_call_ceilings) - set(CALL_TYPES)
        if unknown:
            raise ValueError(f"unknown call type(s) in per_call_ceilings: {sorted(unknown)}")
        for call_type, ceiling in self.per_call_ceilings.items():
            if not isinstance(ceiling, (int, float)) or isinstance(ceiling, bool):
                raise ValueError(f"per-call ceiling for {call_type!r} must be a number")
            if ceiling < 0:
                raise ValueError(f"per-call ceiling for {call_type!r} must be non-negative")
        # The wrapped run budget carries the same ceiling so its own
        # ``exhausted``/``remaining`` stay consistent with the gate.
        self._budget = Budget(max_budget_usd=self.max_budget_usd)

    def check_and_charge(self, call_type: str, estimated_cost_usd: float) -> float | None:
        """Estimate-check a call and charge it when it fits.

        Raises:
            ValueError: unknown ``call_type``, negative estimate, or a
                non-numeric estimate.
            BudgetExhausted: the estimate exceeds the per-call ceiling for
                ``call_type``, or would push total spend over the run
                ceiling.

        Returns the remaining run budget in USD, or ``None`` when the run
        has no ceiling.
        """
        if call_type not in CALL_TYPES:
            raise ValueError(
                f"unknown call_type {call_type!r}; expected one of {list(CALL_TYPES)}"
            )
        if isinstance(estimated_cost_usd, bool) or not isinstance(
            estimated_cost_usd, (int, float)
        ):
            raise ValueError("estimated_cost_usd must be a number")
        estimate = float(estimated_cost_usd)
        if estimate < 0:
            raise ValueError("estimated_cost_usd must be non-negative")

        # Per-call ceiling first: one runaway call is refused even when the
        # run budget could absorb it.
        ceiling = self.per_call_ceilings[call_type]
        if estimate > ceiling:
            raise BudgetExhausted(
                call_type=call_type,
                needed=estimate,
                available=self.remaining,
                ceiling=CEILING_PER_CALL,
            )

        # Run ceiling second: the estimate must fit what is left.
        if self.max_budget_usd is not None:
            remaining = self.remaining
            assert remaining is not None
            if self._spent() + estimate > self.max_budget_usd:
                raise BudgetExhausted(
                    call_type=call_type,
                    needed=estimate,
                    available=remaining,
                    ceiling=CEILING_RUN,
                )

        new_spent = round(self._spent() + estimate, 10)
        self._budget.total_cost_usd = new_spent
        remaining = self.remaining
        self.charges.append(
            CallCharge(
                call_type=call_type,
                estimated_cost_usd=estimate,
                remaining_after_usd=remaining,
            )
        )
        return remaining

    def observe_model(self, usage: Any, model: str) -> Any:
        """Reconcile a model call's actual provider-reported cost.

        Delegates to the wrapped :class:`budget.Budget.observe` so the
        itemised breakdown stays intact. The actual is added on top of any
        pre-charged estimate — callers that pre-charged should pass the
        *actual-minus-estimate* delta here, or use this alone when they did
        not pre-charge.
        """
        return self._budget.observe(usage, model)

    def _spent(self) -> float:
        return self._budget.total_cost_usd

    @property
    def total_spent_usd(self) -> float:
        return self._spent()

    @property
    def remaining(self) -> float | None:
        return self._budget.remaining()

    @property
    def exhausted(self) -> bool:
        return self._budget.exhausted

    def charges_for(self, call_type: str) -> list[CallCharge]:
        """All recorded charges of one call type, in order."""
        if call_type not in CALL_TYPES:
            raise ValueError(
                f"unknown call_type {call_type!r}; expected one of {list(CALL_TYPES)}"
            )
        return [c for c in self.charges if c.call_type == call_type]

    def as_dict(self) -> dict[str, Any]:
        return {
            "max_budget_usd": self.max_budget_usd,
            "total_spent_usd": self.total_spent_usd,
            "remaining_usd": self.remaining,
            "exhausted": self.exhausted,
            "per_call_ceilings": dict(self.per_call_ceilings),
            "charges": len(self.charges),
        }


__all__ = [
    "BudgetExhausted",
    "CALL_TYPES",
    "CEILING_PER_CALL",
    "CEILING_RUN",
    "CallCharge",
    "PER_CALL_CEILINGS",
    "PerCallBudget",
]
