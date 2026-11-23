"""Skill + budget integration: every skill invocation passes both gates.

This module wires :mod:`skill_wiring` (authorization) together with
:mod:`per_call_budget` (per-call estimate ceiling + run total ceiling) into
one decision point. A skill invocation is allowed only when all three checks
pass, in a fixed order:

1. **Pre-authorization** — a skill whose estimated cost reaches the expensive
   threshold (``>= expensive_threshold_usd``), or whose policy sets
   ``requires_review``, needs an explicit one-shot grant before it may run.
   Grants are issued by the host (``grant_pre_authorization``), are scoped
   to one ``(skill_name, caller_id)`` pair, and are burned on the first fully
   authorized invocation.
2. **Authorization** — :func:`skill_wiring.authorize_skill_call` against the
   registry, fail-closed (unknown skill, wrong caller, empty caller deny).
3. **Budget** — :meth:`per_call_budget.PerCallBudget.check_and_charge`
   routes the skill's estimated cost through one budget call type
   (``"tool"`` by default). The per-call ceiling refuses a runaway estimate
   even when the run budget has room; the run ceiling refuses when the
   estimate does not fit what is left.

Hard doctrine (enforced, not aspirational):

* a denied call consumes nothing: the budget is charged and the grant is
  burned only on a fully authorized decision;
* grants never override budget ceilings — an expensive skill with a valid
  grant but no budget headroom is still refused (a grant is authorization,
  not money);
* the grant gate runs *before* authorization so that a missing grant fails
  fast, but a grant is only *burned* after the budget gate passes, so a
  denied call never wastes a grant.

Honest scope: estimates are estimates — the gate bounds *estimated* spend,
not metered provider invoices. Code-mode (``skill_wiring``'s ``"code-mode"``
pseudo-skill) flows through the same gate when registered; this module does
not sandbox code, it only guarantees an ungranted, unauthorized, or
over-budget call never reaches the host executor.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from per_call_budget import (
    CALL_TYPES,
    CEILING_PER_CALL,
    PerCallBudget,
)
from per_call_budget import BudgetExhausted as PerCallBudgetExhausted
from skill_wiring import (
    SKILL_WIRING_VERSION,
    SkillCall,
    SkillRegistry,
    args_digest,
    authorize_skill_call,
)

#: Version pin for records minted by this module.
SKILL_BUDGET_COMBO_VERSION = "skill-budget-combo.v1"

#: Schema pin carried on decision and audit records.
SCHEMA_PIN = "northstar.skill-budget-combo.v1"

#: Decision reasons returned by :meth:`SkillBudgetGate.invoke`.
REASON_AUTHORIZED = "authorized"
REASON_UNAUTHORIZED = "unauthorized"
REASON_PRE_AUTH_REQUIRED = "pre-authorization-required"
REASON_BUDGET_PER_CALL = "budget-exhausted-per-call"
REASON_BUDGET_RUN = "budget-exhausted-run"


class SkillBudgetError(ValueError):
    """Misuse of the skill+budget gate (bad policy, bad arguments)."""


@dataclass(frozen=True)
class PreAuthorization:
    """One explicit host grant for an expensive/review skill call."""

    skill_name: str
    caller_id: str
    granted_seq: int  # caller-supplied sequence number; no wall clock is read

    def as_dict(self) -> dict[str, Any]:
        return {
            "skill_name": self.skill_name,
            "caller_id": self.caller_id,
            "granted_seq": self.granted_seq,
            "version": SKILL_BUDGET_COMBO_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class SkillBudgetDecision:
    """The combined verdict of all three gates for one skill invocation."""

    call: SkillCall
    allowed: bool
    reason: str  # one of the REASON_* constants
    cost_usd: float
    pre_auth_used: bool  # True when a grant was burned for this decision

    def as_dict(self) -> dict[str, Any]:
        return {
            "call": self.call.as_dict(),
            "allowed": self.allowed,
            "reason": self.reason,
            "cost_usd": self.cost_usd,
            "pre_auth_used": self.pre_auth_used,
            "version": SKILL_BUDGET_COMBO_VERSION,
            "schema": SCHEMA_PIN,
        }


def combo_audit_event(decision: SkillBudgetDecision, seq: int) -> dict[str, Any]:
    """Shape a decision as an ``audit.ndjson/1`` record."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SkillBudgetError("seq must be an int")
    if seq < 0:
        raise SkillBudgetError("seq must be non-negative")
    return {
        "schema": "audit.ndjson/1",
        "seq": seq,
        "event": "skill-budget-decision",
        "skill_name": decision.call.skill_name,
        "caller_id": decision.call.caller_id,
        "call_seq": decision.call.seq,
        "allowed": decision.allowed,
        "reason": decision.reason,
        "cost_usd": decision.cost_usd,
        "pre_auth_used": decision.pre_auth_used,
        "version": SKILL_BUDGET_COMBO_VERSION,
    }


class SkillBudgetGate:
    """One decision point for skill invocations: grant, auth, budget.

    ``expensive_threshold_usd`` names the cost at or above which a skill is
    "expensive" and needs a pre-authorization grant. Skills with
    ``SkillPolicy.requires_review`` need a grant regardless of cost.
    ``budget_call_type`` selects which per-call-budget tier the skill's
    estimated cost is charged against (``"tool"`` by default); it must be
    one of :data:`per_call_budget.CALL_TYPES`.
    """

    def __init__(
        self,
        *,
        registry: SkillRegistry,
        budget: PerCallBudget,
        expensive_threshold_usd: float = 1.0,
        budget_call_type: str = "tool",
    ) -> None:
        if not isinstance(registry, SkillRegistry):
            raise SkillBudgetError("registry must be a SkillRegistry")
        if not isinstance(budget, PerCallBudget):
            raise SkillBudgetError("budget must be a PerCallBudget")
        if isinstance(expensive_threshold_usd, bool) or not isinstance(
            expensive_threshold_usd, (int, float)
        ):
            raise SkillBudgetError("expensive_threshold_usd must be a number")
        if expensive_threshold_usd < 0:
            raise SkillBudgetError("expensive_threshold_usd must be non-negative")
        if budget_call_type not in CALL_TYPES:
            raise SkillBudgetError(
                f"budget_call_type must be one of {list(CALL_TYPES)}"
            )
        self._registry = registry
        self._budget = budget
        self._expensive_threshold_usd = float(expensive_threshold_usd)
        self._budget_call_type = budget_call_type
        self._grants: dict[tuple[str, str], PreAuthorization] = {}

    @property
    def expensive_threshold_usd(self) -> float:
        return self._expensive_threshold_usd

    @property
    def budget_call_type(self) -> str:
        return self._budget_call_type

    def grant_pre_authorization(
        self, skill_name: str, caller_id: str, seq: int
    ) -> PreAuthorization:
        """Issue (or replace) a one-shot grant for an expensive skill."""
        self._check_names(skill_name, caller_id)
        grant = PreAuthorization(
            skill_name=skill_name, caller_id=caller_id, granted_seq=self._check_seq(seq)
        )
        self._grants[(skill_name, caller_id)] = grant
        return grant

    def revoke_pre_authorization(self, skill_name: str, caller_id: str) -> bool:
        """Revoke a grant; True when one existed."""
        self._check_names(skill_name, caller_id)
        return self._grants.pop((skill_name, caller_id), None) is not None

    def has_grant(self, skill_name: str, caller_id: str) -> bool:
        """Whether a live grant exists for this pair."""
        self._check_names(skill_name, caller_id)
        return (skill_name, caller_id) in self._grants

    def pending_grants(self) -> tuple[PreAuthorization, ...]:
        """All live grants in deterministic (skill, caller) order."""
        return tuple(
            self._grants[key] for key in sorted(self._grants, key=lambda k: (k[0], k[1]))
        )

    def invoke(
        self, skill_name: str, args: Any, caller_id: str, seq: int
    ) -> SkillBudgetDecision:
        """Decide one skill invocation through grant, auth, then budget.

        Returns a :class:`SkillBudgetDecision`; nothing is charged and no
        grant is burned unless the decision is fully authorized.
        """
        self._check_names(skill_name, caller_id)
        seq = self._check_seq(seq)
        call = SkillCall(
            skill_name=skill_name,
            args_hash=args_digest(args),
            caller_id=caller_id,
            seq=seq,
        )
        policy = self._registry.policy_for(skill_name)
        cost = policy.estimated_cost_usd if policy is not None else 0.0
        needs_grant = policy is not None and (
            cost >= self._expensive_threshold_usd or policy.requires_review
        )
        grant: PreAuthorization | None = None
        if needs_grant:
            grant = self._grants.get((skill_name, caller_id))
            if grant is None:
                return SkillBudgetDecision(
                    call=call,
                    allowed=False,
                    reason=REASON_PRE_AUTH_REQUIRED,
                    cost_usd=cost,
                    pre_auth_used=False,
                )
        if not authorize_skill_call(call, policy):
            return SkillBudgetDecision(
                call=call,
                allowed=False,
                reason=REASON_UNAUTHORIZED,
                cost_usd=cost,
                pre_auth_used=False,
            )
        try:
            self._budget.check_and_charge(self._budget_call_type, cost)
        except PerCallBudgetExhausted as exc:
            reason = (
                REASON_BUDGET_PER_CALL
                if exc.ceiling == CEILING_PER_CALL
                else REASON_BUDGET_RUN
            )
            return SkillBudgetDecision(
                call=call,
                allowed=False,
                reason=reason,
                cost_usd=cost,
                pre_auth_used=False,
            )
        # Full pass: burn the grant (if one was required) and allow.
        if grant is not None:
            del self._grants[(skill_name, caller_id)]
        return SkillBudgetDecision(
            call=call,
            allowed=True,
            reason=REASON_AUTHORIZED,
            cost_usd=cost,
            pre_auth_used=grant is not None,
        )

    @staticmethod
    def _check_names(skill_name: str, caller_id: str) -> None:
        if not isinstance(skill_name, str) or not skill_name:
            raise SkillBudgetError("skill_name must be a non-empty string")
        if not isinstance(caller_id, str) or not caller_id:
            raise SkillBudgetError("caller_id must be a non-empty string")

    @staticmethod
    def _check_seq(seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SkillBudgetError("seq must be an int")
        if seq < 0:
            raise SkillBudgetError("seq must be non-negative")
        return seq


def main() -> None:
    """Self-check: cheap skill flows, expensive skill needs a grant."""
    from skill_wiring import SkillPolicy

    registry = SkillRegistry()
    registry.register(
        SkillPolicy(
            skill_name="lookup",
            allowed_callers=frozenset({"agent"}),
            estimated_cost_usd=0.005,
        )
    )
    registry.register(
        SkillPolicy(
            skill_name="heavy-compute",
            allowed_callers=frozenset({"agent"}),
            estimated_cost_usd=2.0,
        )
    )
    budget = PerCallBudget(
        max_budget_usd=10.0, per_call_ceilings={"model": 0.10, "tool": 5.0,
                                                "memory_read": 0.001, "memory_write": 0.001}
    )
    gate = SkillBudgetGate(registry=registry, budget=budget,
                           expensive_threshold_usd=1.0)
    cheap = gate.invoke("lookup", {"q": "x"}, "agent", 1)
    assert cheap.allowed and cheap.reason == REASON_AUTHORIZED
    pricey = gate.invoke("heavy-compute", {}, "agent", 2)
    assert not pricey.allowed and pricey.reason == REASON_PRE_AUTH_REQUIRED
    gate.grant_pre_authorization("heavy-compute", "agent", 3)
    granted = gate.invoke("heavy-compute", {}, "agent", 4)
    assert granted.allowed and granted.pre_auth_used
    assert not gate.has_grant("heavy-compute", "agent")  # one-shot, burned
    print("skill-budget-combo OK: grant flow, auth, and budget all enforced")


if __name__ == "__main__":
    main()
