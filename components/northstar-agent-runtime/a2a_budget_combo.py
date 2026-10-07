"""A2A delegation gated by the delegator's budget.

Integration: ``a2a_gates`` (handoff safety) composed with
``per_call_budget`` (spend enforcement). When one agent delegates work
to another, two independent questions must both answer yes:

1. **Can the delegator afford it?** The delegated task's estimated cost
   is pre-charged against the *delegator's* budget before the handoff is
   even safety-checked. A delegation the parent cannot pay for is
   refused as ``deny_budget`` without touching the handoff gate.
2. **Is the handoff safe?** The usual sabotage / turf-war checks run on
   the handoff. If they deny, the pre-charge is refunded, so a refused
   delegation leaves the budget ledger exactly as it found it.

Sub-agent spending counts against the parent budget: the estimate is
charged up front (conservative, mirroring ``PerCallBudget`` doctrine),
and the sub-agent reconciles via :meth:`A2ABudgetGate.report_actual`.
An under-run refunds the difference; an over-run charges the delta
through the normal per-call gate, so a sub-agent that blows its
estimate can still blow the run budget -- and the gate reports it
instead of hiding it.

Hard doctrine (enforced, not aspirational):

- budget is checked *before* the handoff gate: a broke delegator never
  gets a safety verdict, and a refused handoff never costs money;
- the pre-charge is refunded if and only if the handoff gate denies;
  ``total_spent_usd`` after a denied delegation equals the value before
  it -- refunds are explicit negative charge records, not deletions;
- one grant = one delegation: ``report_actual`` closes the grant, and a
  second report for the same grant id raises ``KeyError``;
- an actual that exceeds the per-call ceiling for its call type is
  refused with ``BudgetExhausted`` (``CEILING_PER_CALL``); the
  pre-charged estimate stands and the violation is the host's incident
  to handle -- the gate never normalises an over-ceiling actual into
  the ledger;
- malformed delegation inputs fail closed as ``deny_budget``;
  malformed handoff inputs fail closed as ``deny_sabotage`` (the a2a
  gate's own verdict) with the budget untouched.

No wall clock anywhere: grant ids come from a caller-independent
monotonic counter, so every decision is deterministic and testable.

Honest scope: this is a *composition of host-reported records*, not a
defense against a hostile runtime. The estimate is the delegator's
guess; ``report_actual`` trusts the sub-agent's report -- a sub-agent
that lies about its actuals lies to this gate too. The refund path
mutates the wrapped :class:`PerCallBudget`'s charge list (appending a
negative ``CallCharge``); it does not rewrite history. Persistence
across restarts is the host's job.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from a2a_gates import (
    A2A_GATES_VERSION,
    A2AGate,
    ALLOW,
    DENY_SABOTAGE,
    DENY_TURF_WAR,
)
from per_call_budget import (
    CEILING_PER_CALL,
    BudgetExhausted,
    CallCharge,
    CALL_TYPES,
    PER_CALL_CEILINGS,
    PerCallBudget,
)

#: Version pin for this module's record shape.
A2A_BUDGET_COMBO_VERSION = "a2a-budget-combo.v1"

#: Verdict when the delegator's budget refuses the delegation. Joins the
#: a2a verdict vocabulary (``allow`` / ``deny_sabotage`` /
#: ``deny_turf_war``).
DENY_BUDGET = "deny_budget"

_VERDICTS = (ALLOW, DENY_BUDGET, DENY_SABOTAGE, DENY_TURF_WAR)


def _is_agent(value: object) -> bool:
    """Loose agent-id check for the pre-screen (the a2a gate is canonical)."""
    return isinstance(value, str) and bool(value.strip())


def _check_estimate(value: object) -> float:
    """Validate a cost estimate: numeric, not bool, non-negative."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"estimated_cost_usd must be a number, got {value!r}")
    estimate = float(value)
    if estimate < 0:
        raise ValueError(f"estimated_cost_usd must be non-negative, got {value!r}")
    return estimate


@dataclass(frozen=True)
class DelegationGrant:
    """Authorisation for one delegated task, pre-charged to the parent."""

    grant_id: str
    from_agent: str
    to_agent: str
    call_type: str
    estimated_cost_usd: float
    seq: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "from_agent": self.from_agent,
            "to_agent": self.to_agent,
            "call_type": self.call_type,
            "estimated_cost_usd": self.estimated_cost_usd,
            "seq": self.seq,
            "version": A2A_BUDGET_COMBO_VERSION,
        }


@dataclass(frozen=True)
class DelegationDecision:
    """Outcome of one :meth:`A2ABudgetGate.delegate` call."""

    verdict: str
    grant: DelegationGrant | None
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "grant": self.grant.as_dict() if self.grant is not None else None,
            "reason": self.reason,
            "version": A2A_BUDGET_COMBO_VERSION,
        }


class A2ABudgetGate:
    """Budget-gated checkpoint for agent-to-agent delegation.

    Owns one :class:`A2AGate` (handoff safety) and one
    :class:`PerCallBudget` (the delegator's spend ledger). ``delegate``
    is the only way to authorise delegated spend.
    """

    def __init__(
        self,
        gate_id: str = "a2a-budget-gate",
        max_budget_usd: float | None = None,
        per_call_ceilings: Mapping[str, float] | None = None,
    ) -> None:
        self._a2a = A2AGate(gate_id=gate_id)
        self._budget = PerCallBudget(
            max_budget_usd=max_budget_usd,
            per_call_ceilings=(
                dict(per_call_ceilings)
                if per_call_ceilings is not None
                else dict(PER_CALL_CEILINGS)
            ),
        )
        self._grants: dict[str, DelegationGrant] = {}
        self._seq = 0

    @property
    def a2a_gate(self) -> A2AGate:
        """The underlying handoff gate (history inspection, release)."""
        return self._a2a

    @property
    def total_spent_usd(self) -> float:
        """Net spend charged to the delegator's budget (refunds netted)."""
        return self._budget.total_spent_usd

    @property
    def remaining(self) -> float | None:
        """Remaining run budget, or ``None`` when no run ceiling is set."""
        return self._budget.remaining

    @property
    def active_grants(self) -> tuple[DelegationGrant, ...]:
        """Grants authorised but not yet reconciled or released."""
        return tuple(self._grants.values())

    def _next_seq(self) -> int:
        seq = self._seq
        self._seq += 1
        return seq

    def _adjust(self, call_type: str, delta: float) -> float | None:
        """Apply a signed delta to the ledger without ceiling checks.

        Used only for refunds (negative deltas), which cannot violate a
        ceiling. The refund is appended as an explicit negative
        :class:`CallCharge` so the ledger stays append-only and
        auditable; history is never rewritten.
        """
        inner = self._budget._budget  # the wrapped run Budget; same package
        inner.total_cost_usd = round(inner.total_cost_usd + delta, 10)
        remaining = self._budget.remaining
        self._budget.charges.append(
            CallCharge(
                call_type=call_type,
                estimated_cost_usd=delta,
                remaining_after_usd=remaining,
            )
        )
        return remaining

    def delegate(
        self,
        from_agent: str,
        to_agent: str,
        payload: Mapping[str, Any],
        estimated_cost_usd: float,
        call_type: str = "tool",
    ) -> DelegationDecision:
        """Authorise a delegation from *from_agent* to *to_agent*.

        Budget first: the estimate is pre-charged to the delegator's
        budget. ``deny_budget`` when it does not fit. Handoff safety
        second: ``deny_sabotage`` / ``deny_turf_war`` from the a2a gate,
        with the pre-charge refunded. On ``allow`` a
        :class:`DelegationGrant` is issued for later reconciliation.
        """
        # Cheap pre-screen so malformed handoffs never churn the ledger.
        if not (
            _is_agent(from_agent)
            and _is_agent(to_agent)
            and isinstance(payload, Mapping)
        ):
            verdict = self._a2a.check_handoff(from_agent, to_agent, payload)
            return DelegationDecision(
                verdict=verdict,
                grant=None,
                reason="malformed handoff; budget untouched",
            )

        try:
            estimate = _check_estimate(estimated_cost_usd)
        except ValueError as exc:
            return DelegationDecision(
                verdict=DENY_BUDGET, grant=None, reason=str(exc)
            )
        if call_type not in CALL_TYPES:
            return DelegationDecision(
                verdict=DENY_BUDGET,
                grant=None,
                reason=(
                    f"unknown call_type {call_type!r}; "
                    f"expected one of {list(CALL_TYPES)}"
                ),
            )

        try:
            self._budget.check_and_charge(call_type, estimate)
        except BudgetExhausted as exc:
            return DelegationDecision(
                verdict=DENY_BUDGET, grant=None, reason=str(exc)
            )
        except ValueError as exc:  # fail closed; unreachable after validation
            return DelegationDecision(
                verdict=DENY_BUDGET, grant=None, reason=str(exc)
            )

        verdict = self._a2a.check_handoff(from_agent, to_agent, payload)
        if verdict != ALLOW:
            # The handoff gate denied: unwind the pre-charge exactly.
            self._adjust(call_type, -estimate)
            return DelegationDecision(
                verdict=verdict,
                grant=None,
                reason=f"handoff denied ({verdict}); pre-charge refunded",
            )

        grant = DelegationGrant(
            grant_id=f"grant-{self._next_seq():06d}",
            from_agent=from_agent,
            to_agent=to_agent,
            call_type=call_type,
            estimated_cost_usd=estimate,
            seq=self._seq - 1,
        )
        self._grants[grant.grant_id] = grant
        return DelegationDecision(
            verdict=ALLOW,
            grant=grant,
            reason="delegation allowed; estimate pre-charged to delegator",
        )

    def report_actual(
        self, grant_id: str, actual_cost_usd: float
    ) -> float | None:
        """Reconcile a grant's estimate with the sub-agent's actual spend.

        Under-runs refund the difference; over-runs charge the delta
        through the per-call gate. An actual above the per-call ceiling
        raises :class:`BudgetExhausted` and the pre-charged estimate
        stands. The grant is closed in all cases. Unknown grant ids
        raise ``KeyError``.

        Returns the remaining run budget, or ``None`` when no run
        ceiling is set.
        """
        try:
            grant = self._grants.pop(grant_id)
        except KeyError:
            raise KeyError(f"unknown grant_id {grant_id!r}") from None
        actual = _check_estimate(actual_cost_usd)

        ceiling = self._budget.per_call_ceilings[grant.call_type]
        if actual > ceiling:
            raise BudgetExhausted(
                call_type=grant.call_type,
                needed=actual,
                available=self.remaining,
                ceiling=CEILING_PER_CALL,
            )

        delta = actual - grant.estimated_cost_usd
        if delta > 0:
            # Over-run: the extra spend must still fit the run budget.
            return self._budget.check_and_charge(grant.call_type, delta)
        if delta < 0:
            return self._adjust(grant.call_type, delta)
        return self.remaining

    def release_grant(self, grant_id: str) -> float | None:
        """Cancel a delegation before work started; refund the estimate.

        Unknown grant ids raise ``KeyError``. Returns the remaining run
        budget, or ``None`` when no run ceiling is set.
        """
        try:
            grant = self._grants.pop(grant_id)
        except KeyError:
            raise KeyError(f"unknown grant_id {grant_id!r}") from None
        return self._adjust(grant.call_type, -grant.estimated_cost_usd)

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": A2A_BUDGET_COMBO_VERSION,
            "a2a_gates_version": A2A_GATES_VERSION,
            "total_spent_usd": self.total_spent_usd,
            "remaining_usd": self.remaining,
            "active_grants": [g.as_dict() for g in self.active_grants],
        }


def a2a_budget_audit_event(
    decision: DelegationDecision, seq: int
) -> dict[str, Any]:
    """Shape a delegation decision as an ``audit.ndjson/1`` record."""
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    return {
        "schema": "audit.ndjson/1",
        "seq": seq,
        "event": "a2a-budget-delegation",
        "verdict": decision.verdict,
        "grant_id": decision.grant.grant_id if decision.grant else None,
        "reason": decision.reason,
        "version": A2A_BUDGET_COMBO_VERSION,
    }


__all__ = [
    "A2A_BUDGET_COMBO_VERSION",
    "A2ABudgetGate",
    "DENY_BUDGET",
    "DelegationDecision",
    "DelegationGrant",
    "a2a_budget_audit_event",
]


def main() -> None:
    gate = A2ABudgetGate(max_budget_usd=1.0)
    d = gate.delegate(
        "parent", "worker", {"action_type": "analyse", "target": "logs"},
        0.005,
    )
    assert d.verdict == ALLOW and d.grant is not None, d
    assert gate.total_spent_usd == 0.005
    remaining = gate.report_actual(d.grant.grant_id, 0.003)
    assert gate.total_spent_usd == 0.003, gate.total_spent_usd
    assert remaining == 1.0 - 0.003

    broke = A2ABudgetGate(max_budget_usd=0.001)
    denied = broke.delegate(
        "parent", "worker", {"action_type": "analyse", "target": "logs"},
        0.005,
    )
    assert denied.verdict == DENY_BUDGET and denied.grant is None
    assert broke.total_spent_usd == 0.0

    # Sabotage denial refunds the pre-charge.
    g2 = A2ABudgetGate(max_budget_usd=1.0)
    ok = g2.delegate(
        "parent", "w1", {"action_type": "create", "target": "report"}, 0.001
    )
    assert ok.verdict == ALLOW
    bad = g2.delegate(
        "parent", "w2", {"action_type": "delete", "target": "report"}, 0.002
    )
    assert bad.verdict == DENY_SABOTAGE, bad
    assert g2.total_spent_usd == 0.001, g2.total_spent_usd

    print("a2a-budget-combo OK: allow charges, deny_budget blocks, "
          "sabotage-denial refunds")


if __name__ == "__main__":
    main()
