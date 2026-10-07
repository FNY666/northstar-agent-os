"""Budget-gated approval: the budget is checked before a human is bothered.

The optimal wiring of :mod:`per_call_budget` and :mod:`approval_sla`
composes them in a fixed order: **budget first, approval second**.

* Over budget? Deny immediately. No approval request is enqueued, no
  human is paged, no SLA clock starts. An unaffordable action is not
  worth a human's attention.
* Under budget but expensive (estimate >= ``high_cost_threshold_usd``)?
  Park it in the approval queue. The budget gate runs *dry*: nothing is
  charged until the human approves, so a denied or expired approval
  cannot drain the budget (otherwise denied approvals become a cheap
  budget-drain vector -- the same doctrine as
  :mod:`budget_combo`: "a denied call consumes nothing from either
  guard").
* Under budget and cheap? Allow immediately and charge the budget.

Because the budget is only *reserved* (not charged) while a request is
pending, the budget can move between request and approval. If approval
lands after the budget has been spent elsewhere, the call is denied at
finalize time -- fail closed on budget drift.

House style: frozen dataclasses, no wall clock (all sequence numbers are
caller-supplied ints), fail-closed (unknown call types and malformed
inputs raise rather than pass), deterministic, stdlib-only.

Honest scope: estimates are estimates -- the gate bounds *estimated*
spend, not metered provider invoices. The dry-run fit check in
:meth:`BudgetApprovalGate.fits_budget` intentionally mirrors the refusal
rules of ``PerCallBudget.check_and_charge``; the two are cross-checked
in the test suite, but if ``per_call_budget`` ever changes its refusal
rules this mirror must be updated to match. The gate does not
authenticate the decider and does not sign receipts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from approval_sla import (
    APPROVAL_SLA_VERSION,
    STATUS_APPROVED,
    STATUS_DENIED,
    STATUS_EXPIRED,
    STATUS_PENDING,
    ApprovalQueue,
)
from per_call_budget import (
    CALL_TYPES,
    CEILING_PER_CALL,
    CEILING_RUN,
    BudgetExhausted,
    PerCallBudget,
)

#: Version pin for this module's record shape.
BUDGET_APPROVAL_COMBO_VERSION = "budget-approval-combo.v1"

#: Schema pin for audit-shaped records produced here.
BUDGET_APPROVAL_COMBO_SCHEMA = "northstar.budget-approval-combo.v1"

#: Gate decisions.
DECISION_ALLOWED = "allowed"
DECISION_PENDING = "pending"
DECISION_DENIED = "denied"

#: Why a request was denied. ``budget_exhausted`` fires at request time
#: (the human is never bothered); ``budget_exhausted_after_approval``
#: fires when the budget moved between request and finalize;
#: ``not_approved`` fires when finalize sees a non-approved request.
DENIAL_BUDGET = "budget_exhausted"
DENIAL_BUDGET_DRIFT = "budget_exhausted_after_approval"
DENIAL_NOT_APPROVED = "not_approved"

_DECISIONS = (DECISION_ALLOWED, DECISION_PENDING, DECISION_DENIED)
_DENIALS = (DENIAL_BUDGET, DENIAL_BUDGET_DRIFT, DENIAL_NOT_APPROVED)


def _check_text(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not value:
        raise ValueError(f"{name} must be non-empty")
    return value


def _check_seq(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


def _check_estimate(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(
            f"estimated_cost_usd must be a number, got {type(value).__name__}"
        )
    estimate = float(value)
    if estimate < 0:
        raise ValueError("estimated_cost_usd must be non-negative")
    return estimate


@dataclass(frozen=True)
class GateDecision:
    """One gate verdict.

    ``decision`` is ``allowed`` / ``pending`` / ``denied``.
    ``request_id`` is set only for ``pending``. ``denial_reason`` is one
    of :data:`DENIAL_BUDGET`, :data:`DENIAL_BUDGET_DRIFT`,
    :data:`DENIAL_NOT_APPROVED`, set only for ``denied``. ``ceiling``
    names which budget ceiling refused the call when the reason is
    budget-related (:data:`CEILING_PER_CALL` / :data:`CEILING_RUN`).
    """

    decision: str
    request_id: Optional[str] = None
    denial_reason: Optional[str] = None
    ceiling: Optional[str] = None
    schema: str = BUDGET_APPROVAL_COMBO_SCHEMA

    def __post_init__(self) -> None:
        if self.decision not in _DECISIONS:
            raise ValueError(f"unknown decision {self.decision!r}")
        if self.decision == DECISION_PENDING and self.request_id is None:
            raise ValueError("pending decision must carry request_id")
        if self.decision != DECISION_PENDING and self.request_id is not None:
            raise ValueError("only pending decisions carry request_id")
        if self.decision == DECISION_DENIED and self.denial_reason is None:
            raise ValueError("denied decision must carry denial_reason")
        if self.decision != DECISION_DENIED and self.denial_reason is not None:
            raise ValueError("only denied decisions carry denial_reason")
        if self.denial_reason is not None and self.denial_reason not in _DENIALS:
            raise ValueError(f"unknown denial_reason {self.denial_reason!r}")
        if self.ceiling is not None and self.ceiling not in (
            CEILING_PER_CALL,
            CEILING_RUN,
        ):
            raise ValueError(f"unknown ceiling {self.ceiling!r}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "request_id": self.request_id,
            "denial_reason": self.denial_reason,
            "ceiling": self.ceiling,
            "schema": self.schema,
        }


class BudgetApprovalGate:
    """Compose a per-call budget gate with an approval queue.

    ``request`` runs the budget gate first (dry-run: no charge), then
    routes cheap calls to immediate allow and expensive calls to human
    approval. ``finalize`` converts an approved request into a charged
    allow, failing closed when the budget drifted in between.
    """

    def __init__(
        self,
        budget: PerCallBudget,
        queue: Optional[ApprovalQueue] = None,
        high_cost_threshold_usd: float = 0.01,
    ) -> None:
        if not isinstance(budget, PerCallBudget):
            raise TypeError(
                f"budget must be a PerCallBudget, got {type(budget).__name__}"
            )
        if queue is not None and not isinstance(queue, ApprovalQueue):
            raise TypeError(
                f"queue must be an ApprovalQueue, got {type(queue).__name__}"
            )
        if isinstance(high_cost_threshold_usd, bool) or not isinstance(
            high_cost_threshold_usd, (int, float)
        ):
            raise TypeError(
                "high_cost_threshold_usd must be a number, "
                f"got {type(high_cost_threshold_usd).__name__}"
            )
        if high_cost_threshold_usd < 0:
            raise ValueError("high_cost_threshold_usd must be non-negative")
        self._budget = budget
        self._queue = queue if queue is not None else ApprovalQueue()
        self._threshold = float(high_cost_threshold_usd)
        # request_id -> (call_type, estimate) for requests still pending.
        self._held: dict[str, tuple[str, float]] = {}

    @property
    def high_cost_threshold_usd(self) -> float:
        return self._threshold

    def fits_budget(
        self, call_type: str, estimated_cost_usd: float
    ) -> tuple[bool, Optional[str]]:
        """Dry-run budget gate: would ``check_and_charge`` refuse this call?

        Returns ``(True, None)`` when the call fits, or ``(False,
        ceiling)`` naming the refusing ceiling. This intentionally
        mirrors the refusal rules of
        ``PerCallBudget.check_and_charge`` using its public state, so a
        denied (or approval-pending) call consumes nothing -- see the
        module docstring. Unknown ``call_type`` raises ``ValueError``,
        matching the underlying gate's fail-closed behaviour.
        """
        if call_type not in CALL_TYPES:
            raise ValueError(
                f"unknown call_type {call_type!r}; expected one of {list(CALL_TYPES)}"
            )
        estimate = _check_estimate(estimated_cost_usd)
        ceiling = self._budget.per_call_ceilings[call_type]
        if estimate > ceiling:
            return False, CEILING_PER_CALL
        max_budget = self._budget.max_budget_usd
        if max_budget is not None:
            if self._budget.total_spent_usd + estimate > max_budget:
                return False, CEILING_RUN
        return True, None

    def request(
        self,
        action: str,
        call_type: str,
        estimated_cost_usd: float,
        reason: str,
        sla_ticks: int,
        current_seq: int,
    ) -> GateDecision:
        """Run the budget gate, then route: allow / approval / deny.

        Budget check comes first: when the estimate does not fit, the
        call is denied and no approval request is enqueued. When it
        fits, estimates below ``high_cost_threshold_usd`` are allowed
        (and charged) immediately; estimates at or above the threshold
        are parked in the approval queue and the budget is *not*
        charged until approval.
        """
        _check_text(action, "action")
        _check_text(reason, "reason")
        _check_seq(current_seq, "current_seq")
        if isinstance(sla_ticks, bool) or not isinstance(sla_ticks, int):
            raise TypeError(
                f"sla_ticks must be an int, got {type(sla_ticks).__name__}"
            )
        if sla_ticks <= 0:
            raise ValueError(f"sla_ticks must be positive, got {sla_ticks}")
        # fits_budget validates call_type and the estimate.
        fits, ceiling = self.fits_budget(call_type, estimated_cost_usd)
        estimate = _check_estimate(estimated_cost_usd)
        if not fits:
            return GateDecision(
                decision=DECISION_DENIED,
                denial_reason=DENIAL_BUDGET,
                ceiling=ceiling,
            )
        if estimate < self._threshold:
            # Cheap path: charge now. Cannot fail after the dry-run fit,
            # but stay fail-closed if the world moved under us.
            try:
                self._budget.check_and_charge(call_type, estimate)
            except BudgetExhausted as exc:
                return GateDecision(
                    decision=DECISION_DENIED,
                    denial_reason=DENIAL_BUDGET,
                    ceiling=exc.ceiling,
                )
            return GateDecision(decision=DECISION_ALLOWED)
        request_id = self._queue.enqueue(action, reason, sla_ticks, current_seq)
        self._held[request_id] = (call_type, estimate)
        return GateDecision(decision=DECISION_PENDING, request_id=request_id)

    def poll(self, request_id: str, current_seq: int) -> str:
        """Approval status of a parked request at ``current_seq``.

        Delegates to the queue: ``pending`` / ``approved`` / ``denied`` /
        ``expired``. Unknown ids raise ``KeyError``.
        """
        return self._queue.poll(request_id, current_seq)

    def finalize(self, request_id: str, current_seq: int) -> GateDecision:
        """Convert an approved request into a charged allow.

        Only ``approved`` requests may execute. ``denied`` / ``expired``
        / still-``pending`` requests return a ``denied`` decision with
        reason :data:`DENIAL_NOT_APPROVED` and charge nothing. When the
        request is approved, the budget is charged for real; if the
        budget moved since the request was parked, the call is denied
        with reason :data:`DENIAL_BUDGET_DRIFT`. Unknown ids raise
        ``KeyError``.
        """
        status = self._queue.poll(request_id, current_seq)
        held = self._held.pop(request_id, None)
        if status != STATUS_APPROVED:
            return GateDecision(
                decision=DECISION_DENIED,
                denial_reason=DENIAL_NOT_APPROVED,
            )
        if held is None:
            # Already finalized once: replay of an approval must not
            # charge twice. The queue is sticky-approved, but the gate
            # only honors each approval once.
            return GateDecision(
                decision=DECISION_DENIED,
                denial_reason=DENIAL_NOT_APPROVED,
            )
        call_type, estimate = held
        try:
            self._budget.check_and_charge(call_type, estimate)
        except BudgetExhausted as exc:
            return GateDecision(
                decision=DECISION_DENIED,
                denial_reason=DENIAL_BUDGET_DRIFT,
                ceiling=exc.ceiling,
            )
        return GateDecision(decision=DECISION_ALLOWED)

    def pending_requests(self) -> list[str]:
        """Ids of requests still parked (held estimates not yet finalized)."""
        return list(self._held)

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": BUDGET_APPROVAL_COMBO_VERSION,
            "approval_sla_version": APPROVAL_SLA_VERSION,
            "high_cost_threshold_usd": self._threshold,
            "held_requests": len(self._held),
            "budget": self._budget.as_dict(),
        }

    def gate_audit_event(self, decision: GateDecision, seq: int) -> dict[str, Any]:
        """Audit-shaped record for one gate verdict."""
        _check_seq(seq, "seq")
        event = {
            "schema": BUDGET_APPROVAL_COMBO_SCHEMA,
            "version": BUDGET_APPROVAL_COMBO_VERSION,
            "seq": seq,
        }
        event.update(decision.as_dict())
        return event


def main() -> None:
    budget = PerCallBudget(max_budget_usd=1.0)
    gate = BudgetApprovalGate(budget)
    cheap = gate.request("summarize", "tool", 0.005, "routine", 10, 0)
    assert cheap.decision == DECISION_ALLOWED
    pricey = gate.request("full-eval", "model", 0.08, "abstain: costly", 10, 1)
    assert pricey.decision == DECISION_PENDING and pricey.request_id
    assert gate.poll(pricey.request_id, 2) == STATUS_PENDING
    gate._queue.decide(pricey.request_id, True, "op-1")
    done = gate.finalize(pricey.request_id, 3)
    assert done.decision == DECISION_ALLOWED
    broke = gate.request("huge", "model", 5.0, "too big", 10, 4)
    assert broke.decision == DECISION_DENIED
    assert broke.denial_reason == DENIAL_BUDGET
    assert len(gate._queue) == 1  # the denied request never bothered a human
    print("budget-approval-combo OK: allow/pending/finalize/deny, human unbothered")


if __name__ == "__main__":
    main()


__all__ = [
    "BUDGET_APPROVAL_COMBO_VERSION",
    "BUDGET_APPROVAL_COMBO_SCHEMA",
    "DECISION_ALLOWED",
    "DECISION_PENDING",
    "DECISION_DENIED",
    "DENIAL_BUDGET",
    "DENIAL_BUDGET_DRIFT",
    "DENIAL_NOT_APPROVED",
    "GateDecision",
    "BudgetApprovalGate",
]
