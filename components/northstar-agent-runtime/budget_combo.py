"""Combined budget: per-call ceiling + token bucket, checked together.

The comparison of the two budget methods (see the parent task's triage)
concluded they *compose*, not compete:

* :mod:`per_call_budget` is the **cost** guard: a per-call estimate ceiling
  plus a run-total ceiling. It answers "can we afford this at all?"
* :mod:`budget_token_bucket` is the **rate** guard: per-type token buckets
  with linear refill over sequence ticks. It answers "can we afford this
  *right now* without hammering the provider?"

The optimal wiring is both, in a fixed order: the cost guard is checked
first (fail fast, deterministic), then the rate guard. A call proceeds
only when **both** pass. Crucially, a *denied* call consumes nothing from
either guard — the rate bucket must not be drained by calls that the cost
guard would refuse anyway (otherwise denied traffic becomes a cheap way
to starve legitimate calls), and the cost ceiling must not be charged for
calls the rate guard refuses.

House style: no wall-clock (``seq`` is the caller-supplied integer tick),
fail-closed (unknown call types and malformed inputs raise rather than
pass), deterministic. :class:`ComboDenied` names which guard refused, so
the caller knows whether to give up (cost) or retry later (rate).

Honest scope: estimates are estimates — both guards bound *estimated*
spend, not metered provider invoices. This is a pre-call gate, not an
accounting system; it does not replace the run-level budget, it makes it
enforceable on every call at a sustainable rate.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from budget_token_bucket import TokenBucket, TokenBucketBudget, TOKEN_BUCKET_VERSION
from per_call_budget import (
    CALL_TYPES,
    CEILING_PER_CALL,
    CEILING_RUN,
    BudgetExhausted,
    PerCallBudget,
)

#: Version pin for the combined-guard protocol described here.
BUDGET_COMBO_VERSION = "budget-combo.v1"

#: Guard identifiers, in the order they are checked.
GUARD_CEILING = "ceiling"
GUARD_BUCKET = "bucket"

#: Which underlying ceiling refused, when the ceiling guard does.
#: Re-exported so callers need only import this module.
GUARD_PER_CALL = "per_call"
GUARD_RUN = "run"


class ComboDenied(Exception):
    """Raised when a call is refused by the combined budget.

    Attributes:
        call_type: the refused call's type (one of
            :data:`per_call_budget.CALL_TYPES`).
        needed: the call's estimated cost in USD.
        guard: which guard refused — ``"per_call"`` or ``"run"`` for the
            cost guard's sub-ceilings, ``"bucket"`` for the rate guard.
        available: remaining run budget in USD when the run ceiling
            refused (``None`` when the run is uncapped or another guard
            refused).
        retry_in_seqs: sequence ticks until the rate guard would allow
            the call (only meaningful when ``guard == "bucket"``).
    """

    def __init__(
        self,
        call_type: str,
        needed: float,
        guard: str,
        available: float | None = None,
        retry_in_seqs: int | None = None,
    ) -> None:
        self.call_type = call_type
        self.needed = needed
        self.guard = guard
        self.available = available
        self.retry_in_seqs = retry_in_seqs
        if guard == GUARD_PER_CALL:
            detail = f"estimated ${needed:.6f} exceeds the per-call ceiling"
        elif guard == GUARD_RUN:
            detail = (
                f"estimated ${needed:.6f} exceeds remaining run budget"
                + (f" (${available:.6f} left)" if available is not None else "")
            )
        elif guard == GUARD_BUCKET:
            detail = (
                f"rate guard has insufficient tokens"
                + (
                    f"; retry in {retry_in_seqs} seqs"
                    if retry_in_seqs is not None
                    else ""
                )
            )
        else:  # pragma: no cover - constructor is internal; guards are fixed
            detail = f"refused by unknown guard {guard!r}"
        super().__init__(f"combo budget denied {call_type} call: {detail}")


@dataclass(frozen=True)
class ComboCharge:
    """Frozen record of one admitted call."""

    call_type: str
    estimated_cost_usd: float
    seq: int
    remaining_run_usd: float | None
    tokens_left: float


class ComboBudget:
    """Cost guard + rate guard checked together, atomically.

    ``check_and_charge`` dry-runs the cost guard first (reading the live
    ceiling state, so the dry run cannot diverge from the real check),
    then consumes the rate bucket, then charges the cost guard. Either
    refusal leaves both guards untouched.
    """

    def __init__(
        self,
        max_budget_usd: float | None = None,
        per_call_ceilings: Mapping[str, float] | None = None,
        buckets: Mapping[str, TokenBucket] | None = None,
        *,
        start_seq: int = 0,
    ) -> None:
        self._per_call = PerCallBudget(
            max_budget_usd=max_budget_usd,
            **({"per_call_ceilings": dict(per_call_ceilings)} if per_call_ceilings is not None else {}),
        )
        self._bucket = TokenBucketBudget(buckets=buckets, start_seq=start_seq)
        self._charges: list[ComboCharge] = []

    # -- dry run ------------------------------------------------------
    def _dry_run_ceiling(self, call_type: str, estimate: float) -> str | None:
        """Mirror of :meth:`PerCallBudget.check_and_charge`'s checks.

        Returns the refusing sub-guard (``"per_call"``/``"run"``) or None.
        Reads live state, so it agrees with the real check that follows.
        """
        if estimate > self._per_call.per_call_ceilings[call_type]:
            return GUARD_PER_CALL
        max_budget = self._per_call.max_budget_usd
        if max_budget is not None:
            if self._per_call.total_spent_usd + estimate > max_budget:
                return GUARD_RUN
        return None

    # -- public API ---------------------------------------------------
    def check_and_charge(
        self, call_type: str, estimated_cost_usd: float, current_seq: int
    ) -> ComboCharge:
        """Check both guards and charge when both pass.

        Raises:
            ValueError: unknown ``call_type`` or malformed cost/seq
                (fail-closed, from the underlying guards).
            ComboDenied: the cost guard (``guard`` ``"per_call"``/``"run"``)
                or the rate guard (``guard`` ``"bucket"``, with
                ``retry_in_seqs``) refused the call. Neither guard is
                charged on refusal.
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
        if isinstance(current_seq, bool) or not isinstance(current_seq, int):
            raise ValueError("current_seq must be an int")
        if current_seq < 0:
            raise ValueError("current_seq must be non-negative")

        # 1. Cost guard, dry run first: a denied call must not drain the
        #    rate bucket.
        refused = self._dry_run_ceiling(call_type, estimate)
        if refused is not None:
            raise ComboDenied(
                call_type=call_type,
                needed=estimate,
                guard=refused,
                available=self._per_call.remaining,
            )

        # 2. Rate guard: consume returns False (and records the rejection)
        #    without deducting when tokens are insufficient.
        if not self._bucket.check_and_consume(call_type, estimate, current_seq):
            raise ComboDenied(
                call_type=call_type,
                needed=estimate,
                guard=GUARD_BUCKET,
                retry_in_seqs=self._bucket.retry_in_seqs(
                    call_type, estimate, current_seq
                ),
            )

        # 3. Commit the cost charge. The dry run read identical state, so
        #    this cannot raise BudgetExhausted; assert anyway, fail-closed.
        try:
            remaining = self._per_call.check_and_charge(call_type, estimate)
        except BudgetExhausted as exc:  # pragma: no cover - dry run guarantees
            raise ComboDenied(
                call_type=exc.call_type,
                needed=exc.needed,
                guard=exc.ceiling,
                available=exc.available,
            ) from exc

        charge = ComboCharge(
            call_type=call_type,
            estimated_cost_usd=estimate,
            seq=current_seq,
            remaining_run_usd=remaining,
            tokens_left=self._bucket.tokens_for(call_type),
        )
        self._charges.append(charge)
        return charge

    def try_charge(
        self, call_type: str, estimated_cost_usd: float, current_seq: int
    ) -> tuple[bool, ComboCharge | ComboDenied]:
        """Non-raising variant: returns ``(True, charge)`` or
        ``(False, denial)``. Validation errors (unknown type, malformed
        inputs) still raise — only guard refusals are returned."""
        try:
            return True, self.check_and_charge(call_type, estimated_cost_usd, current_seq)
        except ComboDenied as denied:
            return False, denied

    def observe_model(self, usage: Any, model: str) -> Any:
        """Reconcile a model call's actual provider-reported cost.

        Delegates to the cost guard's underlying run budget.
        """
        return self._per_call.observe_model(usage, model)

    @property
    def charges(self) -> tuple[ComboCharge, ...]:
        return tuple(self._charges)

    @property
    def bucket_rejections(self) -> tuple:
        return self._bucket.rejections

    @property
    def total_spent_usd(self) -> float:
        return self._per_call.total_spent_usd

    @property
    def remaining(self) -> float | None:
        return self._per_call.remaining

    @property
    def exhausted(self) -> bool:
        return self._per_call.exhausted

    def tokens_for(self, call_type: str) -> float:
        return self._bucket.tokens_for(call_type)

    def retry_in_seqs(self, call_type: str, cost: float, current_seq: int) -> int:
        return self._bucket.retry_in_seqs(call_type, cost, current_seq)

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": BUDGET_COMBO_VERSION,
            "cost_guard": self._per_call.as_dict(),
            "rate_guard": self._bucket.as_dict(),
            "combo_charges": len(self._charges),
            "token_bucket_version": TOKEN_BUCKET_VERSION,
        }


def main() -> None:
    combo = ComboBudget(max_budget_usd=1.0)
    c1 = combo.check_and_charge("tool", 0.005, 0)
    assert c1.remaining_run_usd is not None and c1.remaining_run_usd < 1.0
    # Over the per-call ceiling: refused by the cost guard, bucket untouched.
    before = combo.tokens_for("tool")
    try:
        combo.check_and_charge("tool", 0.50, 1)
    except ComboDenied as d:
        assert d.guard == GUARD_PER_CALL, d.guard
    else:  # pragma: no cover
        raise AssertionError("expected ComboDenied")
    assert combo.tokens_for("tool") == before
    print("budget-combo OK: ceiling+bucket composed, denied calls consume nothing")


if __name__ == "__main__":
    main()


__all__ = [
    "BUDGET_COMBO_VERSION",
    "GUARD_BUCKET",
    "GUARD_CEILING",
    "GUARD_PER_CALL",
    "GUARD_RUN",
    "ComboBudget",
    "ComboCharge",
    "ComboDenied",
]
