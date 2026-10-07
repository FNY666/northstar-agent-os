"""SaaS subscription manager: plans, trials, billing periods, cancellation (simulated).

Research note: every SaaS billing stack eventually converges on the same
four operational questions, codified in Stripe Billing's docs, Zuora's
subscription model, and the Paddle/Chargebee plan/subscription primitives:

* **Plan** — a named, priced, recurring offering: ``price_cents``,
  ``interval`` (``month``/``year``), and an optional default trial length.
  The ledger stores the plan as an immutable, digest-pinned record; a plan
  is never mutated in place — a price change is a *new* plan version (the
  Stripe "create a new price, don't edit the old one" discipline).
* **Subscribe** — bind a customer to a plan. Without a trial the
  subscription starts ``active`` at the current billing period; with a
  trial it starts ``trialing`` and flips to ``active`` when the host
  reports the trial ended (the module cannot observe time, so the caller
  supplies seqs — the trial flip is a recorded host claim, not a timer).
* **Cancel** — ``cancel_at_period_end=True`` (default, Stripe's
  cancellation schedule) vs immediate ``cancel_now()``. Either way the
  subscription record becomes terminal: no re-activation, no second cancel.
  A customer who returns buys a *new* subscription id.
* **Billing periods** — ``advance_period()`` records the host-reported
  transition from one period to the next (success or ``past_due`` on a
  reported payment failure). The ledger books *reported* outcomes; it
  never charges anything.

Expiry and trials are expressed in caller-supplied logical seqs (no
wall-clock): a trial is live while ``at_seq < trial_end_seq``; a period
is live while ``at_seq < period_end_seq``. A clock that moves backwards
cannot resurrect a canceled subscription.

Fail-closed rules (load-bearing):

* ``plan_id`` is globally unique: re-defining an existing id raises
  ``DuplicatePlanError``, even for a retired plan (plans are immutable;
  retiring sets a flag, it never deletes).
* A customer may hold at most one non-terminal subscription per plan:
  re-subscribing to the same plan while a ``trialing``/``active``/
  ``past_due`` subscription exists raises ``DuplicateSubscriptionError``
  (the Stripe "one active subscription per customer+price" shape; a
  customer CAN subscribe to a *different* plan).
* Cancellation is terminal: ``cancel()`` on a canceled subscription
  raises ``AlreadyCanceledError``; ``advance_period()`` on a canceled or
  never-subscribed id raises, never silently no-ops.
* Mutation seqs must strictly increase per manager (``SeqOrderError``),
  so the ledger order is total and replay-exact.
* Trial lengths and periods must be positive; ``price_cents`` may be
  zero (free tier) but never negative; bool numerics are rejected
  everywhere (``True`` must not alias ``1``).
* Audit events carry ids and digest pins only — no customer PII, no
  payment-method references, nothing that could name a real human.

Honest scope: this books *reported* subscription-lifecycle events. It
cannot prove a trial user actually used the product, cannot verify a
payment succeeded (``mark_paid`` records the host's report), and knows
nothing about proration, taxes, or invoicing — those are separate
ledgers. ``trialing`` and ``active`` mean "the ledger says so", never
"the customer is entitled" without an enforcement layer on top.

Version pin: subscription-manager.v1
Schema pin: northstar.subscription-manager.v1
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
SUBSCRIPTION_MANAGER_VERSION = "subscription-manager.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.subscription-manager.v1"

#: Legal billing intervals.
INTERVALS = ("month", "year")

#: Legal subscription states.
STATES = ("trialing", "active", "past_due", "canceled")

#: Terminal states: no further transitions out.
TERMINAL_STATES = ("canceled",)

#: Subscription ids carry this prefix (ledger minted).
SUBSCRIPTION_PREFIX = "sub-"


class SubscriptionError(Exception):
    """Base error for the subscription manager (fail-closed programming error)."""


class UnknownPlanError(SubscriptionError):
    """No plan with this id exists in the ledger."""


class DuplicatePlanError(SubscriptionError):
    """A plan with this id already exists (ids are never recycled)."""


class RetiredPlanError(SubscriptionError):
    """The plan exists but is retired: no new subscriptions."""


class UnknownSubscriptionError(SubscriptionError):
    """No subscription with this id exists in the ledger."""


class DuplicateSubscriptionError(SubscriptionError):
    """Customer already holds a non-terminal subscription to this plan."""


class AlreadyCanceledError(SubscriptionError):
    """The subscription is already canceled (cancellation is terminal)."""


class SeqOrderError(SubscriptionError):
    """Mutation seq did not strictly increase (ledger must be total)."""


def _check_seq(seq: Any, name: str = "seq") -> int:
    """Validate a caller-supplied logical sequence number."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SubscriptionError(f"{name} must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SubscriptionError(f"{name} must be non-negative")
    return seq


def _check_positive_int(value: Any, name: str) -> int:
    """Validate a strictly positive int (bool is not a number here)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SubscriptionError(f"{name} must be an int, got {type(value).__name__}")
    if value <= 0:
        raise SubscriptionError(f"{name} must be positive")
    return value


def _check_non_negative_int(value: Any, name: str) -> int:
    """Validate a non-negative int (bool is not a number here)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SubscriptionError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise SubscriptionError(f"{name} must be non-negative")
    return value


def _check_id(value: Any, name: str) -> str:
    """Validate a non-empty str identifier."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise SubscriptionError(f"{name} must be a str, got {type(value).__name__}")
    if not value.strip():
        raise SubscriptionError(f"{name} must not be empty")
    return value


def _digest(body: Any) -> str:
    """sha256: digest pin over a canonicalized body (type-tagged encoding)."""
    encoded = _type_tagged(body)
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _type_tagged(value: Any) -> bytes:
    """Type-tagged canonical encoding: bool != int != str, NaN/inf refused.

    Integral floats with |v| > 2**53 are refused fail-closed (the batch-5
    JCS float-loss caveat: JSON would silently round them).
    """
    if value is None:
        return b"null"
    if isinstance(value, bool):
        return b"b:" + (b"1" if value else b"0")
    if isinstance(value, int):
        return b"i:" + str(value).encode()
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise SubscriptionError("NaN/inf values are refused")
        if value.is_integer() and abs(value) > 2**53:
            raise SubscriptionError("integral float with |v| > 2**53 refused")
        return b"f:" + repr(value).encode()
    if isinstance(value, str):
        return b"s:" + value.encode("utf-8")
    if isinstance(value, (list, tuple)):
        parts = b",".join(_type_tagged(v) for v in value)
        return b"l:[" + parts + b"]"
    if isinstance(value, dict):
        items = sorted(
            ((k if isinstance(k, str) else repr(k)), v) for k, v in value.items()
        )
        parts = b",".join(_type_tagged(k) + b"=" + _type_tagged(v) for k, v in items)
        return b"m:{" + parts + b"}"
    # Fallback to the canonicalizer for anything else (must canonicalize).
    return b"j:" + jcs_canonical_json(value)


@dataclass(frozen=True)
class PlanRecord:
    """Immutable, digest-pinned plan definition."""

    plan_id: str
    name: str
    price_cents: int
    interval: str
    trial_period_seqs: int
    retired: bool
    seq: int
    digest: str
    version: str = SUBSCRIPTION_MANAGER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "name": self.name,
            "price_cents": self.price_cents,
            "interval": self.interval,
            "trial_period_seqs": self.trial_period_seqs,
            "retired": self.retired,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; False on any mismatch (never raises)."""
        try:
            return hmac.compare_digest(self.digest, _plan_digest(self))
        except SubscriptionError:
            return False


def _plan_digest(plan: PlanRecord) -> str:
    return _digest(
        {
            "plan_id": plan.plan_id,
            "name": plan.name,
            "price_cents": plan.price_cents,
            "interval": plan.interval,
            "trial_period_seqs": plan.trial_period_seqs,
            "retired": plan.retired,
            "seq": plan.seq,
        }
    )


@dataclass(frozen=True)
class SubscriptionRecord:
    """Immutable snapshot of a subscription at one point in its life."""

    subscription_id: str
    customer_id: str
    plan_id: str
    state: str
    trial_end_seq: Optional[int]
    period_start_seq: int
    period_end_seq: Optional[int]
    cancel_at_period_end: bool
    seq: int
    digest: str
    version: str = SUBSCRIPTION_MANAGER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "subscription_id": self.subscription_id,
            "customer_id": self.customer_id,
            "plan_id": self.plan_id,
            "state": self.state,
            "trial_end_seq": self.trial_end_seq,
            "period_start_seq": self.period_start_seq,
            "period_end_seq": self.period_end_seq,
            "cancel_at_period_end": self.cancel_at_period_end,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; False on any mismatch (never raises)."""
        try:
            return hmac.compare_digest(self.digest, _subscription_digest(self))
        except SubscriptionError:
            return False


def _subscription_digest(sub: SubscriptionRecord) -> str:
    return _digest(
        {
            "subscription_id": sub.subscription_id,
            "customer_id": sub.customer_id,
            "plan_id": sub.plan_id,
            "state": sub.state,
            "trial_end_seq": sub.trial_end_seq,
            "period_start_seq": sub.period_start_seq,
            "period_end_seq": sub.period_end_seq,
            "cancel_at_period_end": sub.cancel_at_period_end,
            "seq": sub.seq,
        }
    )


@dataclass(frozen=True)
class PeriodTransition:
    """One recorded billing-period advance."""

    subscription_id: str
    from_seq: int
    to_seq: int
    outcome: str  # "paid" | "past_due"
    seq: int
    digest: str
    version: str = SUBSCRIPTION_MANAGER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "subscription_id": self.subscription_id,
            "from_seq": self.from_seq,
            "to_seq": self.to_seq,
            "outcome": self.outcome,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class CancellationRecord:
    """Terminal cancellation record."""

    subscription_id: str
    cancel_at_period_end: bool
    effective_seq: int
    seq: int
    digest: str
    version: str = SUBSCRIPTION_MANAGER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "subscription_id": self.subscription_id,
            "cancel_at_period_end": self.cancel_at_period_end,
            "effective_seq": self.effective_seq,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


class SubscriptionManager:
    """SaaS subscription lifecycle ledger (deterministic, single-host).

    Plans are defined once (immutable); customers subscribe to plans,
    optionally starting with a trial; billing periods advance on
    host-reported outcomes; cancellation is terminal.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._plans: Dict[str, PlanRecord] = {}
        self._subscriptions: Dict[str, Dict[str, Any]] = {}  # id -> mutable ledger row
        self._last_seq = -1
        self._next_sub = 0
        self._periods: List[PeriodTransition] = []
        self._cancellations: Dict[str, CancellationRecord] = {}

    # -- internal ------------------------------------------------------

    def _bump_seq(self, seq: int) -> int:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase: got {seq}, last was {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _get_row(self, subscription_id: str) -> Dict[str, Any]:
        _check_id(subscription_id, "subscription_id")
        row = self._subscriptions.get(subscription_id)
        if row is None:
            raise UnknownSubscriptionError(f"unknown subscription: {subscription_id}")
        return row

    # -- plans ----------------------------------------------------------

    def define_plan(
        self,
        plan_id: str,
        name: str,
        price_cents: int,
        interval: str,
        seq: int,
        trial_period_seqs: int = 0,
    ) -> PlanRecord:
        """Define an immutable plan. Duplicate ids are refused fail-closed."""
        with self._lock:
            self._bump_seq(seq)
            _check_id(plan_id, "plan_id")
            _check_id(name, "name")
            _check_non_negative_int(price_cents, "price_cents")
            if isinstance(interval, bool) or interval not in INTERVALS:
                raise SubscriptionError(f"interval must be one of {INTERVALS}")
            _check_non_negative_int(trial_period_seqs, "trial_period_seqs")
            if plan_id in self._plans:
                raise DuplicatePlanError(f"plan already defined: {plan_id}")
            record = PlanRecord(
                plan_id=plan_id,
                name=name,
                price_cents=price_cents,
                interval=interval,
                trial_period_seqs=trial_period_seqs,
                retired=False,
                seq=seq,
                digest="",
            )
            record = PlanRecord(
                **{**record.as_dict(), "digest": _plan_digest(record)}
            )
            self._plans[plan_id] = record
            return record

    def retire_plan(self, plan_id: str, seq: int) -> PlanRecord:
        """Retire a plan: no new subscriptions, existing ones untouched."""
        with self._lock:
            self._bump_seq(seq)
            _check_id(plan_id, "plan_id")
            plan = self._plans.get(plan_id)
            if plan is None:
                raise UnknownPlanError(f"unknown plan: {plan_id}")
            retired = PlanRecord(
                **{**plan.as_dict(), "retired": True, "seq": seq, "digest": ""}
            )
            retired = PlanRecord(
                **{**retired.as_dict(), "digest": _plan_digest(retired)}
            )
            self._plans[plan_id] = retired
            return retired

    def plan(self, plan_id: str) -> PlanRecord:
        """Look up a plan; unknown ids raise (never a silent default)."""
        _check_id(plan_id, "plan_id")
        plan = self._plans.get(plan_id)
        if plan is None:
            raise UnknownPlanError(f"unknown plan: {plan_id}")
        return plan

    def plan_ids(self) -> Tuple[str, ...]:
        """All defined plan ids, sorted."""
        return tuple(sorted(self._plans))

    # -- subscriptions ----------------------------------------------------

    def subscribe(
        self,
        customer_id: str,
        plan_id: str,
        seq: int,
        trial: bool = False,
    ) -> SubscriptionRecord:
        """Bind a customer to a plan.

        ``trial=True`` starts the subscription in ``trialing`` when the
        plan offers a trial (``trial_period_seqs > 0``); otherwise the
        trial flag is refused fail-closed (a plan without a trial offer
        cannot mint a trial subscription).
        """
        with self._lock:
            self._bump_seq(seq)
            _check_id(customer_id, "customer_id")
            _check_id(plan_id, "plan_id")
            if isinstance(trial, bool) is False:
                raise SubscriptionError("trial must be a bool")
            plan = self.plan(plan_id)
            if plan.retired:
                raise RetiredPlanError(f"plan is retired: {plan_id}")
            for row in self._subscriptions.values():
                if (
                    row["customer_id"] == customer_id
                    and row["plan_id"] == plan_id
                    and row["state"] not in TERMINAL_STATES
                ):
                    raise DuplicateSubscriptionError(
                        f"customer {customer_id} already holds a non-terminal "
                        f"subscription to plan {plan_id}"
                    )
            if trial and plan.trial_period_seqs == 0:
                raise SubscriptionError(
                    f"plan {plan_id} offers no trial; trial=True refused"
                )
            self._next_sub += 1
            subscription_id = f"{SUBSCRIPTION_PREFIX}{self._next_sub}"
            if trial:
                state = "trialing"
                trial_end: Optional[int] = seq + plan.trial_period_seqs
                period_start = seq
                period_end: Optional[int] = None
            else:
                state = "active"
                trial_end = None
                period_start = seq
                period_end = None
            row = {
                "subscription_id": subscription_id,
                "customer_id": customer_id,
                "plan_id": plan_id,
                "state": state,
                "trial_end_seq": trial_end,
                "period_start_seq": period_start,
                "period_end_seq": period_end,
                "cancel_at_period_end": False,
            }
            self._subscriptions[subscription_id] = row
            return self._snapshot(subscription_id, seq)

    def trial(self, customer_id: str, plan_id: str, seq: int) -> SubscriptionRecord:
        """Start a trial subscription (convenience for subscribe(trial=True)).

        Fail-closed: the plan must offer a trial, otherwise raises.
        """
        return self.subscribe(customer_id, plan_id, seq, trial=True)

    def end_trial(self, subscription_id: str, seq: int) -> SubscriptionRecord:
        """Record the host-reported end of a trial: trialing -> active."""
        with self._lock:
            self._bump_seq(seq)
            row = self._get_row(subscription_id)
            if row["state"] != "trialing":
                raise SubscriptionError(
                    f"end_trial requires trialing state, got {row['state']}"
                )
            row["state"] = "active"
            row["period_start_seq"] = seq
            return self._snapshot(subscription_id, seq)

    def advance_period(
        self,
        subscription_id: str,
        seq: int,
        period_end_seq: int,
        paid: bool = True,
    ) -> PeriodTransition:
        """Record a host-reported billing-period transition.

        ``paid=True`` keeps the subscription ``active``; ``paid=False``
        moves it to ``past_due``. Only ``active`` subscriptions can
        advance (trials must end first; past_due must be resolved with
        ``mark_paid``; canceled is terminal).
        """
        with self._lock:
            self._bump_seq(seq)
            row = self._get_row(subscription_id)
            if isinstance(paid, bool) is False:
                raise SubscriptionError("paid must be a bool")
            _check_seq(period_end_seq, "period_end_seq")
            if period_end_seq <= row["period_start_seq"]:
                raise SubscriptionError(
                    "period_end_seq must exceed the current period start"
                )
            if row["state"] != "active":
                raise SubscriptionError(
                    f"advance_period requires active state, got {row['state']}"
                )
            outcome = "paid" if paid else "past_due"
            transition = PeriodTransition(
                subscription_id=subscription_id,
                from_seq=row["period_start_seq"],
                to_seq=period_end_seq,
                outcome=outcome,
                seq=seq,
                digest="",
            )
            transition = PeriodTransition(
                **{
                    **transition.as_dict(),
                    "digest": _digest(transition.as_dict()),
                }
            )
            row["period_start_seq"] = period_end_seq
            row["period_end_seq"] = None
            if not paid:
                row["state"] = "past_due"
            self._periods.append(transition)
            return transition

    def mark_paid(self, subscription_id: str, seq: int) -> SubscriptionRecord:
        """Record host-reported recovery from past_due: past_due -> active."""
        with self._lock:
            self._bump_seq(seq)
            row = self._get_row(subscription_id)
            if row["state"] != "past_due":
                raise SubscriptionError(
                    f"mark_paid requires past_due state, got {row['state']}"
                )
            row["state"] = "active"
            return self._snapshot(subscription_id, seq)

    # -- cancellation ------------------------------------------------------

    def cancel(
        self,
        subscription_id: str,
        seq: int,
        at_period_end: bool = True,
    ) -> CancellationRecord:
        """Cancel a subscription.

        ``at_period_end=True`` (default, Stripe discipline): the
        subscription stays ``active`` until the host reports the period
        end, then flips to ``canceled``. ``at_period_end=False`` cancels
        immediately. Cancellation is terminal either way.
        """
        with self._lock:
            self._bump_seq(seq)
            if isinstance(at_period_end, bool) is False:
                raise SubscriptionError("at_period_end must be a bool")
            row = self._get_row(subscription_id)
            if row["state"] in TERMINAL_STATES:
                raise AlreadyCanceledError(
                    f"subscription already canceled: {subscription_id}"
                )
            if at_period_end:
                row["cancel_at_period_end"] = True
                effective = row["period_end_seq"] if row["period_end_seq"] else seq
            else:
                row["state"] = "canceled"
                effective = seq
            record = CancellationRecord(
                subscription_id=subscription_id,
                cancel_at_period_end=at_period_end,
                effective_seq=effective if isinstance(effective, int) else seq,
                seq=seq,
                digest="",
            )
            record = CancellationRecord(
                **{**record.as_dict(), "digest": _digest(record.as_dict())}
            )
            self._cancellations[subscription_id] = record
            return record

    def cancel_now(self, subscription_id: str, seq: int) -> CancellationRecord:
        """Immediate cancellation (convenience for cancel(at_period_end=False))."""
        return self.cancel(subscription_id, seq, at_period_end=False)

    def finalize_cancellation(self, subscription_id: str, seq: int) -> SubscriptionRecord:
        """Flip a scheduled cancellation to terminal at the host-reported period end."""
        with self._lock:
            self._bump_seq(seq)
            row = self._get_row(subscription_id)
            if not row["cancel_at_period_end"]:
                raise SubscriptionError(
                    "finalize_cancellation requires a scheduled cancellation"
                )
            if row["state"] in TERMINAL_STATES:
                raise AlreadyCanceledError(
                    f"subscription already canceled: {subscription_id}"
                )
            row["state"] = "canceled"
            row["cancel_at_period_end"] = False
            return self._snapshot(subscription_id, seq)

    # -- views ---------------------------------------------------------------

    def subscription(self, subscription_id: str) -> SubscriptionRecord:
        """Latest snapshot of a subscription; unknown ids raise."""
        row = self._get_row(subscription_id)
        return self._snapshot(subscription_id, self._last_seq)

    def subscriptions(
        self, customer_id: Optional[str] = None, state: Optional[str] = None
    ) -> Tuple[SubscriptionRecord, ...]:
        """All subscriptions, optionally filtered by customer and/or state."""
        if customer_id is not None:
            _check_id(customer_id, "customer_id")
        if state is not None:
            if isinstance(state, bool) or state not in STATES:
                raise SubscriptionError(f"unknown state: {state!r}")
        out = []
        for row in self._subscriptions.values():
            if customer_id is not None and row["customer_id"] != customer_id:
                continue
            if state is not None and row["state"] != state:
                continue
            out.append(self._snapshot(row["subscription_id"], self._last_seq))
        return tuple(out)

    def subscription_ids(self) -> Tuple[str, ...]:
        """All subscription ids, sorted."""
        return tuple(sorted(self._subscriptions))

    def is_active(self, subscription_id: str, at_seq: int) -> bool:
        """Whether the subscription is non-terminal at a caller-supplied seq."""
        _check_seq(at_seq, "at_seq")
        row = self._get_row(subscription_id)
        if row["state"] in TERMINAL_STATES:
            return False
        if row["state"] == "trialing" and row["trial_end_seq"] is not None:
            return at_seq < row["trial_end_seq"]
        return True

    def cancellation(self, subscription_id: str) -> Optional[CancellationRecord]:
        """The cancellation record, or None if never canceled."""
        _check_id(subscription_id, "subscription_id")
        return self._cancellations.get(subscription_id)

    def _snapshot(self, subscription_id: str, seq: int) -> SubscriptionRecord:
        row = self._subscriptions[subscription_id]
        sub = SubscriptionRecord(
            subscription_id=row["subscription_id"],
            customer_id=row["customer_id"],
            plan_id=row["plan_id"],
            state=row["state"],
            trial_end_seq=row["trial_end_seq"],
            period_start_seq=row["period_start_seq"],
            period_end_seq=row["period_end_seq"],
            cancel_at_period_end=row["cancel_at_period_end"],
            seq=seq,
            digest="",
        )
        return SubscriptionRecord(
            **{**sub.as_dict(), "digest": _subscription_digest(sub)}
        )


# -- audit events ----------------------------------------------------------

_AUDIT_KINDS = (
    "plan-defined",
    "plan-retired",
    "subscribed",
    "trial-started",
    "trial-ended",
    "period-advanced",
    "marked-paid",
    "canceled",
    "cancellation-finalized",
    "rejected",
)


def subscription_manager_audit_event(
    kind: str, seq: int, detail: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for this module.

    Carries ids and digest pins only — never customer PII or payment
    references. Unknown kinds and bad seqs are refused fail-closed.
    """
    if kind not in _AUDIT_KINDS:
        raise SubscriptionError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    body: Dict[str, Any] = {
        "version": "audit.ndjson/1",
        "schema": "northstar.subscription-manager.v1",
        "kind": kind,
        "seq": seq,
    }
    if detail is not None:
        if not isinstance(detail, dict):
            raise SubscriptionError("detail must be a mapping")
        safe: Dict[str, Any] = {}
        for key, value in detail.items():
            if not isinstance(key, str) or not key:
                raise SubscriptionError("detail keys must be non-empty str")
            if isinstance(value, (str, int)) and not isinstance(value, bool):
                safe[key] = value
            else:
                # Non-scalar details are pinned, never inlined.
                safe[key + "_digest"] = _digest(value)
        body["detail"] = safe
    return body


def main() -> None:
    mgr = SubscriptionManager()
    mgr.define_plan("pro", "Pro", 2000, "month", 1, trial_period_seqs=10)
    sub = mgr.trial("cust-1", "pro", 2)
    assert sub.state == "trialing"
    sub = mgr.end_trial(sub.subscription_id, 12)
    assert sub.state == "active"
    t = mgr.advance_period(sub.subscription_id, 13, 100, paid=True)
    assert t.outcome == "paid"
    rec = mgr.cancel(sub.subscription_id, 14, at_period_end=False)
    assert mgr.subscription(sub.subscription_id).state == "canceled"
    assert rec.cancel_at_period_end is False
    print("subscription-manager OK: define, trial, end_trial, advance, cancel")


if __name__ == "__main__":
    main()
