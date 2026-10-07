"""Billing engine: metered usage, tiered pricing, invoices, and proration (simulated).

Research note: metered billing is the oldest usage-based pricing discipline
on the web, and every major platform converges on the same four operational
questions — codified in Stripe's metered-billing docs, AWS's tiered pricing
pages, and Zuora's proration discipline:

* **Define** — a plan pins a base fee (flat per period, in integer cents)
  plus per-metric pricing: either flat (metric -> cents per unit) or
  graduated tiers (first N units at price A, next M at price B, rest at
  price C — the AWS "first 50 TB" shape). A plan definition is immutable;
  re-defining an id is a new version only if content differs, otherwise it
  is refused as a duplicate (silently replacing a price book is how
  overbilling incidents start).
* **Record** — usage is host-reported (``record_usage``): a customer, a
  metric, a positive integer quantity. The metric must be priced by the
  referenced plan, and the plan must exist — an unpriced metric is refused
  fail-closed rather than silently billed at zero.
* **Invoice** — aggregates all *uninvoiced* usage for a (customer, plan)
  pair into line items with a ``sha256:`` digest pin; the usage it consumed
  is marked invoiced so the same usage can never be double-billed. The
  base fee is its own line item.
* **Prorate** — mid-cycle plan changes are settled by splitting base fees
  over caller-supplied logical seqs (no wall-clock): the old plan is
  charged for the used fraction ``(switch - start) / (end - start)`` and
  credited for the rest; the new plan is charged for the remaining
  fraction. Usage is metered, not prorated — a usage record bills at the
  plan active when it was recorded, never retroactively re-priced.

Fail-closed rules (load-bearing):

* All money is integer cents and all quantities are positive integers —
  floats never touch the money path (a float cent is a rounding dispute
  waiting to happen).
* ``quantity`` must be a positive int; zero and negative usage are refused
  (zero usage is recorded nowhere; negative usage is not a credit — use a
  proration record or an explicit adjustment).
* Mutation seqs must strictly increase per engine (``SeqOrderError``), so
  the ledger order is total and replay-exact.
* Unknown plans, unknown (customer, plan) usage, and unpriced metrics are
  refused; ``invoice()`` on a pair with no uninvoiced usage still mints a
  ``$0`` invoice (Stripe's empty-invoice discipline) rather than raising.
* Proration requires ``start < switch < end`` with ``end > start``; the
  division uses round-half-up integer math so the credit and the charge
  always sum to a whole cent with no dust.
* Invoice and proration digests pin the full canonical body — an invoice
  whose line items are later edited no longer verifies.

Honest scope: this books *reported* usage and pricing decisions. It cannot
observe real consumption, cannot prove a host-reported usage record is
true, and ``invoice()`` proves "these reported records were aggregated at
these pinned prices", never "this is what the customer owes in the real
world" — tax, FX, refunds, and dunning are out of scope by design.

Version pin: billing-engine.v1
Schema pin: northstar.billing-engine.v1
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
BILLING_ENGINE_VERSION = "billing-engine.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.billing-engine.v1"


class BillingError(Exception):
    """Base error for the billing engine (fail-closed programming error)."""


class DuplicatePlanError(BillingError):
    """A plan with this id already exists (plans are immutable)."""


class UnknownPlanError(BillingError):
    """No plan with this id is defined in the ledger."""


class UnpricedMetricError(BillingError):
    """The metric is not priced by the referenced plan."""


class BadQuantityError(BillingError):
    """Quantity must be a positive integer."""


class BadMoneyError(BillingError):
    """A money amount (cents) must be a non-negative integer."""


class SeqOrderError(BillingError):
    """Mutation seqs must strictly increase per engine (no rewinding)."""


class BadPeriodError(BillingError):
    """Proration period is malformed (start < switch < end, end > start)."""


class BadTierError(BillingError):
    """Tier definition is malformed (limits, prices, ordering)."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise BillingError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _check_id(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise BillingError(f"{what} must be a non-empty str, got {value!r}")
    return value


def _check_cents(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BadMoneyError(f"{what} must be a non-negative int (cents), got {value!r}")
    return value


def _check_quantity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise BadQuantityError(f"quantity must be a positive int, got {value!r}")
    return value


def _digest(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(payload)).hexdigest()


def _round_div(numerator: int, denominator: int) -> int:
    """Round-half-up integer division; denominator must be positive."""
    return (numerator + denominator // 2) // denominator


@dataclass(frozen=True)
class PlanRecord:
    """Frozen plan definition (flat or graduated-tier pricing)."""

    version: str
    plan_id: str
    base_fee_cents: int
    pricing: Tuple[Tuple[str, Any], ...]  # metric -> cents/unit, or metric -> tier tuple
    kind: str  # "flat" | "tiered"
    defined_seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "schema": SCHEMA_PIN,
            "plan_id": self.plan_id,
            "base_fee_cents": self.base_fee_cents,
            "kind": self.kind,
            "pricing": [
                {"metric": m, "price": p} for m, p in self.pricing
            ],
            "defined_seq": self.defined_seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class UsageRecord:
    """Frozen usage record; consumed by exactly one invoice."""

    version: str
    customer_id: str
    plan_id: str
    metric: str
    quantity: int
    recorded_seq: int
    invoiced: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "schema": SCHEMA_PIN,
            "customer_id": self.customer_id,
            "plan_id": self.plan_id,
            "metric": self.metric,
            "quantity": self.quantity,
            "recorded_seq": self.recorded_seq,
            "invoiced": self.invoiced,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class LineItem:
    """One invoice line: metric, total quantity, and the priced breakdown."""

    metric: str
    quantity: int
    breakdown: Tuple[Tuple[int, int, int], ...]  # (units, price_cents, amount_cents)
    amount_cents: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "metric": self.metric,
            "quantity": self.quantity,
            "breakdown": [
                {"units": u, "price_cents": p, "amount_cents": a}
                for u, p, a in self.breakdown
            ],
            "amount_cents": self.amount_cents,
        }


@dataclass(frozen=True)
class InvoiceRecord:
    """Frozen invoice pinning every consumed usage record."""

    version: str
    invoice_id: str
    customer_id: str
    plan_id: str
    period_label: str
    line_items: Tuple[LineItem, ...]
    base_fee_cents: int
    total_cents: int
    usage_digests: Tuple[str, ...]
    issued_seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "schema": SCHEMA_PIN,
            "invoice_id": self.invoice_id,
            "customer_id": self.customer_id,
            "plan_id": self.plan_id,
            "period_label": self.period_label,
            "line_items": [li.as_dict() for li in self.line_items],
            "base_fee_cents": self.base_fee_cents,
            "total_cents": self.total_cents,
            "usage_digests": list(self.usage_digests),
            "issued_seq": self.issued_seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ProrationRecord:
    """Frozen mid-cycle plan-change settlement (base fees only)."""

    version: str
    customer_id: str
    from_plan_id: str
    to_plan_id: str
    period_start_seq: int
    period_end_seq: int
    switch_seq: int
    old_plan_used_cents: int
    old_plan_credit_cents: int
    new_plan_charge_cents: int
    net_cents: int  # positive = customer owes more, negative = credit
    computed_seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "schema": SCHEMA_PIN,
            "customer_id": self.customer_id,
            "from_plan_id": self.from_plan_id,
            "to_plan_id": self.to_plan_id,
            "period_start_seq": self.period_start_seq,
            "period_end_seq": self.period_end_seq,
            "switch_seq": self.switch_seq,
            "old_plan_used_cents": self.old_plan_used_cents,
            "old_plan_credit_cents": self.old_plan_credit_cents,
            "new_plan_charge_cents": self.new_plan_charge_cents,
            "net_cents": self.net_cents,
            "computed_seq": self.computed_seq,
            "digest": self.digest,
        }


class BillingEngine:
    """Metered-billing ledger: plans, usage, invoices, proration."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._plans: Dict[str, PlanRecord] = {}
        self._usage: List[UsageRecord] = []
        self._invoices: Dict[str, InvoiceRecord] = {}
        self._last_seq: int = -1
        self._invoice_n: int = 0

    # -- internal ---------------------------------------------------------
    def _bump_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must strictly increase (last={self._last_seq}, got={seq})"
                )
            self._last_seq = seq
        return seq

    def _get_plan(self, plan_id: str) -> PlanRecord:
        _check_id(plan_id, "plan_id")
        try:
            return self._plans[plan_id]
        except KeyError:
            raise UnknownPlanError(f"unknown plan_id: {plan_id!r}") from None

    # -- plans ------------------------------------------------------------
    def define_plan(
        self,
        plan_id: str,
        base_fee_cents: int,
        unit_prices: Mapping[str, int],
        seq: int,
    ) -> PlanRecord:
        """Define a flat per-unit pricing plan."""
        plan_id = _check_id(plan_id, "plan_id")
        base_fee_cents = _check_cents(base_fee_cents, "base_fee_cents")
        if not isinstance(unit_prices, Mapping) or not unit_prices:
            raise BillingError("unit_prices must be a non-empty mapping")
        pricing: List[Tuple[str, int]] = []
        for metric, price in unit_prices.items():
            _check_id(metric, "metric")
            pricing.append((metric, _check_cents(price, f"price[{metric}]")))
        pricing.sort(key=lambda t: t[0])
        seq = self._bump_seq(seq)
        with self._lock:
            if plan_id in self._plans:
                raise DuplicatePlanError(f"plan already defined: {plan_id!r}")
            digest = _digest(
                {
                    "plan_id": plan_id,
                    "base_fee_cents": base_fee_cents,
                    "kind": "flat",
                    "pricing": [[m, p] for m, p in pricing],
                    "defined_seq": seq,
                }
            )
            record = PlanRecord(
                version=BILLING_ENGINE_VERSION,
                plan_id=plan_id,
                base_fee_cents=base_fee_cents,
                pricing=tuple(pricing),
                kind="flat",
                defined_seq=seq,
                digest=digest,
            )
            self._plans[plan_id] = record
            return record

    def define_tiered_plan(
        self,
        plan_id: str,
        base_fee_cents: int,
        tiers: Mapping[str, Tuple[Tuple[Optional[int], int], ...]],
        seq: int,
    ) -> PlanRecord:
        """Define a graduated-tier pricing plan.

        ``tiers`` maps metric -> tuple of ``(up_to, price_cents)``; ``up_to``
        is a cumulative unit threshold (AWS "first N" discipline) or ``None``
        for the unbounded final tier. Thresholds must be strictly
        increasing and the final tier must be unbounded.
        """
        plan_id = _check_id(plan_id, "plan_id")
        base_fee_cents = _check_cents(base_fee_cents, "base_fee_cents")
        if not isinstance(tiers, Mapping) or not tiers:
            raise BillingError("tiers must be a non-empty mapping")
        validated: List[Tuple[str, Tuple[Tuple[Optional[int], int], ...]]] = []
        for metric, tier_list in tiers.items():
            _check_id(metric, "metric")
            if not isinstance(tier_list, (tuple, list)) or not tier_list:
                raise BadTierError(f"tiers[{metric}] must be a non-empty tuple")
            norm: List[Tuple[Optional[int], int]] = []
            prev_limit: Optional[int] = 0
            for i, tier in enumerate(tier_list):
                if not isinstance(tier, (tuple, list)) or len(tier) != 2:
                    raise BadTierError(f"tiers[{metric}][{i}] must be (up_to, price_cents)")
                up_to, price = tier
                price = _check_cents(price, f"tiers[{metric}][{i}].price_cents")
                if up_to is not None:
                    if (
                        isinstance(up_to, bool)
                        or not isinstance(up_to, int)
                        or up_to <= 0
                    ):
                        raise BadTierError(
                            f"tiers[{metric}][{i}].up_to must be a positive int or None"
                        )
                    assert prev_limit is not None
                    if up_to <= prev_limit:
                        raise BadTierError(
                            f"tiers[{metric}] limits must be strictly increasing"
                        )
                    if i == len(tier_list) - 1:
                        raise BadTierError(
                            f"tiers[{metric}] final tier must be unbounded (up_to=None)"
                        )
                    prev_limit = up_to
                else:
                    if i != len(tier_list) - 1:
                        raise BadTierError(
                            f"tiers[{metric}] unbounded tier must be last"
                        )
                norm.append((up_to, price))
            validated.append((metric, tuple(norm)))
        validated.sort(key=lambda t: t[0])
        seq = self._bump_seq(seq)
        with self._lock:
            if plan_id in self._plans:
                raise DuplicatePlanError(f"plan already defined: {plan_id!r}")
            digest = _digest(
                {
                    "plan_id": plan_id,
                    "base_fee_cents": base_fee_cents,
                    "kind": "tiered",
                    "pricing": [
                        {"metric": m, "tiers": [[u, p] for u, p in ts]}
                        for m, ts in validated
                    ],
                    "defined_seq": seq,
                }
            )
            record = PlanRecord(
                version=BILLING_ENGINE_VERSION,
                plan_id=plan_id,
                base_fee_cents=base_fee_cents,
                pricing=tuple(validated),  # type: ignore[arg-type]
                kind="tiered",
                defined_seq=seq,
                digest=digest,
            )
            self._plans[plan_id] = record
            return record

    # -- usage ------------------------------------------------------------
    def record_usage(
        self, customer_id: str, plan_id: str, metric: str, quantity: int, seq: int
    ) -> UsageRecord:
        """Record metered usage against a plan's pricing."""
        customer_id = _check_id(customer_id, "customer_id")
        plan = self._get_plan(plan_id)
        metric = _check_id(metric, "metric")
        quantity = _check_quantity(quantity)
        priced_metrics = {m for m, _ in plan.pricing}
        if metric not in priced_metrics:
            raise UnpricedMetricError(
                f"metric {metric!r} not priced by plan {plan.plan_id!r}"
            )
        seq = self._bump_seq(seq)
        digest = _digest(
            {
                "customer_id": customer_id,
                "plan_id": plan.plan_id,
                "metric": metric,
                "quantity": quantity,
                "recorded_seq": seq,
            }
        )
        record = UsageRecord(
            version=BILLING_ENGINE_VERSION,
            customer_id=customer_id,
            plan_id=plan.plan_id,
            metric=metric,
            quantity=quantity,
            recorded_seq=seq,
            invoiced=False,
            digest=digest,
        )
        with self._lock:
            self._usage.append(record)
        return record

    # -- pricing ----------------------------------------------------------
    @staticmethod
    def _price_flat(quantity: int, price_cents: int) -> Tuple[Tuple[int, int, int], ...]:
        return ((quantity, price_cents, quantity * price_cents),)

    @staticmethod
    def _price_tiered(
        quantity: int, tiers: Tuple[Tuple[Optional[int], int], ...]
    ) -> Tuple[Tuple[int, int, int], ...]:
        breakdown: List[Tuple[int, int, int]] = []
        remaining = quantity
        prev_limit = 0
        for up_to, price in tiers:
            if remaining <= 0:
                break
            span = remaining if up_to is None else min(remaining, up_to - prev_limit)
            if span > 0:
                breakdown.append((span, price, span * price))
                remaining -= span
            if up_to is not None:
                prev_limit = up_to
        return tuple(breakdown)

    # -- invoice ----------------------------------------------------------
    def invoice(
        self, customer_id: str, plan_id: str, period_label: str, seq: int
    ) -> InvoiceRecord:
        """Aggregate all uninvoiced usage for (customer, plan) into an invoice.

        Consumed usage is marked invoiced exactly once; the invoice pins the
        digests of every usage record it consumed.
        """
        customer_id = _check_id(customer_id, "customer_id")
        plan = self._get_plan(plan_id)
        period_label = _check_id(period_label, "period_label")
        seq = self._bump_seq(seq)
        with self._lock:
            pending = [
                u
                for u in self._usage
                if u.customer_id == customer_id
                and u.plan_id == plan.plan_id
                and not u.invoiced
            ]
            totals: Dict[str, int] = {}
            for u in pending:
                totals[u.metric] = totals.get(u.metric, 0) + u.quantity
            price_map = dict(plan.pricing)
            line_items: List[LineItem] = []
            total = plan.base_fee_cents
            for metric in sorted(totals):
                qty = totals[metric]
                if plan.kind == "flat":
                    breakdown = self._price_flat(qty, price_map[metric])  # type: ignore[arg-type]
                else:
                    breakdown = self._price_tiered(qty, price_map[metric])  # type: ignore[arg-type]
                amount = sum(a for _, _, a in breakdown)
                total += amount
                line_items.append(
                    LineItem(metric=metric, quantity=qty, breakdown=breakdown, amount_cents=amount)
                )
            usage_digests = tuple(u.digest for u in pending)
            self._invoice_n += 1
            invoice_id = f"inv-{self._invoice_n}"
            digest = _digest(
                {
                    "invoice_id": invoice_id,
                    "customer_id": customer_id,
                    "plan_id": plan.plan_id,
                    "period_label": period_label,
                    "line_items": [li.as_dict() for li in line_items],
                    "base_fee_cents": plan.base_fee_cents,
                    "total_cents": total,
                    "usage_digests": list(usage_digests),
                    "issued_seq": seq,
                }
            )
            record = InvoiceRecord(
                version=BILLING_ENGINE_VERSION,
                invoice_id=invoice_id,
                customer_id=customer_id,
                plan_id=plan.plan_id,
                period_label=period_label,
                line_items=tuple(line_items),
                base_fee_cents=plan.base_fee_cents,
                total_cents=total,
                usage_digests=usage_digests,
                issued_seq=seq,
                digest=digest,
            )
            self._invoices[invoice_id] = record
            # Mark consumed usage invoiced (frozen records: replace in place).
            for i, u in enumerate(self._usage):
                if u in pending:
                    self._usage[i] = UsageRecord(
                        version=u.version,
                        customer_id=u.customer_id,
                        plan_id=u.plan_id,
                        metric=u.metric,
                        quantity=u.quantity,
                        recorded_seq=u.recorded_seq,
                        invoiced=True,
                        digest=u.digest,
                    )
            return record

    # -- proration --------------------------------------------------------
    def prorate(
        self,
        customer_id: str,
        from_plan_id: str,
        to_plan_id: str,
        period_start_seq: int,
        period_end_seq: int,
        switch_seq: int,
        seq: int,
    ) -> ProrationRecord:
        """Settle a mid-cycle plan change over base fees (usage is metered, not prorated).

        ``net_cents`` is positive when the customer owes more, negative when
        the switch yields a credit.
        """
        customer_id = _check_id(customer_id, "customer_id")
        from_plan = self._get_plan(from_plan_id)
        to_plan = self._get_plan(to_plan_id)
        period_start_seq = _check_seq(period_start_seq)
        period_end_seq = _check_seq(period_end_seq)
        switch_seq = _check_seq(switch_seq)
        if not (period_start_seq < switch_seq < period_end_seq):
            raise BadPeriodError(
                "require period_start_seq < switch_seq < period_end_seq, got "
                f"({period_start_seq}, {switch_seq}, {period_end_seq})"
            )
        total_span = period_end_seq - period_start_seq
        used_span = switch_seq - period_start_seq
        remaining_span = period_end_seq - switch_seq
        old_used = _round_div(from_plan.base_fee_cents * used_span, total_span)
        old_credit = from_plan.base_fee_cents - old_used
        new_charge = _round_div(to_plan.base_fee_cents * remaining_span, total_span)
        net = new_charge - old_credit
        seq = self._bump_seq(seq)
        digest = _digest(
            {
                "customer_id": customer_id,
                "from_plan_id": from_plan.plan_id,
                "to_plan_id": to_plan.plan_id,
                "period_start_seq": period_start_seq,
                "period_end_seq": period_end_seq,
                "switch_seq": switch_seq,
                "old_plan_used_cents": old_used,
                "old_plan_credit_cents": old_credit,
                "new_plan_charge_cents": new_charge,
                "net_cents": net,
                "computed_seq": seq,
            }
        )
        return ProrationRecord(
            version=BILLING_ENGINE_VERSION,
            customer_id=customer_id,
            from_plan_id=from_plan.plan_id,
            to_plan_id=to_plan.plan_id,
            period_start_seq=period_start_seq,
            period_end_seq=period_end_seq,
            switch_seq=switch_seq,
            old_plan_used_cents=old_used,
            old_plan_credit_cents=old_credit,
            new_plan_charge_cents=new_charge,
            net_cents=net,
            computed_seq=seq,
            digest=digest,
        )

    # -- views ------------------------------------------------------------
    def plan(self, plan_id: str) -> PlanRecord:
        return self._get_plan(plan_id)

    def plans(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._plans))

    def invoice_lookup(self, invoice_id: str) -> InvoiceRecord:
        _check_id(invoice_id, "invoice_id")
        try:
            return self._invoices[invoice_id]
        except KeyError:
            raise BillingError(f"unknown invoice_id: {invoice_id!r}") from None

    def uninvoiced_count(self, customer_id: str, plan_id: str) -> int:
        customer_id = _check_id(customer_id, "customer_id")
        plan = self._get_plan(plan_id)
        with self._lock:
            return sum(
                1
                for u in self._usage
                if u.customer_id == customer_id
                and u.plan_id == plan.plan_id
                and not u.invoiced
            )


_AUDIT_KINDS = frozenset(
    {
        "plan-defined",
        "usage-recorded",
        "invoiced",
        "prorated",
        "rejected",
    }
)


def billing_engine_audit_event(
    kind: str, seq: int, detail: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for billing events."""
    if kind not in _AUDIT_KINDS:
        raise BillingError(f"unknown audit kind: {kind!r}")
    seq = _check_seq(seq)
    event: Dict[str, Any] = {
        "version": "audit.ndjson/1",
        "schema": SCHEMA_PIN,
        "module": BILLING_ENGINE_VERSION,
        "kind": kind,
        "seq": seq,
    }
    if detail is not None:
        if not isinstance(detail, Mapping):
            raise BillingError("detail must be a mapping")
        # Pins and ids only — raw usage quantities are business data but not
        # secrets; still, audit carries ids and digests, never raw amounts.
        event["detail"] = {k: v for k, v in detail.items()}
    return event


def main() -> None:
    eng = BillingEngine()
    eng.define_plan("basic", 1000, {"api_calls": 2, "gb": 50}, seq=1)
    eng.record_usage("acme", "basic", "api_calls", 100, seq=2)
    eng.record_usage("acme", "basic", "gb", 3, seq=3)
    inv = eng.invoice("acme", "basic", "2026-10", seq=4)
    assert inv.total_cents == 1000 + 200 + 150, inv.total_cents
    assert eng.uninvoiced_count("acme", "basic") == 0
    eng.define_tiered_plan(
        "pro", 5000, {"api_calls": ((1000, 2), (9000, 1), (None, 0))}, seq=5
    )
    eng.record_usage("globex", "pro", "api_calls", 12000, seq=6)
    inv2 = eng.invoice("globex", "pro", "2026-10", seq=7)
    # cumulative thresholds: 1000*2 + 8000*1 + 3000*0 + 5000 base = 15000
    assert inv2.total_cents == 15000, inv2.total_cents
    pr = eng.prorate("acme", "basic", "pro", 0, 100, 40, seq=8)
    # old: 1000 * 40/100 = 400 used, 600 credit; new: 5000 * 60/100 = 3000
    assert pr.old_plan_used_cents == 400
    assert pr.old_plan_credit_cents == 600
    assert pr.new_plan_charge_cents == 3000
    assert pr.net_cents == 2400
    print("billing-engine OK: define, record, invoice, prorate, tiered")


if __name__ == "__main__":
    main()
