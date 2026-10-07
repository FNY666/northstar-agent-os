"""Tenant billing: multi-tenant usage metering and invoicing bookkeeping.

Research note: every SaaS metering stack (Stripe Billing's metered usage,
AWS's per-tenant usage records, Cloudflare's per-zone metering) converges on
the same operational core, codified here as a deterministic single-host
ledger:

* **Tier** — ``define_tier(tier_id, seq, name, base_cents, included=,
  overage=)`` pins a pricing contract as a frozen ``TierRecord``:
  a flat ``base_cents`` per period plus, per meter kind, an included
  quota and an overage price in cents per unit. Tiers are immutable;
  a price change is a *new* tier id (the Stripe "create a new price,
  don't edit the old one" discipline).
* **Provision** — ``provision(tenant_id, tier_id, seq)`` binds a tenant
  to a tier. Tenant ids are never recycled; suspend/reactivate flips
  status, never deletes history.
* **Meter** — ``meter(tenant_id, meter_kind, seq, quantity)`` books
  *host-reported* usage as a hash-chained ``MeterRecord`` (``mtr-N``
  ids). Quantity is a positive int; the module never observes the
  wire — a meter record means "the host reported N units", never
  "the tenant consumed N units".
* **Invoice** — ``invoice(tenant_id, seq, period)`` aggregates the
  tenant's usage since the previous invoice into a frozen
  ``InvoiceRecord`` (``inv-N`` ids): per-meter line items with
  used/included/billable/unit_cents/amount_cents, plus the tier base
  line. All money is integer cents; the total is exact. Invoicing
  resets the tenant's unbilled usage buckets. One invoice per
  (tenant, period) — the second attempt raises fail-closed.
* **Settle** — ``mark_paid(invoice_id, seq)`` and
  ``void(invoice_id, seq)`` are terminal status transitions on the
  same invoice id; double-pay, void-after-paid, and double-void raise
  fail-closed.

Fail-closed rules (load-bearing):

* Tier and tenant ids are globally unique: re-defining raises
  ``DuplicateTierError``/``DuplicateTenantError`` even after the
  original is retired (ids are never recycled).
* Meter kinds are a pinned vocabulary
  (``api_calls``/``compute_seconds``/``storage_gb_hours``/``seats``);
  unknown kinds raise ``UnknownMeterKindError`` at define *and* meter
  time.
* All money is integer cents (bool refused, floats refused,
  negatives refused); quantities are positive ints (bool refused).
* ``meter()`` on a suspended tenant raises ``SuspendedTenantError``
  — usage during suspension is dropped loudly, never booked.
* Mutation seqs must strictly increase per manager
  (``SeqOrderError``); failed mutations consume their seq (batch-21
  ledger discipline), so the audit trail is totally ordered.
* Audit events carry ids and digest pins only — no tenant names,
  no meter values beyond counts, nothing that could name a real
  customer.

Honest scope: this books *reported* metering and billing decisions.
It cannot prove usage happened, cannot charge a card, and knows
nothing about taxes, proration across tier changes, or dunning —
those are separate ledgers. An ``open`` invoice means "the ledger
says so", never "the tenant owes it" without an enforcement layer.

Version pin: tenant-billing.v1
Schema pin: northstar.tenant-billing.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version pin.
TENANT_BILLING_VERSION = "tenant-billing.v1"

#: Schema pin carried by records.
SCHEMA_PIN = "northstar.tenant-billing.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned meter-kind vocabulary.
METER_KINDS = ("api_calls", "compute_seconds", "storage_gb_hours", "seats")

#: Pinned tenant statuses.
STATUSES = ("active", "suspended")

#: Pinned invoice statuses.
INVOICE_STATUSES = ("open", "paid", "voided")

#: Max safe int for digest pins (batch-5 JCS discipline).
_MAX_SAFE_INT = 2**53

#: Meter record ids carry this prefix.
_METER_PREFIX = "mtr-"

#: Invoice ids carry this prefix.
_INVOICE_PREFIX = "inv-"

# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class TenantBillingError(Exception):
    """Base error for the tenant billing ledger (fail-closed)."""


class DuplicateTierError(TenantBillingError):
    """A tier with this id already exists (ids are never recycled)."""


class UnknownTierError(TenantBillingError):
    """No tier with this id exists in the ledger."""


class DuplicateTenantError(TenantBillingError):
    """A tenant with this id already exists (ids are never recycled)."""


class UnknownTenantError(TenantBillingError):
    """No tenant with this id exists in the ledger."""


class SuspendedTenantError(TenantBillingError):
    """The tenant is suspended: usage may not be booked."""


class UnknownMeterKindError(TenantBillingError):
    """The meter kind is not in the pinned vocabulary."""


class BadQuantityError(TenantBillingError):
    """A metered quantity was not a positive int."""


class BadMoneyError(TenantBillingError):
    """A money amount was not a non-negative integer cents value."""


class UnknownInvoiceError(TenantBillingError):
    """No invoice with this id exists in the ledger."""


class DuplicateInvoiceError(TenantBillingError):
    """This tenant already has an invoice for this period."""


class AlreadyPaidError(TenantBillingError):
    """The invoice is already paid (payment is terminal)."""


class VoidedInvoiceError(TenantBillingError):
    """The invoice is already voided (voiding is terminal)."""


class PaidInvoiceError(TenantBillingError):
    """A paid invoice may not be voided."""


class SeqOrderError(TenantBillingError):
    """Mutation seq did not strictly increase (ledger must be total)."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any, name: str = "seq") -> int:
    """Validate a caller-supplied logical sequence number."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TenantBillingError(f"{name} must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise TenantBillingError(f"{name} must be non-negative")
    return seq


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TenantBillingError(f"{name} must be a non-empty str")
    return value.strip()


def _check_cents(value: Any, name: str) -> int:
    """Validate an integer-cents money amount (no bool, no float, no negative)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadMoneyError(f"{name} must be integer cents, got {type(value).__name__}")
    if value < 0:
        raise BadMoneyError(f"{name} must be non-negative")
    if value >= _MAX_SAFE_INT:
        raise BadMoneyError(f"{name} outside +/-2^53 refused")
    return value


def _check_quantity(value: Any, name: str = "quantity") -> int:
    """Validate a metered quantity: positive int, no bool."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadQuantityError(f"{name} must be a positive int, got {type(value).__name__}")
    if value <= 0:
        raise BadQuantityError(f"{name} must be positive")
    if value >= _MAX_SAFE_INT:
        raise BadQuantityError(f"{name} outside +/-2^53 refused")
    return value


def _check_meter_kind(value: Any) -> str:
    if value not in METER_KINDS:
        raise UnknownMeterKindError(f"unknown meter kind: {value!r}")
    return value


def _norm_quota_map(mapping: Any, name: str) -> Tuple[Tuple[str, int], ...]:
    """Normalize a meter-kind -> int mapping fail-closed."""
    if not isinstance(mapping, Mapping):
        raise TenantBillingError(f"{name} must be a mapping")
    out: List[Tuple[str, int]] = []
    for kind, qty in mapping.items():
        _check_meter_kind(kind)
        if isinstance(qty, bool) or not isinstance(qty, int):
            raise TenantBillingError(f"{name}[{kind!r}] must be an int")
        if qty < 0 or qty >= _MAX_SAFE_INT:
            raise TenantBillingError(f"{name}[{kind!r}] out of range")
        out.append((kind, qty))
    return tuple(sorted(out))


def _norm_overage_map(mapping: Any, name: str) -> Tuple[Tuple[str, int], ...]:
    """Normalize a meter-kind -> cents-per-unit mapping fail-closed."""
    if not isinstance(mapping, Mapping):
        raise TenantBillingError(f"{name} must be a mapping")
    out: List[Tuple[str, int]] = []
    for kind, cents in mapping.items():
        _check_meter_kind(kind)
        _check_cents(cents, f"{name}[{kind!r}]")
        out.append((kind, cents))
    return tuple(sorted(out))


def _tag(value: Any) -> Any:
    """Type-tagged canonical form: bool != int; floats refused."""
    if value is None:
        return ["n"]
    if isinstance(value, bool):
        return ["b", value]
    if isinstance(value, int):
        if abs(value) >= _MAX_SAFE_INT:
            raise TenantBillingError(f"int outside +/-2^53 refused: {value!r}")
        return ["i", value]
    if isinstance(value, float):
        raise TenantBillingError(f"floats refused at the billing boundary: {value!r}")
    if isinstance(value, str):
        if len(value) > 65536:
            raise TenantBillingError("str longer than 65536 chars refused")
        return ["s", value]
    if isinstance(value, (list, tuple)):
        if len(value) > 10000:
            raise TenantBillingError("list longer than 10000 items refused")
        return ["l", [_tag(item) for item in value]]
    if isinstance(value, dict):
        if len(value) > 10000:
            raise TenantBillingError("dict larger than 10000 entries refused")
        for k in value:
            if not isinstance(k, str):
                raise TenantBillingError("dict keys must be str")
        return ["d", [[k, _tag(value[k])] for k in sorted(value)]]
    raise TenantBillingError(f"unencodable value type: {type(value).__name__}")


def _pin(*parts: Any) -> str:
    """Pin a sha256 digest over the type-tagged canonical encoding."""
    body = jcs_canonical_json(_tag([TENANT_BILLING_VERSION, *parts]))
    return f"sha256:{hashlib.sha256(body).hexdigest()}"


def _line_parts(lines: Tuple["LineItem", ...]) -> List[List[Any]]:
    return [
        [li.kind, li.used, li.included, li.billable, li.unit_cents, li.amount_cents]
        for li in lines
    ]


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "tier-defined",
    "tenant-provisioned",
    "tenant-suspended",
    "tenant-reactivated",
    "usage-metered",
    "invoiced",
    "invoice-paid",
    "invoice-voided",
    "rejected",
)


def tenant_billing_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the tenant billing ledger."""
    if kind not in _AUDIT_KINDS:
        raise TenantBillingError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise TenantBillingError("detail must be a mapping")
    # Meter values and tenant names never cross the audit boundary;
    # ids and digest pins only.
    banned = {"tenant_name", "usage_values", "line_details", "reason_text"}
    if any(k in detail for k in banned):
        raise TenantBillingError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": TENANT_BILLING_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TierRecord:
    """One pinned pricing tier (frozen, immutable)."""

    tier_id: str
    name: str
    base_cents: int
    included: Tuple[Tuple[str, int], ...]
    overage_cents: Tuple[Tuple[str, int], ...]
    seq: int
    prev_digest: str
    digest: str

    def verify(self) -> None:
        """Re-derive the digest pin; raise on mismatch."""
        expected = _pin(
            "tier",
            self.prev_digest,
            self.seq,
            self.tier_id,
            self.name,
            self.base_cents,
            [list(p) for p in self.included],
            [list(p) for p in self.overage_cents],
        )
        if self.digest != expected:
            raise TenantBillingError("tier digest mismatch")


@dataclass(frozen=True)
class TenantRecord:
    """One provisioned tenant (frozen snapshot of the binding)."""

    tenant_id: str
    tier_id: str
    tier_digest: str
    status: str
    seq: int
    prev_digest: str
    digest: str

    def verify(self) -> None:
        """Re-derive the digest pin; raise on mismatch."""
        expected = _pin(
            "tenant",
            self.prev_digest,
            self.seq,
            self.tenant_id,
            self.tier_id,
            self.tier_digest,
            self.status,
        )
        if self.digest != expected:
            raise TenantBillingError("tenant digest mismatch")


@dataclass(frozen=True)
class MeterRecord:
    """One booked usage event (frozen, hash-chained)."""

    meter_id: str
    tenant_id: str
    meter_kind: str
    quantity: int
    seq: int
    prev_digest: str
    digest: str

    def verify(self) -> None:
        """Re-derive the digest pin; raise on mismatch."""
        expected = _pin(
            "meter",
            self.prev_digest,
            self.seq,
            self.meter_id,
            self.tenant_id,
            self.meter_kind,
            self.quantity,
        )
        if self.digest != expected:
            raise TenantBillingError("meter digest mismatch")


@dataclass(frozen=True)
class LineItem:
    """One invoice line: used/included/billable/units/amount (frozen)."""

    kind: str
    used: int
    included: int
    billable: int
    unit_cents: int
    amount_cents: int


@dataclass(frozen=True)
class InvoiceRecord:
    """One computed invoice (frozen; status transitions re-pin)."""

    invoice_id: str
    tenant_id: str
    tier_id: str
    tier_digest: str
    period: str
    lines: Tuple[LineItem, ...]
    total_cents: int
    status: str
    seq: int
    prev_digest: str
    digest: str

    def verify(self) -> None:
        """Re-derive the digest pin; raise on mismatch."""
        expected = _pin(
            "invoice",
            self.prev_digest,
            self.seq,
            self.invoice_id,
            self.tenant_id,
            self.tier_id,
            self.tier_digest,
            self.period,
            _line_parts(self.lines),
            self.total_cents,
            self.status,
        )
        if self.digest != expected:
            raise TenantBillingError("invoice digest mismatch")


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class TenantBilling:
    """Deterministic multi-tenant metering/invoicing ledger.

    All mutation methods take the seq first (batch-21 discipline):
    failed mutations consume their seq. Pure views validate the seq
    shape without consuming it.
    """

    def __init__(self, seed: str = "tenant-billing") -> None:
        self._lock = threading.RLock()
        self._seed = _check_nonempty_str(seed, "seed")
        self._last_seq = -1
        self._tiers: Dict[str, TierRecord] = {}
        self._tenants: Dict[str, TenantRecord] = {}
        self._meters: Dict[str, MeterRecord] = {}
        self._invoices: Dict[str, InvoiceRecord] = {}
        self._usage: Dict[str, Dict[str, int]] = {}  # tenant -> kind -> unbilled
        self._invoiced_periods: Dict[str, set] = {}  # tenant -> {period}
        self._meter_counter = 0
        self._invoice_counter = 0
        self._audit_log: List[Dict[str, Any]] = []
        self._prev_digest = _pin("genesis", self._seed)

    # -- internals ------------------------------------------------------

    def _take_seq(self, seq: Any) -> int:
        """Consume a mutation seq (strictly increasing)."""
        value = _check_seq(seq, "seq")
        if value <= self._last_seq:
            raise SeqOrderError(f"seq must exceed {self._last_seq}, got {value}")
        self._last_seq = value
        return value

    def _audit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(tenant_billing_audit_event(kind, detail, seq))

    def _chain(self, tag: str, seq: int, *parts: Any) -> Tuple[str, str]:
        """Compute the next digest pin and advance the chain; returns (prev, digest)."""
        prev = self._prev_digest
        digest = _pin(tag, prev, seq, *parts)
        self._prev_digest = digest
        return prev, digest

    # -- tiers ----------------------------------------------------------

    def define_tier(
        self,
        tier_id: str,
        seq: int,
        name: str,
        base_cents: int,
        included: Optional[Mapping[str, int]] = None,
        overage: Optional[Mapping[str, int]] = None,
    ) -> TierRecord:
        """Pin a pricing tier as an immutable, digest-sealed record."""
        with self._lock:
            seq = self._take_seq(seq)
            try:
                tier_id = _check_nonempty_str(tier_id, "tier_id")
                name = _check_nonempty_str(name, "name")
                base_cents = _check_cents(base_cents, "base_cents")
                included_t = _norm_quota_map(included or {}, "included")
                overage_t = _norm_overage_map(overage or {}, "overage")
                if tier_id in self._tiers:
                    raise DuplicateTierError(f"tier already exists: {tier_id!r}")
                inc_parts = [list(p) for p in included_t]
                ovr_parts = [list(p) for p in overage_t]
                prev, digest = self._chain(
                    "tier", seq, tier_id, name, base_cents, inc_parts, ovr_parts
                )
                record = TierRecord(
                    tier_id=tier_id,
                    name=name,
                    base_cents=base_cents,
                    included=included_t,
                    overage_cents=overage_t,
                    seq=seq,
                    prev_digest=prev,
                    digest=digest,
                )
                self._tiers[tier_id] = record
                self._audit("tier-defined", seq, tier_id=tier_id, tier_digest=digest)
                return record
            except TenantBillingError:
                self._audit("rejected", seq, op="define_tier")
                raise

    # -- tenants --------------------------------------------------------

    def provision(self, tenant_id: str, tier_id: str, seq: int) -> TenantRecord:
        """Bind a tenant to a tier (status starts active)."""
        with self._lock:
            seq = self._take_seq(seq)
            try:
                tenant_id = _check_nonempty_str(tenant_id, "tenant_id")
                tier_id = _check_nonempty_str(tier_id, "tier_id")
                tier = self._tiers.get(tier_id)
                if tier is None:
                    raise UnknownTierError(f"unknown tier: {tier_id!r}")
                if tenant_id in self._tenants:
                    raise DuplicateTenantError(f"tenant already exists: {tenant_id!r}")
                prev, digest = self._chain(
                    "tenant", seq, tenant_id, tier_id, tier.digest, "active"
                )
                record = TenantRecord(
                    tenant_id=tenant_id,
                    tier_id=tier_id,
                    tier_digest=tier.digest,
                    status="active",
                    seq=seq,
                    prev_digest=prev,
                    digest=digest,
                )
                self._tenants[tenant_id] = record
                self._usage[tenant_id] = {k: 0 for k in METER_KINDS}
                self._invoiced_periods[tenant_id] = set()
                self._audit(
                    "tenant-provisioned",
                    seq,
                    tenant_id=tenant_id,
                    tier_id=tier_id,
                    tenant_digest=digest,
                )
                return record
            except TenantBillingError:
                self._audit("rejected", seq, op="provision")
                raise

    def _tenant_mutable(self, tenant_id: str) -> TenantRecord:
        record = self._tenants.get(tenant_id)
        if record is None:
            raise UnknownTenantError(f"unknown tenant: {tenant_id!r}")
        return record

    def _restate_tenant(self, record: TenantRecord, status: str, seq: int) -> TenantRecord:
        prev, digest = self._chain(
            "tenant", seq, record.tenant_id, record.tier_id,
            record.tier_digest, status,
        )
        return TenantRecord(
            tenant_id=record.tenant_id,
            tier_id=record.tier_id,
            tier_digest=record.tier_digest,
            status=status,
            seq=seq,
            prev_digest=prev,
            digest=digest,
        )

    def suspend(self, tenant_id: str, seq: int) -> TenantRecord:
        """Suspend a tenant (usage booking refuses until reactivated)."""
        with self._lock:
            seq = self._take_seq(seq)
            try:
                record = self._tenant_mutable(tenant_id)
                updated = self._restate_tenant(record, "suspended", seq)
                self._tenants[tenant_id] = updated
                self._audit(
                    "tenant-suspended",
                    seq,
                    tenant_id=tenant_id,
                    tenant_digest=updated.digest,
                )
                return updated
            except TenantBillingError:
                self._audit("rejected", seq, op="suspend")
                raise

    def reactivate(self, tenant_id: str, seq: int) -> TenantRecord:
        """Reactivate a suspended tenant."""
        with self._lock:
            seq = self._take_seq(seq)
            try:
                record = self._tenant_mutable(tenant_id)
                if record.status != "suspended":
                    raise TenantBillingError(f"tenant is not suspended: {tenant_id!r}")
                updated = self._restate_tenant(record, "active", seq)
                self._tenants[tenant_id] = updated
                self._audit(
                    "tenant-reactivated",
                    seq,
                    tenant_id=tenant_id,
                    tenant_digest=updated.digest,
                )
                return updated
            except TenantBillingError:
                self._audit("rejected", seq, op="reactivate")
                raise

    # -- metering -------------------------------------------------------

    def meter(
        self, tenant_id: str, meter_kind: str, seq: int, quantity: int
    ) -> MeterRecord:
        """Book host-reported usage for a tenant."""
        with self._lock:
            seq = self._take_seq(seq)
            try:
                tenant_id = _check_nonempty_str(tenant_id, "tenant_id")
                _check_meter_kind(meter_kind)
                quantity = _check_quantity(quantity)
                record = self._tenant_mutable(tenant_id)
                if record.status == "suspended":
                    raise SuspendedTenantError(
                        f"tenant suspended, usage refused: {tenant_id!r}"
                    )
                self._meter_counter += 1
                meter_id = f"{_METER_PREFIX}{self._meter_counter}"
                prev, digest = self._chain(
                    "meter", seq, meter_id, tenant_id, meter_kind, quantity
                )
                meter = MeterRecord(
                    meter_id=meter_id,
                    tenant_id=tenant_id,
                    meter_kind=meter_kind,
                    quantity=quantity,
                    seq=seq,
                    prev_digest=prev,
                    digest=digest,
                )
                self._meters[meter_id] = meter
                self._usage[tenant_id][meter_kind] += quantity
                self._audit(
                    "usage-metered",
                    seq,
                    meter_id=meter_id,
                    tenant_id=tenant_id,
                    meter_digest=digest,
                )
                return meter
            except TenantBillingError:
                self._audit("rejected", seq, op="meter")
                raise

    # -- invoicing ------------------------------------------------------

    def invoice(self, tenant_id: str, seq: int, period: str) -> InvoiceRecord:
        """Compute and pin an invoice for a tenant's period.

        Aggregates unbilled usage since the previous invoice, charges
        ``base_cents`` plus per-meter overage above the included quota,
        then resets the tenant's unbilled buckets. One invoice per
        (tenant, period).
        """
        with self._lock:
            seq = self._take_seq(seq)
            try:
                tenant_id = _check_nonempty_str(tenant_id, "tenant_id")
                period = _check_nonempty_str(period, "period")
                tenant = self._tenant_mutable(tenant_id)
                tier = self._tiers[tenant.tier_id]
                if period in self._invoiced_periods[tenant_id]:
                    raise DuplicateInvoiceError(
                        f"tenant {tenant_id!r} already invoiced for {period!r}"
                    )
                usage = self._usage[tenant_id]
                included = dict(tier.included)
                overage = dict(tier.overage_cents)
                lines: List[LineItem] = [
                    LineItem(
                        kind="base",
                        used=0,
                        included=0,
                        billable=1,
                        unit_cents=tier.base_cents,
                        amount_cents=tier.base_cents,
                    )
                ]
                total = tier.base_cents
                for kind in METER_KINDS:
                    used = usage[kind]
                    inc = included.get(kind, 0)
                    billable = max(0, used - inc)
                    unit = overage.get(kind, 0)
                    amount = billable * unit
                    total += amount
                    lines.append(
                        LineItem(
                            kind=kind,
                            used=used,
                            included=inc,
                            billable=billable,
                            unit_cents=unit,
                            amount_cents=amount,
                        )
                    )
                self._invoice_counter += 1
                invoice_id = f"{_INVOICE_PREFIX}{self._invoice_counter}"
                frozen_lines = tuple(lines)
                parts = _line_parts(frozen_lines)
                prev, digest = self._chain(
                    "invoice", seq, invoice_id, tenant_id, tier.tier_id,
                    tier.digest, period, parts, total, "open",
                )
                record = InvoiceRecord(
                    invoice_id=invoice_id,
                    tenant_id=tenant_id,
                    tier_id=tier.tier_id,
                    tier_digest=tier.digest,
                    period=period,
                    lines=frozen_lines,
                    total_cents=total,
                    status="open",
                    seq=seq,
                    prev_digest=prev,
                    digest=digest,
                )
                self._invoices[invoice_id] = record
                self._invoiced_periods[tenant_id].add(period)
                self._usage[tenant_id] = {k: 0 for k in METER_KINDS}
                self._audit(
                    "invoiced",
                    seq,
                    invoice_id=invoice_id,
                    tenant_id=tenant_id,
                    invoice_digest=digest,
                    total_cents=total,
                )
                return record
            except TenantBillingError:
                self._audit("rejected", seq, op="invoice")
                raise

    def _invoice_mutable(self, invoice_id: str) -> InvoiceRecord:
        record = self._invoices.get(invoice_id)
        if record is None:
            raise UnknownInvoiceError(f"unknown invoice: {invoice_id!r}")
        return record

    def _restate_invoice(
        self, record: InvoiceRecord, status: str, seq: int
    ) -> InvoiceRecord:
        prev, digest = self._chain(
            "invoice", seq, record.invoice_id, record.tenant_id,
            record.tier_id, record.tier_digest, record.period,
            _line_parts(record.lines), record.total_cents, status,
        )
        return InvoiceRecord(
            invoice_id=record.invoice_id,
            tenant_id=record.tenant_id,
            tier_id=record.tier_id,
            tier_digest=record.tier_digest,
            period=record.period,
            lines=record.lines,
            total_cents=record.total_cents,
            status=status,
            seq=seq,
            prev_digest=prev,
            digest=digest,
        )

    def mark_paid(self, invoice_id: str, seq: int) -> InvoiceRecord:
        """Record the host-reported payment of an invoice (terminal)."""
        with self._lock:
            seq = self._take_seq(seq)
            try:
                record = self._invoice_mutable(invoice_id)
                if record.status == "paid":
                    raise AlreadyPaidError(f"invoice already paid: {invoice_id!r}")
                if record.status == "voided":
                    raise VoidedInvoiceError(f"invoice voided: {invoice_id!r}")
                updated = self._restate_invoice(record, "paid", seq)
                self._invoices[invoice_id] = updated
                self._audit(
                    "invoice-paid",
                    seq,
                    invoice_id=invoice_id,
                    invoice_digest=updated.digest,
                )
                return updated
            except TenantBillingError:
                self._audit("rejected", seq, op="mark_paid")
                raise

    def void(self, invoice_id: str, seq: int) -> InvoiceRecord:
        """Void an open invoice (terminal; paid invoices may not be voided)."""
        with self._lock:
            seq = self._take_seq(seq)
            try:
                record = self._invoice_mutable(invoice_id)
                if record.status == "paid":
                    raise PaidInvoiceError(
                        f"paid invoice may not be voided: {invoice_id!r}"
                    )
                if record.status == "voided":
                    raise VoidedInvoiceError(
                        f"invoice already voided: {invoice_id!r}"
                    )
                updated = self._restate_invoice(record, "voided", seq)
                self._invoices[invoice_id] = updated
                self._audit(
                    "invoice-voided",
                    seq,
                    invoice_id=invoice_id,
                    invoice_digest=updated.digest,
                )
                return updated
            except TenantBillingError:
                self._audit("rejected", seq, op="void")
                raise

    # -- views (pure: validate seq shape, never consume) -----------------

    def tier(self, tenant_id: str, seq: int = 0) -> TierRecord:
        """Return the tier record currently bound to a tenant."""
        _check_seq(seq, "seq")
        with self._lock:
            tenant = self._tenant_mutable(tenant_id)
            return self._tiers[tenant.tier_id]

    def tenant(self, tenant_id: str, seq: int = 0) -> TenantRecord:
        """Return a tenant's current record."""
        _check_seq(seq, "seq")
        with self._lock:
            return self._tenant_mutable(tenant_id)

    def invoice_record(self, invoice_id: str, seq: int = 0) -> InvoiceRecord:
        """Return an invoice record by id."""
        _check_seq(seq, "seq")
        with self._lock:
            return self._invoice_mutable(invoice_id)

    def usage(self, tenant_id: str, seq: int = 0) -> Dict[str, int]:
        """Return a tenant's current unbilled usage buckets."""
        _check_seq(seq, "seq")
        with self._lock:
            self._tenant_mutable(tenant_id)
            return dict(self._usage[tenant_id])

    def tier_ids(self, seq: int = 0) -> Tuple[str, ...]:
        _check_seq(seq, "seq")
        with self._lock:
            return tuple(sorted(self._tiers))

    def tenant_ids(self, seq: int = 0) -> Tuple[str, ...]:
        _check_seq(seq, "seq")
        with self._lock:
            return tuple(sorted(self._tenants))

    def invoice_ids(self, seq: int = 0) -> Tuple[str, ...]:
        _check_seq(seq, "seq")
        with self._lock:
            return tuple(sorted(self._invoices))

    def audit_log(self, seq: int = 0) -> Tuple[Dict[str, Any], ...]:
        """Return the audit trail (pure view)."""
        _check_seq(seq, "seq")
        with self._lock:
            return tuple(self._audit_log)

    def as_dict(self, seq: int = 0) -> Dict[str, Any]:
        """Snapshot the ledger (ids + counts only, no tenant PII)."""
        _check_seq(seq, "seq")
        with self._lock:
            return {
                "schema": SCHEMA_PIN,
                "module": TENANT_BILLING_VERSION,
                "tier_count": len(self._tiers),
                "tenant_count": len(self._tenants),
                "meter_count": len(self._meters),
                "invoice_count": len(self._invoices),
                "state_digest": self._prev_digest,
            }


def main() -> None:
    """Self-check: define, provision, meter, invoice, settle."""
    tb = TenantBilling()
    tb.define_tier(
        "pro", 0, "Pro", 19900,
        included={"api_calls": 1000},
        overage={"api_calls": 2, "compute_seconds": 1},
    )
    tb.provision("acme", "pro", 1)
    tb.meter("acme", "api_calls", 2, 1500)
    inv = tb.invoice("acme", 3, "2026-10")
    assert inv.total_cents == 19900 + 500 * 2, inv.total_cents
    paid = tb.mark_paid(inv.invoice_id, 4)
    assert paid.status == "paid"
    assert tb.tier("acme").tier_id == "pro"
    print("tenant-billing OK: define, provision, meter, invoice, settle")


if __name__ == "__main__":
    main()
