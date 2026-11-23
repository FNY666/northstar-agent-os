"""Invoice content model: line items, tax, and rendering spec, in-memory.

Research note: an *invoice* (UBL 2.1 / Peppol BIS Billing; the accounting
pattern behind QuickBooks, Stripe Invoicing) is a *content model*, not a
file format: line items (description, quantity, unit price), a tax rate,
and totals. The rendering step turns that model into a presentation --
PDF is the usual one. The load-bearing production concerns, all kept here:

* **Exact money** -- amounts are integer *cents*; the tax rate is integer
  *basis points*. No floats ever touch money, so there is no rounding
  drift and no >2^53 JCS float-loss caveat anywhere in this module.
* **Half-up rounding** -- ``tax_cents = (subtotal * bp + 5000) // 10000``,
  the standard commercial rounding (not banker's), documented and
  test-pinned.
* **Finalization** -- once ``finalize()`` is called the invoice is
  immutable; further edits raise ``FinalizedError`` fail-closed. A sent
  invoice must not change under a reader's eyes.
* **Render pins** -- every line item, the tax record, and each rendered
  invoice carries a ``sha256:`` digest pin over the canonical body, so a
  tampered render no longer verifies.

Honest scope: this is the *content model and rendering contract* for
invoices, not a PDF engine. ``render("text")`` produces a deterministic
monospace layout specification that a real PDF renderer (reportlab,
WeasyPrint) consumes; the module emits no PDF bytes, embeds no fonts,
and cannot prove a PDF was produced or delivered. Amounts are
host-reported -- the module pins arithmetic, not economic truth.

Version pin: invoice-generator.v1
Schema pin: northstar.invoice-generator.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
INVOICE_GENERATOR_VERSION = "invoice-generator.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.invoice-generator.v1"

#: Basis points in one whole: a tax rate of 825 == 8.25%.
BP_PER_WHOLE = 10000

#: Rounding half: +BP_PER_WHOLE/2 before the floor gives half-up.
_ROUND_HALF = BP_PER_WHOLE // 2

#: Supported render formats.
_FORMATS = ("text", "dict")


class InvoiceError(Exception):
    """Base error for invoice misuse or constraint violations."""


class DuplicateInvoiceError(InvoiceError):
    """An invoice id was registered twice."""


class UnknownInvoiceError(InvoiceError):
    """An operation named an invoice id that does not exist."""


class FinalizedError(InvoiceError):
    """An invoice was mutated after finalization."""


class ValidationError(InvoiceError):
    """A field failed fail-closed validation."""


class SeqOrderError(InvoiceError):
    """A caller seq did not strictly increase."""


def _check_seq(seq: int) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ValidationError("seq must be an int, not bool")
    if seq < 0:
        raise ValidationError("seq must be non-negative")
    return seq


def _check_id(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{what} must be a non-empty str")
    return value.strip()


def _pin(body: Any) -> str:
    digest = hashlib.sha256(jcs_canonical_json(body)).hexdigest()
    return f"sha256:{digest}"


def _money_q(value: Any, what: str) -> int:
    """Validate an integer-cent amount: int, not bool, non-negative."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{what} must be an int (cents), not bool")
    if value < 0:
        raise ValidationError(f"{what} must be non-negative")
    return value


def _quantity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError("quantity must be an int, not bool")
    if value <= 0:
        raise ValidationError("quantity must be positive")
    return value


def _tax_bp(value: Any) -> int:
    """Validate a tax rate in basis points: int in [0, 10000]."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError("tax rate must be an int in basis points, not bool")
    if not 0 <= value <= BP_PER_WHOLE:
        raise ValidationError("tax rate must be in [0, 10000] basis points")
    return value


def _fmt_money(cents: int) -> str:
    return f"{cents // 100}.{cents % 100:02d}"


@dataclass(frozen=True)
class LineItem:
    """One pinned line on an invoice."""

    invoice_id: str
    line_no: int
    description: str
    quantity: int
    unit_price_cents: int
    line_total_cents: int
    seq: int
    digest: str
    version: str = INVOICE_GENERATOR_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "invoice_id": self.invoice_id,
            "line_no": self.line_no,
            "description": self.description,
            "quantity": self.quantity,
            "unit_price_cents": self.unit_price_cents,
            "line_total_cents": self.line_total_cents,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class TaxRecord:
    """The pinned tax setting for an invoice."""

    invoice_id: str
    tax_rate_bp: int
    seq: int
    digest: str
    version: str = INVOICE_GENERATOR_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "invoice_id": self.invoice_id,
            "tax_rate_bp": self.tax_rate_bp,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class InvoiceTotals:
    """Pinned arithmetic summary for an invoice."""

    invoice_id: str
    subtotal_cents: int
    tax_rate_bp: int
    tax_cents: int
    total_cents: int
    seq: int
    digest: str
    version: str = INVOICE_GENERATOR_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "invoice_id": self.invoice_id,
            "subtotal_cents": self.subtotal_cents,
            "tax_rate_bp": self.tax_rate_bp,
            "tax_cents": self.tax_cents,
            "total_cents": self.total_cents,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RenderedInvoice:
    """A rendered invoice in the requested format, digest-pinned."""

    invoice_id: str
    format: str
    body: Any
    digest: str
    seq: int
    version: str = INVOICE_GENERATOR_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "invoice_id": self.invoice_id,
            "format": self.format,
            "body": self.body,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class InvoiceView:
    """Read-only view of an invoice's header state."""

    invoice_id: str
    customer: str
    finalized: bool
    item_count: int
    digest: str
    version: str = INVOICE_GENERATOR_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "invoice_id": self.invoice_id,
            "customer": self.customer,
            "finalized": self.finalized,
            "item_count": self.item_count,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


class InvoiceGenerator:
    """Registry of invoices: line items, tax, totals, rendering.

    Caller-supplied int seqs order every mutation; they must strictly
    increase per invoice (clock-free ordering). All mutations are
    RLock-guarded; records are frozen and digest-pinned.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # invoice_id -> {"customer": str, "finalized": bool, "tax_bp": int,
        #                "items": [dict], "last_seq": int}
        self._invoices: Dict[str, Dict[str, Any]] = {}

    # -- helpers ------------------------------------------------------

    def _get(self, invoice_id: str) -> Dict[str, Any]:
        try:
            return self._invoices[invoice_id]
        except KeyError:
            raise UnknownInvoiceError(f"unknown invoice {invoice_id!r}") from None

    def _bump_seq(self, inv: Dict[str, Any], seq: int) -> None:
        _check_seq(seq)
        if seq <= inv["last_seq"]:
            raise SeqOrderError("seq must strictly increase per invoice")
        inv["last_seq"] = seq

    def _require_open(self, inv: Dict[str, Any], invoice_id: str) -> None:
        if inv["finalized"]:
            raise FinalizedError(f"invoice {invoice_id!r} is finalized")

    # -- lifecycle ----------------------------------------------------

    def create(self, invoice_id: str, customer: str, seq: int) -> InvoiceView:
        """Register a new invoice for ``customer``."""
        invoice_id = _check_id(invoice_id, "invoice_id")
        customer = _check_id(customer, "customer")
        _check_seq(seq)
        with self._lock:
            if invoice_id in self._invoices:
                raise DuplicateInvoiceError(f"invoice {invoice_id!r} already exists")
            self._invoices[invoice_id] = {
                "customer": customer,
                "finalized": False,
                "tax_bp": 0,
                "items": [],
                "last_seq": seq,
            }
            return self._view(invoice_id)

    def _view(self, invoice_id: str) -> InvoiceView:
        inv = self._invoices[invoice_id]
        digest = _pin(
            {
                "invoice_id": invoice_id,
                "customer": inv["customer"],
                "finalized": inv["finalized"],
                "item_count": len(inv["items"]),
                "tax_bp": inv["tax_bp"],
            }
        )
        return InvoiceView(
            invoice_id=invoice_id,
            customer=inv["customer"],
            finalized=inv["finalized"],
            item_count=len(inv["items"]),
            digest=digest,
        )

    def invoice(self, invoice_id: str) -> InvoiceView:
        """Read-only view of an invoice."""
        _check_id(invoice_id, "invoice_id")
        with self._lock:
            self._get(invoice_id)  # raises UnknownInvoiceError if absent
            return self._view(invoice_id)

    def finalize(self, invoice_id: str, seq: int) -> InvoiceView:
        """Lock the invoice; further edits are refused."""
        _check_id(invoice_id, "invoice_id")
        with self._lock:
            inv = self._get(invoice_id)
            self._bump_seq(inv, seq)
            inv["finalized"] = True
            return self._view(invoice_id)

    # -- line items ---------------------------------------------------

    def add_item(
        self,
        invoice_id: str,
        description: str,
        quantity: int,
        unit_price_cents: int,
        seq: int,
    ) -> LineItem:
        """Append a line item; returns the pinned record."""
        _check_id(invoice_id, "invoice_id")
        description = _check_id(description, "description")
        quantity = _quantity(quantity)
        unit_price_cents = _money_q(unit_price_cents, "unit_price_cents")
        with self._lock:
            inv = self._get(invoice_id)
            self._require_open(inv, invoice_id)
            self._bump_seq(inv, seq)
            line_no = len(inv["items"]) + 1
            line_total = quantity * unit_price_cents
            inv["items"].append(
                {
                    "line_no": line_no,
                    "description": description,
                    "quantity": quantity,
                    "unit_price_cents": unit_price_cents,
                    "line_total_cents": line_total,
                    "seq": seq,
                }
            )
            digest = _pin(
                {
                    "invoice_id": invoice_id,
                    "line_no": line_no,
                    "description": description,
                    "quantity": quantity,
                    "unit_price_cents": unit_price_cents,
                    "line_total_cents": line_total,
                    "seq": seq,
                }
            )
            return LineItem(
                invoice_id=invoice_id,
                line_no=line_no,
                description=description,
                quantity=quantity,
                unit_price_cents=unit_price_cents,
                line_total_cents=line_total,
                seq=seq,
                digest=digest,
            )

    def items(self, invoice_id: str) -> Tuple[LineItem, ...]:
        """All line items, in insertion order."""
        _check_id(invoice_id, "invoice_id")
        with self._lock:
            inv = self._get(invoice_id)
            out: List[LineItem] = []
            for row in inv["items"]:
                body = {
                    "invoice_id": invoice_id,
                    "line_no": row["line_no"],
                    "description": row["description"],
                    "quantity": row["quantity"],
                    "unit_price_cents": row["unit_price_cents"],
                    "line_total_cents": row["line_total_cents"],
                    "seq": row["seq"],
                }
                out.append(
                    LineItem(
                        invoice_id=invoice_id,
                        line_no=row["line_no"],
                        description=row["description"],
                        quantity=row["quantity"],
                        unit_price_cents=row["unit_price_cents"],
                        line_total_cents=row["line_total_cents"],
                        seq=row["seq"],
                        digest=_pin(body),
                    )
                )
            return tuple(out)

    # -- tax and totals -----------------------------------------------

    def tax(self, invoice_id: str, tax_rate_bp: int, seq: int) -> TaxRecord:
        """Set the invoice tax rate in basis points (e.g. 825 == 8.25%)."""
        _check_id(invoice_id, "invoice_id")
        tax_rate_bp = _tax_bp(tax_rate_bp)
        with self._lock:
            inv = self._get(invoice_id)
            self._require_open(inv, invoice_id)
            self._bump_seq(inv, seq)
            inv["tax_bp"] = tax_rate_bp
            digest = _pin(
                {"invoice_id": invoice_id, "tax_rate_bp": tax_rate_bp, "seq": seq}
            )
            return TaxRecord(
                invoice_id=invoice_id, tax_rate_bp=tax_rate_bp, seq=seq, digest=digest
            )

    def totals(self, invoice_id: str, seq: int) -> InvoiceTotals:
        """Compute pinned subtotal / tax / total (exact integer cents)."""
        _check_id(invoice_id, "invoice_id")
        _check_seq(seq)
        with self._lock:
            inv = self._get(invoice_id)
            subtotal = sum(row["line_total_cents"] for row in inv["items"])
            tax_cents = (subtotal * inv["tax_bp"] + _ROUND_HALF) // BP_PER_WHOLE
            total = subtotal + tax_cents
            digest = _pin(
                {
                    "invoice_id": invoice_id,
                    "subtotal_cents": subtotal,
                    "tax_rate_bp": inv["tax_bp"],
                    "tax_cents": tax_cents,
                    "total_cents": total,
                    "seq": seq,
                }
            )
            return InvoiceTotals(
                invoice_id=invoice_id,
                subtotal_cents=subtotal,
                tax_rate_bp=inv["tax_bp"],
                tax_cents=tax_cents,
                total_cents=total,
                seq=seq,
                digest=digest,
            )

    # -- rendering ----------------------------------------------------

    def render(self, invoice_id: str, seq: int, format: str = "text") -> RenderedInvoice:
        """Render the invoice to the requested format.

        ``"text"`` produces a deterministic monospace layout spec that a
        real PDF renderer consumes; ``"dict"`` produces the canonical
        content body. Unknown formats are refused fail-closed.
        """
        _check_id(invoice_id, "invoice_id")
        _check_seq(seq)
        if format not in _FORMATS:
            raise ValidationError(f"unknown render format {format!r}")
        with self._lock:
            inv = self._get(invoice_id)
            view = self._view(invoice_id)
            totals = self.totals(invoice_id, seq)
            lines = [
                {
                    "line_no": row["line_no"],
                    "description": row["description"],
                    "quantity": row["quantity"],
                    "unit_price_cents": row["unit_price_cents"],
                    "line_total_cents": row["line_total_cents"],
                }
                for row in inv["items"]
            ]
            if format == "dict":
                body: Any = {
                    "invoice_id": invoice_id,
                    "customer": inv["customer"],
                    "finalized": inv["finalized"],
                    "lines": lines,
                    "subtotal_cents": totals.subtotal_cents,
                    "tax_rate_bp": totals.tax_rate_bp,
                    "tax_cents": totals.tax_cents,
                    "total_cents": totals.total_cents,
                }
            else:
                body = self._render_text(view, lines, totals)
            digest = _pin({"invoice_id": invoice_id, "format": format, "body": body})
            return RenderedInvoice(
                invoice_id=invoice_id,
                format=format,
                body=body,
                digest=digest,
                seq=seq,
            )

    @staticmethod
    def _render_text(
        view: InvoiceView, lines: List[Dict[str, Any]], totals: InvoiceTotals
    ) -> str:
        out = [f"INVOICE {view.invoice_id}", f"Bill to: {view.customer}", "-" * 48]
        for row in lines:
            out.append(
                f"{row['line_no']:>3}. {row['description']:<24} "
                f"{row['quantity']:>3} x {_fmt_money(row['unit_price_cents']):>9} = "
                f"{_fmt_money(row['line_total_cents']):>10}"
            )
        out.append("-" * 48)
        out.append(f"{'Subtotal':>40} {_fmt_money(totals.subtotal_cents):>10}")
        rate_pct = totals.tax_rate_bp / 100
        out.append(
            f"{'Tax (' + f'{rate_pct:.2f}' + '%)':>40} "
            f"{_fmt_money(totals.tax_cents):>10}"
        )
        out.append(f"{'TOTAL':>40} {_fmt_money(totals.total_cents):>10}")
        return "\n".join(out)


_AUDIT_KINDS = (
    "invoice-created",
    "item-added",
    "tax-set",
    "finalized",
    "rendered",
    "rejected",
)


def invoice_generator_audit_event(kind: str, seq: int, detail: Mapping[str, Any]) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for this module."""
    _check_seq(seq)
    if kind not in _AUDIT_KINDS:
        raise ValidationError(f"unknown audit kind {kind!r}")
    if not isinstance(detail, Mapping):
        raise ValidationError("detail must be a mapping")
    return {
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
        "version": INVOICE_GENERATOR_VERSION,
        "schema": SCHEMA_PIN,
    }


def main() -> None:
    gen = InvoiceGenerator()
    gen.create("INV-1", "Acme Corp", 1)
    gen.add_item("INV-1", "Widgets", 3, 1999, 2)
    gen.add_item("INV-1", "Gadgets", 1, 4999, 3)
    gen.tax("INV-1", 825, 4)
    totals = gen.totals("INV-1", 5)
    assert totals.subtotal_cents == 3 * 1999 + 4999
    assert totals.tax_cents == (totals.subtotal_cents * 825 + 5000) // 10000
    gen.finalize("INV-1", 6)
    rendered = gen.render("INV-1", 7)
    assert "TOTAL" in rendered.body
    print("invoice-generator OK: create, items, tax, totals, render")


if __name__ == "__main__":
    main()
