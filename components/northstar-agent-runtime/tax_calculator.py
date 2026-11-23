"""VAT / sales-tax calculator with jurisdiction rates and exemptions.

Deterministic tax bookkeeping over caller-supplied jurisdictions:

- ``add_rate(jurisdiction, tax_kind, rate_bps, seq, ...)`` registers a
  tax rate for a jurisdiction (country ``"DE"`` or region ``"US-CA"``).
  Rates are stored in basis points (integers) - never floats - so
  ``calculate`` is exact. ``tax_kind`` is one of ``"vat"``, ``"sales"``,
  ``"gst"``. An optional ``category`` (e.g. ``"reduced"``, ``"food"``)
  scopes the rate to a product category; ``"standard"`` is the default.
- ``calculate(net_cents, jurisdiction, seq, ...)`` -> frozen
  ``TaxQuote``: exact ``tax_cents`` (half-up rounding), ``gross_cents``,
  the applied rate record, and whether VAT was quoted inclusive.
- ``exempt(entity_id, jurisdiction, seq, ...)`` -> frozen ``Exemption``:
  a zero-rate hold for a VAT-ID / resale certificate; ``calculate``
  applies it automatically fail-closed (exemption must match the
  jurisdiction being billed, otherwise it is ignored, not honored).

Fail-closed posture:

1. Unknown jurisdiction or unknown category -> ``NoRateError``; the
   caller supplies a rate, the calculator never invents one.
2. Negative ``net_cents`` and rates above 100% -> ``TaxConfigError`` /
   ``ValueError``; a rate above 100% is a misconfiguration, not a
   feature.
3. ``vat_inclusive=True`` computes the tax embedded in the gross with
   the VAT extraction formula; ``tax_kind`` is still checked so a
   ``"sales"`` rate cannot be quoted inclusive.
4. Exemptions are positive allow-list entries keyed by
   ``(entity_id, jurisdiction)``; a removed exemption stops applying
   at the supplied seq, and audit events record the whole lifecycle.

Honest scope: bookkeeping simulation of the tax API shape, not tax
advice and not a filing boundary. Rates are caller-declared; a quote
proves "this calculator applied that registered rate at this seq",
never that the rate is the legally correct one. All amounts are
caller-supplied integer cents; caller-supplied integer seqs are the
only clock - no wall-clock anywhere.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Module version.
TAX_CALCULATOR_VERSION = "tax-calculator.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.tax-calculator.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Accepted tax kinds.
TAX_KINDS = ("vat", "sales", "gst")

#: Default category when a rate is not category-scoped.
STANDARD_CATEGORY = "standard"

#: Hard cap on registered jurisdictions per calculator (guardrail).
MAX_JURISDICTIONS = 512

#: Hard cap on rates per jurisdiction (guardrail).
MAX_RATES_PER_JURISDICTION = 64

#: Hard cap on exemptions per calculator (guardrail).
MAX_EXEMPTIONS = 4096


class TaxError(Exception):
    """Base fail-closed tax error."""


class NoRateError(TaxError):
    """No rate registered for the jurisdiction (and category)."""


class TaxConfigError(TaxError):
    """Rejected rate registration (out of range, unknown kind)."""


@dataclass(frozen=True)
class TaxRate:
    """A registered rate for one jurisdiction."""

    jurisdiction: str
    tax_kind: str
    rate_bps: int  # basis points: 2000 == 20.00%
    category: str = STANDARD_CATEGORY
    label: str = ""
    added_seq: int = 0
    version: str = TAX_CALCULATOR_VERSION
    schema: str = SCHEMA_PIN

    def digest(self) -> str:
        """``sha256:`` digest pin over the canonical record."""
        return "sha256:" + jcs_sha256_hex(self.as_dict())

    def as_dict(self) -> Dict[str, Any]:
        return {
            "jurisdiction": self.jurisdiction,
            "tax_kind": self.tax_kind,
            "rate_bps": self.rate_bps,
            "category": self.category,
            "label": self.label,
            "added_seq": self.added_seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class TaxQuote:
    """Result of ``calculate``."""

    jurisdiction: str
    tax_kind: str
    category: str
    net_cents: int
    tax_cents: int
    gross_cents: int
    rate_bps: int
    vat_inclusive: bool
    exempt_applied: bool
    reverse_charge: bool
    seq: int
    version: str = TAX_CALCULATOR_VERSION
    schema: str = SCHEMA_PIN

    def digest(self) -> str:
        return "sha256:" + jcs_sha256_hex(self.as_dict())

    def as_dict(self) -> Dict[str, Any]:
        return {
            "jurisdiction": self.jurisdiction,
            "tax_kind": self.tax_kind,
            "category": self.category,
            "net_cents": self.net_cents,
            "tax_cents": self.tax_cents,
            "gross_cents": self.gross_cents,
            "rate_bps": self.rate_bps,
            "vat_inclusive": self.vat_inclusive,
            "exempt_applied": self.exempt_applied,
            "reverse_charge": self.reverse_charge,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class Exemption:
    """A zero-rate hold for one entity in one jurisdiction."""

    entity_id: str
    jurisdiction: str
    reason: str
    granted_seq: int
    revoked_seq: Optional[int] = None
    version: str = TAX_CALCULATOR_VERSION
    schema: str = SCHEMA_PIN

    def digest(self) -> str:
        return "sha256:" + jcs_sha256_hex(self.as_dict())

    def active_at(self, seq: int) -> bool:
        return self.granted_seq <= seq and (
            self.revoked_seq is None or seq < self.revoked_seq
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "jurisdiction": self.jurisdiction,
            "reason": self.reason,
            "granted_seq": self.granted_seq,
            "revoked_seq": self.revoked_seq,
            "version": self.version,
            "schema": self.schema,
        }


_AUDIT_KINDS = ("rate_added", "calculated", "exempted", "exemption_revoked")


def _audit_event(kind: str, seq: int, payload: Mapping[str, Any]) -> Dict[str, Any]:
    if kind not in _AUDIT_KINDS:
        raise TaxError(f"unknown audit kind: {kind!r}")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": "tax_calculator." + kind,
        "seq": seq,
        "module_version": TAX_CALCULATOR_VERSION,
        "payload": dict(payload),
        "digest": "sha256:" + jcs_sha256_hex(dict(payload)),
    }


def _check_jurisdiction(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TaxConfigError("jurisdiction must be a non-empty string")
    return value.strip()


def _half_up_div(numerator: int, denominator: int) -> int:
    """Integer division rounding half up (never floats)."""
    return (numerator + denominator // 2) // denominator


class TaxCalculator:
    """Jurisdiction rates + exemptions with an audit trail.

    Mutable registry guarded by a lock; every mutation and every quote
    appends an ``audit.ndjson/1`` event to ``events``.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rates: Dict[str, List[TaxRate]] = {}
        self._exemptions: Dict[Tuple[str, str], Exemption] = {}
        self.events: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # Rates                                                               #
    # ------------------------------------------------------------------ #

    def add_rate(
        self,
        jurisdiction: str,
        tax_kind: str,
        rate_bps: int,
        seq: int,
        *,
        category: str = STANDARD_CATEGORY,
        label: str = "",
    ) -> TaxRate:
        """Register (or replace) the rate for a jurisdiction+category."""
        jurisdiction = _check_jurisdiction(jurisdiction)
        if tax_kind not in TAX_KINDS:
            raise TaxConfigError(f"unknown tax_kind: {tax_kind!r}")
        if not isinstance(rate_bps, int) or rate_bps < 0 or rate_bps > 10000:
            raise TaxConfigError("rate_bps must be an int in [0, 10000]")
        if not isinstance(seq, int) or seq < 0:
            raise TaxConfigError("seq must be a non-negative int")
        category = category.strip() or STANDARD_CATEGORY

        with self._lock:
            rates = self._rates.setdefault(jurisdiction, [])
            if len(self._rates) > MAX_JURISDICTIONS:
                raise TaxConfigError("too many jurisdictions")
            rates = [r for r in rates if r.category != category]
            if len(rates) >= MAX_RATES_PER_JURISDICTION:
                raise TaxConfigError("too many rates for jurisdiction")
            rate = TaxRate(
                jurisdiction=jurisdiction,
                tax_kind=tax_kind,
                rate_bps=rate_bps,
                category=category,
                label=label,
                added_seq=seq,
            )
            rates.append(rate)
            self._rates[jurisdiction] = rates
            self.events.append(
                _audit_event("rate_added", seq, {"rate": rate.as_dict()})
            )
            return rate

    def get_rate(
        self, jurisdiction: str, category: str = STANDARD_CATEGORY
    ) -> TaxRate:
        """Fetch the registered rate; raises :class:`NoRateError`."""
        jurisdiction = _check_jurisdiction(jurisdiction)
        with self._lock:
            rates = self._rates.get(jurisdiction, [])
            for rate in rates:
                if rate.category == (category.strip() or STANDARD_CATEGORY):
                    return rate
        raise NoRateError(
            f"no rate for jurisdiction={jurisdiction!r} "
            f"category={category!r}"
        )

    # ------------------------------------------------------------------ #
    # Exemptions                                                           #
    # ------------------------------------------------------------------ #

    def exempt(
        self,
        entity_id: str,
        jurisdiction: str,
        seq: int,
        *,
        reason: str = "",
    ) -> Exemption:
        """Grant a zero-rate hold for an entity in a jurisdiction."""
        if not isinstance(entity_id, str) or not entity_id.strip():
            raise TaxConfigError("entity_id must be a non-empty string")
        jurisdiction = _check_jurisdiction(jurisdiction)
        if not isinstance(seq, int) or seq < 0:
            raise TaxConfigError("seq must be a non-negative int")

        with self._lock:
            if len(self._exemptions) >= MAX_EXEMPTIONS:
                raise TaxConfigError("too many exemptions")
            key = (entity_id.strip(), jurisdiction)
            exemption = Exemption(
                entity_id=entity_id.strip(),
                jurisdiction=jurisdiction,
                reason=reason,
                granted_seq=seq,
            )
            self._exemptions[key] = exemption
            self.events.append(
                _audit_event("exempted", seq, {"exemption": exemption.as_dict()})
            )
            return exemption

    def revoke_exemption(
        self, entity_id: str, jurisdiction: str, seq: int
    ) -> Exemption:
        """End an exemption; it stops applying at ``seq``."""
        key = (entity_id.strip(), jurisdiction.strip())
        with self._lock:
            current = self._exemptions.get(key)
            if current is None:
                raise NoRateError(f"no exemption for {key!r}")
            revoked = Exemption(
                entity_id=current.entity_id,
                jurisdiction=current.jurisdiction,
                reason=current.reason,
                granted_seq=current.granted_seq,
                revoked_seq=seq,
            )
            self._exemptions[key] = revoked
            self.events.append(
                _audit_event(
                    "exemption_revoked", seq, {"exemption": revoked.as_dict()}
                )
            )
            return revoked

    # ------------------------------------------------------------------ #
    # Calculation                                                          #
    # ------------------------------------------------------------------ #

    def calculate(
        self,
        net_cents: int,
        jurisdiction: str,
        seq: int,
        *,
        category: str = STANDARD_CATEGORY,
        vat_inclusive: bool = False,
        entity_id: Optional[str] = None,
        reverse_charge: bool = False,
    ) -> TaxQuote:
        """Quote tax for ``net_cents`` in ``jurisdiction``.

        ``entity_id`` applies a matching active exemption. ``reverse_charge``
        is a VAT bookkeeping flag: the tax is quoted at 0 for the seller
        and the buyer's rate record is still bound to the quote.
        """
        if not isinstance(net_cents, int) or net_cents < 0:
            raise TaxConfigError("net_cents must be a non-negative int")
        if not isinstance(seq, int) or seq < 0:
            raise TaxConfigError("seq must be a non-negative int")
        jurisdiction = _check_jurisdiction(jurisdiction)

        rate = self.get_rate(jurisdiction, category)

        exempt_applied = False
        if entity_id is not None:
            with self._lock:
                exemption = self._exemptions.get(
                    (entity_id.strip(), jurisdiction)
                )
            if exemption is not None and exemption.active_at(seq):
                exempt_applied = True

        effective_bps = 0 if (exempt_applied or reverse_charge) else rate.rate_bps

        if vat_inclusive and rate.tax_kind != "vat":
            raise TaxConfigError(
                "vat_inclusive quoting requires a vat tax_kind"
            )

        if vat_inclusive:
            # gross is what the caller passed; extract the embedded tax.
            gross_cents = net_cents
            net_cents_out = _half_up_div(
                gross_cents * 10000, 10000 + effective_bps
            )
            tax_cents = gross_cents - net_cents_out
        else:
            net_cents_out = net_cents
            tax_cents = _half_up_div(net_cents * effective_bps, 10000)
            gross_cents = net_cents + tax_cents

        quote = TaxQuote(
            jurisdiction=jurisdiction,
            tax_kind=rate.tax_kind,
            category=rate.category,
            net_cents=net_cents_out,
            tax_cents=tax_cents,
            gross_cents=gross_cents,
            rate_bps=rate.rate_bps,
            vat_inclusive=vat_inclusive,
            exempt_applied=exempt_applied,
            reverse_charge=reverse_charge,
            seq=seq,
        )
        with self._lock:
            self.events.append(
                _audit_event("calculated", seq, {"quote": quote.as_dict()})
            )
        return quote


def main() -> int:
    """Self-check: register a VAT rate, quote, exempt, and audit trail."""
    calc = TaxCalculator()
    calc.add_rate("DE", "vat", 1900, 1, label="Germany standard VAT")
    calc.add_rate("DE", "vat", 700, 2, category="reduced", label="food")
    q1 = calc.calculate(10000, "DE", 3)
    assert q1.tax_cents == 1900 and q1.gross_cents == 11900, q1
    q2 = calc.calculate(10000, "DE", 4, category="reduced")
    assert q2.tax_cents == 700, q2
    calc.exempt("vat-id-123", "DE", 5, reason="resale certificate")
    q3 = calc.calculate(10000, "DE", 6, entity_id="vat-id-123")
    assert q3.tax_cents == 0 and q3.exempt_applied, q3
    kinds = [e["kind"] for e in calc.events]
    assert kinds == [
        "tax_calculator.rate_added",
        "tax_calculator.rate_added",
        "tax_calculator.calculated",
        "tax_calculator.calculated",
        "tax_calculator.exempted",
        "tax_calculator.calculated",
    ], kinds
    print("tax_calculator self-check OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
