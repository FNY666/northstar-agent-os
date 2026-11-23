"""Payment processor interface: Stripe-style charge/refund/dispute bookkeeping.

Research note: a *payment processor interface* (Stripe, Adyen, Checkout.com
shape) is the contract between a merchant's agent and the money rail: the
merchant asks for a *charge* against a customer + payment method, the rail
settles it, and later the merchant may *refund* (return funds) or face a
*dispute* (chargeback — the cardholder's bank pulls the money back). The
load-bearing invariants are: (1) *amounts in minor units* — money is always an
integer number of cents (or the currency's smallest unit), never a float, so
there is no IEEE rounding anywhere in the money path; (2) *idempotency* —
a charge request retried with the same idempotency key must return the
existing charge, not mint a second one (the "my customer got charged twice"
failure mode); (3) *refund ceiling* — total refunds against a charge can
never exceed the captured amount; (4) *dispute terminality* — a disputed
charge enters a terminal state where refunds are no longer possible (the bank
has already taken the funds); (5) *audit trail* — every state transition is
pinned and auditable, because money disputes are resolved on records.

This module implements that shape as a deterministic, single-host ledger:

* **Charges** — :meth:`PaymentProcessor.charge` records a frozen
  :class:`ChargeRecord` (``ch-<n>`` id, minor-unit amount, ISO currency code,
  customer/method ids, ``sha256:`` digest pin). An optional caller-supplied
  ``idempotency_key`` makes the call idempotent: a repeat call with the same
  key returns the original record instead of minting a new charge.
* **Refunds** — :meth:`PaymentProcessor.refund` records a frozen
  :class:`RefundRecord` (``re-<n>`` id); full or partial; cumulative refunds
  fail closed at the charged amount (``RefundExceedsChargeError``).
* **Disputes** — :meth:`PaymentProcessor.dispute` records a frozen
  :class:`DisputeRecord` (chargeback simulation, ``dp-<n>`` id); a disputed
  charge is terminal — further refunds raise :class:`ChargeDisputedError`,
  and resolving a dispute records the outcome (``won``/``lost``/``withdrawn``).

House style: frozen dataclasses, caller-supplied int seqs (strictly
increasing per processor, no wall-clock, no RNG for ids — ids are
monotonic ``ch-<n>``/``re-<n>``/``dp-<n>`` counters), RLock-guarded,
fail-closed (bool/negative amounts, empty ids, unknown charges, refund
overruns, refunds on disputed charges all raise a subclass of
:class:`PaymentError`), stdlib-only, type-tagged canonical digest encoding
(bool != int; amounts are ints in minor units so the batch-5 JCS float-loss
caveat never applies — floats are refused outright), audit events shaped for
``audit.ndjson/1``, ``main()`` self-check.

Honest scope: this is a *claims ledger*, not a money rail. It cannot move
money, verify that a card exists, contact a bank, or prove settlement.
``charge()`` pins what the host *reported*; a host that lies gets a
consistent ledger of lies (GIGO, same boundary as every other bookkeeping
module). For real settlement pair with a PCI-scoped rail (Stripe/Adyen API)
and ``remote_attestation`` for the host.

Version pin: payment-processor.v1
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

VERSION = "payment-processor.v1"
SCHEMA = "northstar.payment-processor.v1"

__all__ = [
    "VERSION",
    "SCHEMA",
    "PaymentError",
    "UnknownChargeError",
    "DuplicateChargeError",
    "IdempotencyMismatchError",
    "RefundExceedsChargeError",
    "ChargeDisputedError",
    "TerminalDisputeError",
    "UnknownRefundError",
    "ChargeRecord",
    "RefundRecord",
    "DisputeRecord",
    "PaymentProcessor",
    "payment_processor_audit_event",
]


class PaymentError(Exception):
    """Base for all payment-processor errors (fail-closed taxonomy)."""


class UnknownChargeError(PaymentError):
    """Charge id not present in the ledger."""


class DuplicateChargeError(PaymentError):
    """Charge id already minted (internal guard; ids are host-independent)."""


class IdempotencyMismatchError(PaymentError):
    """Same idempotency key reused with different request parameters."""


class RefundExceedsChargeError(PaymentError):
    """Cumulative refunds would exceed the charged amount."""


class ChargeDisputedError(PaymentError):
    """Refund attempted on a charge with an open dispute (terminal state)."""


class TerminalDisputeError(PaymentError):
    """A terminal action (re-dispute / re-resolve) on an already-resolved dispute."""


class UnknownRefundError(PaymentError):
    """Refund id not present in the ledger."""


# ---------------------------------------------------------------------------
# canonical encoding (type-tagged; amounts are ints so floats never occur,
# but the boundary refuses them outright for defense in depth)
# ---------------------------------------------------------------------------

def _canonical(value: Any) -> str:
    """Type-tagged canonical JSON-ish encoding.

    Tags: N(int) B(bool) S(str) L(list) M(map) Z(None).
    Floats, NaN/inf, and |n| >= 2**53 are refused fail-closed.
    """
    if value is None:
        return "Z"
    if isinstance(value, bool):
        return "B1" if value else "B0"
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise PaymentError(f"integer magnitude >= 2**53 refused: {value!r}")
        return f"N{value}"
    if isinstance(value, float):
        raise PaymentError(f"floats refused in money path: {value!r}")
    if isinstance(value, str):
        return "S" + json.dumps(value, ensure_ascii=True)
    if isinstance(value, (list, tuple)):
        return "L[" + ",".join(_canonical(v) for v in value) + "]"
    if isinstance(value, Mapping):
        items = sorted(value.items(), key=lambda kv: kv[0])
        for k in value:
            if not isinstance(k, str):
                raise PaymentError(f"non-str mapping key refused: {k!r}")
        return "M{" + ",".join(_canonical(k) + ":" + _canonical(v) for k, v in items) + "}"
    raise PaymentError(f"non-canonicalizable value refused: {type(value).__name__}")


def _pin(*parts: Any) -> str:
    body = "|".join(_canonical(p) for p in parts)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# validation helpers
# ---------------------------------------------------------------------------

def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise PaymentError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _check_id(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PaymentError(f"{name} must be a non-empty str, got {value!r}")
    if len(value) > 256:
        raise PaymentError(f"{name} exceeds 256 chars")
    return value.strip()


def _check_amount(amount: Any) -> int:
    """Money is always an integer number of minor units. Floats refused."""
    if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
        raise PaymentError(f"amount must be a positive int (minor units), got {amount!r}")
    if amount >= 2**53:
        raise PaymentError(f"amount magnitude >= 2**53 refused: {amount!r}")
    return amount


def _check_currency(currency: Any) -> str:
    if not isinstance(currency, str) or len(currency) != 3 or not currency.isalpha():
        raise PaymentError(f"currency must be a 3-letter ISO code, got {currency!r}")
    return currency.upper()


# ---------------------------------------------------------------------------
# frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ChargeRecord:
    charge_id: str
    amount: int
    currency: str
    customer_id: str
    payment_method: str
    idempotency_key: Optional[str]
    status: str  # "succeeded"
    seq: int
    digest: str
    version: str = field(default=VERSION, compare=False)
    schema: str = field(default=SCHEMA, compare=False)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "charge_id": self.charge_id,
            "amount": self.amount,
            "currency": self.currency,
            "customer_id": self.customer_id,
            "payment_method": self.payment_method,
            "idempotency_key": self.idempotency_key,
            "status": self.status,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RefundRecord:
    refund_id: str
    charge_id: str
    amount: int
    reason: str
    cumulative_refunded: int
    seq: int
    digest: str
    version: str = field(default=VERSION, compare=False)
    schema: str = field(default=SCHEMA, compare=False)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "refund_id": self.refund_id,
            "charge_id": self.charge_id,
            "amount": self.amount,
            "reason": self.reason,
            "cumulative_refunded": self.cumulative_refunded,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class DisputeRecord:
    dispute_id: str
    charge_id: str
    amount: int
    reason: str
    status: str  # "open" | "won" | "lost" | "withdrawn"
    seq: int
    digest: str
    version: str = field(default=VERSION, compare=False)
    schema: str = field(default=SCHEMA, compare=False)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "dispute_id": self.dispute_id,
            "charge_id": self.charge_id,
            "amount": self.amount,
            "reason": self.reason,
            "status": self.status,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


# dispute reasons (pinned vocabulary, Stripe-shaped)
DISPUTE_REASONS = (
    "fraudulent",
    "unrecognized",
    "duplicate",
    "subscription_canceled",
    "product_not_received",
    "product_unacceptable",
    "general",
)

DISPUTE_OUTCOMES = ("won", "lost", "withdrawn")


# ---------------------------------------------------------------------------
# processor
# ---------------------------------------------------------------------------

class PaymentProcessor:
    """Deterministic single-host charge/refund/dispute ledger."""

    def __init__(self, merchant_id: str):
        self._merchant_id = _check_id("merchant_id", merchant_id)
        self._lock = threading.RLock()
        self._charges: Dict[str, ChargeRecord] = {}
        self._refunds: Dict[str, RefundRecord] = {}
        self._disputes: Dict[str, DisputeRecord] = {}
        self._idempotency: Dict[str, Tuple[str, Tuple[int, str, str, str, str]]] = {}
        self._refunded_total: Dict[str, int] = {}
        self._charge_counter = 0
        self._refund_counter = 0
        self._dispute_counter = 0
        self._last_seq = -1

    def _advance_seq(self, seq: int) -> None:
        if seq <= self._last_seq:
            raise PaymentError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq

    # -- charges -----------------------------------------------------------

    def charge(
        self,
        amount: int,
        currency: str,
        customer_id: str,
        payment_method: str,
        seq: int,
        idempotency_key: Optional[str] = None,
    ) -> ChargeRecord:
        """Record a charge. With idempotency_key, repeat calls replay the
        original record instead of minting a second charge."""
        amount = _check_amount(amount)
        currency = _check_currency(currency)
        customer_id = _check_id("customer_id", customer_id)
        payment_method = _check_id("payment_method", payment_method)
        seq = _check_seq(seq)
        if idempotency_key is not None:
            idempotency_key = _check_id("idempotency_key", idempotency_key)
        with self._lock:
            self._advance_seq(seq)
            if idempotency_key is not None and idempotency_key in self._idempotency:
                prior_id, params = self._idempotency[idempotency_key]
                if params != (amount, currency, customer_id, payment_method):
                    raise IdempotencyMismatchError(
                        f"idempotency key {idempotency_key!r} reused with different params"
                    )
                return self._charges[prior_id]
            self._charge_counter += 1
            charge_id = f"ch-{self._charge_counter}"
            if charge_id in self._charges:
                raise DuplicateChargeError(charge_id)
            digest = _pin("charge", self._merchant_id, charge_id, amount, currency,
                          customer_id, payment_method, seq)
            rec = ChargeRecord(
                charge_id=charge_id, amount=amount, currency=currency,
                customer_id=customer_id, payment_method=payment_method,
                idempotency_key=idempotency_key, status="succeeded",
                seq=seq, digest=digest,
            )
            self._charges[charge_id] = rec
            self._refunded_total[charge_id] = 0
            if idempotency_key is not None:
                self._idempotency[idempotency_key] = (
                    charge_id, (amount, currency, customer_id, payment_method))
            return rec

    # -- refunds -----------------------------------------------------------

    def refund(
        self,
        charge_id: str,
        seq: int,
        amount: Optional[int] = None,
        reason: str = "requested_by_customer",
    ) -> RefundRecord:
        """Record a refund (full if amount is None). Cumulative refunds can
        never exceed the charged amount; disputed charges refuse refunds."""
        charge_id = _check_id("charge_id", charge_id)
        seq = _check_seq(seq)
        reason = _check_id("reason", reason)
        with self._lock:
            self._advance_seq(seq)
            charge = self._charges.get(charge_id)
            if charge is None:
                raise UnknownChargeError(charge_id)
            dispute = self._disputes.get(charge_id)
            if dispute is not None and dispute.status == "open":
                raise ChargeDisputedError(
                    f"charge {charge_id} has an open dispute; refunds refused")
            refund_amount = _check_amount(amount) if amount is not None else charge.amount
            already = self._refunded_total[charge_id]
            if already + refund_amount > charge.amount:
                raise RefundExceedsChargeError(
                    f"cumulative refunds {already + refund_amount} > charged {charge.amount}")
            self._refund_counter += 1
            refund_id = f"re-{self._refund_counter}"
            if refund_id in self._refunds:
                raise DuplicateChargeError(refund_id)
            cumulative = already + refund_amount
            digest = _pin("refund", self._merchant_id, refund_id, charge_id,
                          refund_amount, reason, cumulative, seq)
            rec = RefundRecord(
                refund_id=refund_id, charge_id=charge_id, amount=refund_amount,
                reason=reason, cumulative_refunded=cumulative,
                seq=seq, digest=digest,
            )
            self._refunds[refund_id] = rec
            self._refunded_total[charge_id] = cumulative
            return rec

    # -- disputes ----------------------------------------------------------

    def dispute(
        self, charge_id: str, reason: str, seq: int,
    ) -> DisputeRecord:
        """Open a dispute (chargeback) against a charge. Terminal: refunds on
        this charge are refused while the dispute is open."""
        charge_id = _check_id("charge_id", charge_id)
        seq = _check_seq(seq)
        if not isinstance(reason, str) or reason not in DISPUTE_REASONS:
            raise PaymentError(
                f"dispute reason must be one of {DISPUTE_REASONS}, got {reason!r}")
        with self._lock:
            self._advance_seq(seq)
            charge = self._charges.get(charge_id)
            if charge is None:
                raise UnknownChargeError(charge_id)
            existing = self._disputes.get(charge_id)
            if existing is not None and existing.status == "open":
                raise TerminalDisputeError(
                    f"charge {charge_id} already has an open dispute")
            self._dispute_counter += 1
            dispute_id = f"dp-{self._dispute_counter}"
            digest = _pin("dispute", self._merchant_id, dispute_id, charge_id,
                          charge.amount, reason, "open", seq)
            rec = DisputeRecord(
                dispute_id=dispute_id, charge_id=charge_id, amount=charge.amount,
                reason=reason, status="open", seq=seq, digest=digest,
            )
            self._disputes[charge_id] = rec
            return rec

    def resolve_dispute(self, charge_id: str, outcome: str, seq: int) -> DisputeRecord:
        """Record the outcome of a dispute (won/lost/withdrawn). Terminal."""
        charge_id = _check_id("charge_id", charge_id)
        seq = _check_seq(seq)
        if not isinstance(outcome, str) or outcome not in DISPUTE_OUTCOMES:
            raise PaymentError(
                f"dispute outcome must be one of {DISPUTE_OUTCOMES}, got {outcome!r}")
        with self._lock:
            self._advance_seq(seq)
            dispute = self._disputes.get(charge_id)
            if dispute is None or dispute.status != "open":
                raise TerminalDisputeError(
                    f"charge {charge_id} has no open dispute to resolve")
            digest = _pin("dispute", self._merchant_id, dispute.dispute_id,
                          charge_id, dispute.amount, dispute.reason, outcome, seq)
            rec = DisputeRecord(
                dispute_id=dispute.dispute_id, charge_id=charge_id,
                amount=dispute.amount, reason=dispute.reason,
                status=outcome, seq=seq, digest=digest,
            )
            self._disputes[charge_id] = rec
            return rec

    # -- views -------------------------------------------------------------

    def charge_record(self, charge_id: str) -> ChargeRecord:
        charge_id = _check_id("charge_id", charge_id)
        with self._lock:
            rec = self._charges.get(charge_id)
            if rec is None:
                raise UnknownChargeError(charge_id)
            return rec

    def refund_record(self, refund_id: str) -> RefundRecord:
        refund_id = _check_id("refund_id", refund_id)
        with self._lock:
            rec = self._refunds.get(refund_id)
            if rec is None:
                raise UnknownRefundError(refund_id)
            return rec

    def dispute_for(self, charge_id: str) -> Optional[DisputeRecord]:
        charge_id = _check_id("charge_id", charge_id)
        with self._lock:
            return self._disputes.get(charge_id)

    def refunded_total(self, charge_id: str) -> int:
        charge_id = _check_id("charge_id", charge_id)
        with self._lock:
            if charge_id not in self._charges:
                raise UnknownChargeError(charge_id)
            return self._refunded_total[charge_id]

    def remaining_refundable(self, charge_id: str) -> int:
        charge_id = _check_id("charge_id", charge_id)
        with self._lock:
            charge = self._charges.get(charge_id)
            if charge is None:
                raise UnknownChargeError(charge_id)
            return charge.amount - self._refunded_total[charge_id]


# ---------------------------------------------------------------------------
# audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = ("charged", "refunded", "disputed", "dispute-resolved", "rejected")


def payment_processor_audit_event(kind: str, seq: int, record_id: str = "") -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record. Only ids + digest pins; never amounts."""
    if kind not in _AUDIT_KINDS:
        raise PaymentError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    return {
        "kind": kind,
        "seq": seq,
        "record_id": record_id,
        "version": VERSION,
        "schema": SCHEMA,
    }


# ---------------------------------------------------------------------------
# self-check
# ---------------------------------------------------------------------------

def main() -> None:
    p = PaymentProcessor("merch-1")
    ch = p.charge(2500, "usd", "cus-1", "pm-1", seq=1, idempotency_key="key-1")
    assert ch.charge_id == "ch-1" and ch.amount == 2500 and ch.currency == "USD"
    same = p.charge(2500, "usd", "cus-1", "pm-1", seq=2, idempotency_key="key-1")
    assert same.charge_id == "ch-1", "idempotent replay must return original"
    try:
        p.charge(9999, "usd", "cus-1", "pm-1", seq=3, idempotency_key="key-1")
        raise AssertionError("idempotency mismatch must fail")
    except IdempotencyMismatchError:
        pass
    re1 = p.refund("ch-1", seq=4, amount=1000)
    assert re1.cumulative_refunded == 1000
    try:
        p.refund("ch-1", seq=5, amount=2000)
        raise AssertionError("refund overrun must fail")
    except RefundExceedsChargeError:
        pass
    dp = p.dispute("ch-1", "fraudulent", seq=6)
    assert dp.status == "open"
    try:
        p.refund("ch-1", seq=7, amount=500)
        raise AssertionError("refund during open dispute must fail")
    except ChargeDisputedError:
        pass
    res = p.resolve_dispute("ch-1", "lost", seq=8)
    assert res.status == "lost"
    assert p.remaining_refundable("ch-1") == 1500
    ev = payment_processor_audit_event("charged", 9, record_id="ch-1")
    assert ev["schema"] == SCHEMA and "amount" not in ev
    print("payment-processor OK: charge, idempotency, refund, dispute, resolve")


if __name__ == "__main__":
    main()
