"""Payout engine interface: marketplace split/schedule/execute bookkeeping.

Research note: a *marketplace payout* engine (Stripe Connect, Adyen for
Platforms shape) sits between the platform's collected funds and the
sellers' bank accounts. The load-bearing invariants are: (1) *exact penny
reconciliation* — percentage splits are computed in integer minor units
with largest-remainder rounding so the lines always sum to the penny of
the input (no drift, no "missing cent" residue); (2) *fee allocation
determinism* — who bears the platform fee (platform vs proportional)
is declared on the split rule, not improvised per payout; (3) *locked
funds* — once a payout is scheduled, its amount leaves the party's
available balance, so the same cent cannot be scheduled twice; (4)
*reserve holds* — a host models rolling-reserve delays (chargeback
protection) as explicit holds, subtracted from the schedulable amount;
(5) *idempotent execution* — a payout executes exactly once; a retried
execute with the same idempotency key replays the original order;
(6) *amounts in minor units* — money is always an integer number of
cents, never a float.

This module implements that shape as a deterministic, single-host ledger:

* **Split rules** — :meth:`PayoutEngine.create_split_rule` pins a frozen
  :class:`SplitRule` (``sr-<n>`` id) with per-party shares in basis
  points (must sum to exactly 10000) and a fee bearer
  (``"platform"`` | ``"proportional"``).
* **Splits** — :meth:`PayoutEngine.split` applies a rule to a gross
  amount + fee and returns a frozen :class:`SplitRecord` whose lines
  carry ``gross_share``/``fee_share``/``net`` per party; the line sums
  are asserted to reconcile to the penny.
* **Schedules** — :meth:`PayoutEngine.create_schedule` pins a frozen
  :class:`PayoutSchedule` (``ps-<n>`` id) per (party, currency):
  frequency (``daily``|``weekly``|``monthly``|``manual``), minimum
  ``threshold``, ``delay_days`` (rolling-reserve policy metadata the
  host enforces via :meth:`PayoutEngine.hold`), and payout ``method``.
* **Credits / debits / holds** — :meth:`PayoutEngine.credit`,
  :meth:`PayoutEngine.debit`, and :meth:`PayoutEngine.hold` move a
  party's per-currency balance; holds reduce the schedulable amount.
* **Scheduling** — :meth:`PayoutEngine.schedule` locks the party's
  available balance (``balance - held``) into a ``scheduled``
  :class:`PayoutOrder` (``po-<n>`` id) when it meets the threshold.
* **Execution** — :meth:`PayoutEngine.execute` moves a scheduled order
  to ``executed`` exactly once (idempotent on caller key);
  :meth:`PayoutEngine.cancel` moves it to ``canceled`` and returns the
  funds to the available balance.

House style: frozen dataclasses, caller-supplied int seqs (strictly
increasing per engine, no wall-clock, no RNG for ids — ids are
monotonic ``sr-<n>``/``ps-<n>``/``po-<n>``/``le-<n>``/``hd-<n>``
counters), RLock-guarded, fail-closed (bool/negative amounts, empty
ids, non-10000 shares, unknown rules/schedules/payouts, below-threshold
scheduling, double execution all raise a subclass of
:class:`PayoutError`), stdlib-only, type-tagged canonical digest
encoding (bool != int; floats and |n| >= 2**53 refused), audit events
shaped for ``audit.ndjson/1``, ``main()`` self-check.

Honest scope: this is a *claims ledger*, not a money rail. It cannot
move money, validate a bank account, or enforce a real rolling-reserve
window — ``hold()`` pins what the host *reported* as held. For real
settlement pair with a PCI-scoped payout rail (Stripe Connect / Adyen)
and ``remote_attestation`` for the host.

Version pin: payout-engine.v1
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

VERSION = "payout-engine.v1"
SCHEMA = "northstar.payout-engine.v1"

__all__ = [
    "VERSION",
    "SCHEMA",
    "PayoutError",
    "UnknownRuleError",
    "InvalidSplitError",
    "UnknownScheduleError",
    "InvalidScheduleError",
    "UnknownPayoutError",
    "TerminalPayoutError",
    "IdempotencyMismatchError",
    "BelowThresholdError",
    "InsufficientFundsError",
    "FEE_BEARERS",
    "FREQUENCIES",
    "PAYOUT_METHODS",
    "SplitAllocation",
    "SplitRule",
    "SplitLine",
    "SplitRecord",
    "PayoutSchedule",
    "LedgerEntry",
    "HoldRecord",
    "PayoutOrder",
    "PayoutEngine",
    "payout_engine_audit_event",
]


class PayoutError(Exception):
    """Base for all payout-engine errors (fail-closed taxonomy)."""


class UnknownRuleError(PayoutError):
    """Split rule id not present in the ledger."""


class InvalidSplitError(PayoutError):
    """Split rule or split inputs are malformed (shares != 10000 bp, etc.)."""


class UnknownScheduleError(PayoutError):
    """Payout schedule id not present in the ledger."""


class InvalidScheduleError(PayoutError):
    """Payout schedule parameters are malformed."""


class UnknownPayoutError(PayoutError):
    """Payout order id not present in the ledger."""


class TerminalPayoutError(PayoutError):
    """A state-changing action on a non-scheduled (executed/canceled) payout."""


class IdempotencyMismatchError(PayoutError):
    """Same idempotency key reused for a different payout."""


class BelowThresholdError(PayoutError):
    """Available balance is below the schedule's payout threshold."""


class InsufficientFundsError(PayoutError):
    """Debit or hold would drive a balance negative."""


# pinned vocabularies
FEE_BEARERS = ("platform", "proportional")
FREQUENCIES = ("daily", "weekly", "monthly", "manual")
PAYOUT_METHODS = ("bank_transfer", "wallet", "check")
PAYOUT_STATUSES = ("scheduled", "executed", "failed", "canceled")
ENTRY_KINDS = ("credit", "debit")


# ---------------------------------------------------------------------------
# canonical encoding (type-tagged; amounts are ints in minor units, floats
# refused outright)
# ---------------------------------------------------------------------------

def _canonical(value: Any) -> str:
    """Type-tagged canonical encoding.

    Tags: N(int) B(bool) S(str) L(list) M(map) Z(None).
    Floats, NaN/inf, and |n| >= 2**53 are refused fail-closed.
    """
    if value is None:
        return "Z"
    if isinstance(value, bool):
        return "B1" if value else "B0"
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise PayoutError(f"integer magnitude >= 2**53 refused: {value!r}")
        return f"N{value}"
    if isinstance(value, float):
        raise PayoutError(f"floats refused in money path: {value!r}")
    if isinstance(value, str):
        return "S" + json.dumps(value, ensure_ascii=True)
    if isinstance(value, (list, tuple)):
        return "L[" + ",".join(_canonical(v) for v in value) + "]"
    if isinstance(value, Mapping):
        items = sorted(value.items(), key=lambda kv: kv[0])
        for k in value:
            if not isinstance(k, str):
                raise PayoutError(f"non-str mapping key refused: {k!r}")
        return "M{" + ",".join(_canonical(k) + ":" + _canonical(v) for k, v in items) + "}"
    raise PayoutError(f"non-canonicalizable value refused: {type(value).__name__}")


def _pin(*parts: Any) -> str:
    body = "|".join(_canonical(p) for p in parts)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# validation helpers
# ---------------------------------------------------------------------------

def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise PayoutError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _check_id(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PayoutError(f"{name} must be a non-empty str, got {value!r}")
    if len(value) > 256:
        raise PayoutError(f"{name} exceeds 256 chars")
    return value.strip()


def _check_amount(amount: Any, *, allow_zero: bool = False) -> int:
    """Money is always an integer number of minor units. Floats refused."""
    if isinstance(amount, bool) or not isinstance(amount, int):
        raise PayoutError(f"amount must be an int (minor units), got {amount!r}")
    if amount < 0 or (amount == 0 and not allow_zero):
        raise PayoutError(f"amount must be {'non-negative' if allow_zero else 'positive'} int, got {amount!r}")
    if amount >= 2**53:
        raise PayoutError(f"amount magnitude >= 2**53 refused: {amount!r}")
    return amount


def _check_currency(currency: Any) -> str:
    if not isinstance(currency, str) or len(currency) != 3 or not currency.isalpha():
        raise PayoutError(f"currency must be a 3-letter ISO code, got {currency!r}")
    return currency.upper()


def _largest_remainder(total: int, shares_bp: List[Tuple[str, int]]) -> List[int]:
    """Split ``total`` minor units across parties by basis points.

    Largest-remainder method, deterministic (ties broken by party_id):
    the returned list sums to exactly ``total``. ``shares_bp`` must sum to
    exactly 10000.
    """
    if total < 0:
        raise PayoutError(f"total must be non-negative, got {total!r}")
    if sum(bp for _, bp in shares_bp) != 10000:
        raise InvalidSplitError(
            f"shares must sum to 10000 basis points, got {sum(bp for _, bp in shares_bp)}")
    floors: List[int] = []
    remainders: List[Tuple[int, str]] = []
    for party_id, bp in shares_bp:
        exact = total * bp
        floors.append(exact // 10000)
        remainders.append((exact % 10000, party_id))
    leftover = total - sum(floors)
    order = sorted(range(len(shares_bp)), key=lambda i: (-remainders[i][0], shares_bp[i][0]))
    result = list(floors)
    for i in order[:leftover]:
        result[i] += 1
    assert sum(result) == total
    return result


# ---------------------------------------------------------------------------
# frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SplitAllocation:
    party_id: str
    share_bp: int  # basis points of gross; rule total must be 10000

    def as_dict(self) -> Dict[str, Any]:
        return {"party_id": self.party_id, "share_bp": self.share_bp}


@dataclass(frozen=True)
class SplitRule:
    rule_id: str
    name: str
    allocations: Tuple[SplitAllocation, ...]
    fee_bearer: str  # "platform" | "proportional"
    seq: int
    digest: str
    version: str = field(default=VERSION, compare=False)
    schema: str = field(default=SCHEMA, compare=False)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "allocations": [a.as_dict() for a in self.allocations],
            "fee_bearer": self.fee_bearer,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class SplitLine:
    party_id: str
    gross_share: int
    fee_share: int
    net: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "party_id": self.party_id,
            "gross_share": self.gross_share,
            "fee_share": self.fee_share,
            "net": self.net,
        }


@dataclass(frozen=True)
class SplitRecord:
    split_id: str
    rule_id: str
    gross_amount: int
    fee_amount: int
    currency: str
    reference: str
    lines: Tuple[SplitLine, ...]
    seq: int
    digest: str
    version: str = field(default=VERSION, compare=False)
    schema: str = field(default=SCHEMA, compare=False)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "split_id": self.split_id,
            "rule_id": self.rule_id,
            "gross_amount": self.gross_amount,
            "fee_amount": self.fee_amount,
            "currency": self.currency,
            "reference": self.reference,
            "lines": [ln.as_dict() for ln in self.lines],
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class PayoutSchedule:
    schedule_id: str
    party_id: str
    currency: str
    frequency: str  # daily | weekly | monthly | manual
    threshold: int  # minimum available minor units to schedule
    delay_days: int  # rolling-reserve policy metadata; host enforces via hold()
    method: str  # bank_transfer | wallet | check
    enabled: bool
    seq: int
    digest: str
    version: str = field(default=VERSION, compare=False)
    schema: str = field(default=SCHEMA, compare=False)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schedule_id": self.schedule_id,
            "party_id": self.party_id,
            "currency": self.currency,
            "frequency": self.frequency,
            "threshold": self.threshold,
            "delay_days": self.delay_days,
            "method": self.method,
            "enabled": self.enabled,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class LedgerEntry:
    entry_id: str
    party_id: str
    kind: str  # credit | debit
    amount: int
    currency: str
    memo: str
    balance_after: int
    seq: int
    digest: str
    version: str = field(default=VERSION, compare=False)
    schema: str = field(default=SCHEMA, compare=False)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "party_id": self.party_id,
            "kind": self.kind,
            "amount": self.amount,
            "currency": self.currency,
            "memo": self.memo,
            "balance_after": self.balance_after,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class HoldRecord:
    hold_id: str
    party_id: str
    amount: int
    currency: str
    reason: str
    held_after: int
    seq: int
    digest: str
    version: str = field(default=VERSION, compare=False)
    schema: str = field(default=SCHEMA, compare=False)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "hold_id": self.hold_id,
            "party_id": self.party_id,
            "amount": self.amount,
            "currency": self.currency,
            "reason": self.reason,
            "held_after": self.held_after,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class PayoutOrder:
    payout_id: str
    schedule_id: str
    party_id: str
    amount: int
    currency: str
    method: str
    status: str  # scheduled | executed | failed | canceled
    idempotency_key: Optional[str]
    seq: int
    digest: str
    version: str = field(default=VERSION, compare=False)
    schema: str = field(default=SCHEMA, compare=False)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "payout_id": self.payout_id,
            "schedule_id": self.schedule_id,
            "party_id": self.party_id,
            "amount": self.amount,
            "currency": self.currency,
            "method": self.method,
            "status": self.status,
            "idempotency_key": self.idempotency_key,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------

class PayoutEngine:
    """Deterministic single-host marketplace payout ledger."""

    def __init__(self, platform_id: str):
        self._platform_id = _check_id("platform_id", platform_id)
        self._lock = threading.RLock()
        self._rules: Dict[str, SplitRule] = {}
        self._splits: Dict[str, SplitRecord] = {}
        self._schedules: Dict[str, PayoutSchedule] = {}
        self._entries: Dict[str, LedgerEntry] = {}
        self._holds: Dict[str, HoldRecord] = {}
        self._payouts: Dict[str, PayoutOrder] = {}
        self._idempotency: Dict[str, str] = {}  # key -> payout_id
        self._balances: Dict[Tuple[str, str], int] = {}
        self._held: Dict[Tuple[str, str], int] = {}
        self._locked: Dict[Tuple[str, str], int] = {}  # scheduled-not-yet-executed
        self._rule_counter = 0
        self._split_counter = 0
        self._schedule_counter = 0
        self._entry_counter = 0
        self._hold_counter = 0
        self._payout_counter = 0
        self._last_seq = -1

    def _advance_seq(self, seq: int) -> None:
        if seq <= self._last_seq:
            raise PayoutError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq

    def _balance(self, party_id: str, currency: str) -> int:
        return self._balances.get((party_id, currency), 0)

    def _held_amount(self, party_id: str, currency: str) -> int:
        return self._held.get((party_id, currency), 0)

    # -- split rules -----------------------------------------------------

    def create_split_rule(
        self,
        name: str,
        allocations: Mapping[str, int],
        fee_bearer: str,
        seq: int,
    ) -> SplitRule:
        """Pin a split rule. ``allocations`` maps party_id -> share in
        basis points; the shares must sum to exactly 10000."""
        name = _check_id("name", name)
        seq = _check_seq(seq)
        if not isinstance(allocations, Mapping) or not allocations:
            raise InvalidSplitError("allocations must be a non-empty mapping")
        if not isinstance(fee_bearer, str) or fee_bearer not in FEE_BEARERS:
            raise InvalidSplitError(
                f"fee_bearer must be one of {FEE_BEARERS}, got {fee_bearer!r}")
        parts: List[SplitAllocation] = []
        for party_id, bp in allocations.items():
            party_id = _check_id("party_id", party_id)
            if isinstance(bp, bool) or not isinstance(bp, int) or bp < 0:
                raise InvalidSplitError(
                    f"share for {party_id!r} must be a non-negative int bp, got {bp!r}")
            parts.append(SplitAllocation(party_id=party_id, share_bp=bp))
        total_bp = sum(p.share_bp for p in parts)
        if total_bp != 10000:
            raise InvalidSplitError(
                f"shares must sum to 10000 basis points, got {total_bp}")
        if len({p.party_id for p in parts}) != len(parts):
            raise InvalidSplitError("duplicate party_id in allocations")
        with self._lock:
            self._advance_seq(seq)
            self._rule_counter += 1
            rule_id = f"sr-{self._rule_counter}"
            ordered = tuple(sorted(parts, key=lambda p: p.party_id))
            digest = _pin("split-rule", self._platform_id, rule_id, name,
                          [(p.party_id, p.share_bp) for p in ordered],
                          fee_bearer, seq)
            rec = SplitRule(rule_id=rule_id, name=name, allocations=ordered,
                            fee_bearer=fee_bearer, seq=seq, digest=digest)
            self._rules[rule_id] = rec
            return rec

    # -- splits ----------------------------------------------------------

    def split(
        self,
        rule_id: str,
        gross_amount: int,
        fee_amount: int,
        currency: str,
        seq: int,
        reference: str = "",
    ) -> SplitRecord:
        """Apply a split rule: distribute ``gross_amount`` (minor units)
        across the rule's parties, allocating ``fee_amount`` per the rule's
        fee bearer. Lines reconcile to the penny via largest remainder."""
        rule_id = _check_id("rule_id", rule_id)
        gross_amount = _check_amount(gross_amount)
        fee_amount = _check_amount(fee_amount, allow_zero=True)
        currency = _check_currency(currency)
        seq = _check_seq(seq)
        if not isinstance(reference, str) or len(reference) > 256:
            raise PayoutError(f"reference must be a str <= 256 chars, got {reference!r}")
        if fee_amount > gross_amount:
            raise InvalidSplitError(
                f"fee_amount {fee_amount} > gross_amount {gross_amount}")
        with self._lock:
            self._advance_seq(seq)
            rule = self._rules.get(rule_id)
            if rule is None:
                raise UnknownRuleError(rule_id)
            shares = [(p.party_id, p.share_bp) for p in rule.allocations]
            gross_lines = _largest_remainder(gross_amount, shares)
            if rule.fee_bearer == "platform":
                fee_lines = [0] * len(shares)
            else:
                fee_lines = _largest_remainder(fee_amount, shares)
            lines = tuple(
                SplitLine(party_id=party_id,
                          gross_share=gross_lines[i],
                          fee_share=fee_lines[i],
                          net=gross_lines[i] - fee_lines[i])
                for i, (party_id, _bp) in enumerate(shares)
            )
            # penny reconciliation, asserted (defense in depth).
            # With a platform fee bearer the platform eats the fee outside
            # the party lines, so fee lines are zero and nets sum to gross.
            assert sum(ln.gross_share for ln in lines) == gross_amount
            if rule.fee_bearer == "platform":
                assert sum(ln.fee_share for ln in lines) == 0
                assert sum(ln.net for ln in lines) == gross_amount
            else:
                assert sum(ln.fee_share for ln in lines) == fee_amount
                assert sum(ln.net for ln in lines) == gross_amount - fee_amount
            self._split_counter += 1
            split_id = f"sp-{self._split_counter}"
            digest = _pin("split", self._platform_id, split_id, rule_id,
                          gross_amount, fee_amount, currency, reference,
                          [(ln.party_id, ln.gross_share, ln.fee_share, ln.net)
                           for ln in lines], seq)
            rec = SplitRecord(split_id=split_id, rule_id=rule_id,
                              gross_amount=gross_amount, fee_amount=fee_amount,
                              currency=currency, reference=reference,
                              lines=lines, seq=seq, digest=digest)
            self._splits[split_id] = rec
            return rec

    # -- ledger (credits / debits / holds) --------------------------------

    def _record_entry(self, party_id: str, kind: str, amount: int,
                      currency: str, memo: str, seq: int) -> LedgerEntry:
        self._entry_counter += 1
        entry_id = f"le-{self._entry_counter}"
        key = (party_id, currency)
        if kind == "credit":
            self._balances[key] = self._balance(party_id, currency) + amount
        else:
            if amount > self._balance(party_id, currency):
                raise InsufficientFundsError(
                    f"debit {amount} exceeds balance {self._balance(party_id, currency)}"
                    f" for {party_id}/{currency}")
            self._balances[key] = self._balance(party_id, currency) - amount
        digest = _pin("ledger-entry", self._platform_id, entry_id, party_id,
                      kind, amount, currency, memo,
                      self._balances[key], seq)
        rec = LedgerEntry(entry_id=entry_id, party_id=party_id, kind=kind,
                          amount=amount, currency=currency, memo=memo,
                          balance_after=self._balances[key], seq=seq,
                          digest=digest)
        self._entries[entry_id] = rec
        return rec

    def credit(self, party_id: str, amount: int, currency: str, seq: int,
               memo: str = "") -> LedgerEntry:
        """Add funds (e.g. a seller's net share of a settled split) to a
        party's balance."""
        party_id = _check_id("party_id", party_id)
        amount = _check_amount(amount)
        currency = _check_currency(currency)
        seq = _check_seq(seq)
        memo = _check_id("memo", memo) if memo else ""
        with self._lock:
            self._advance_seq(seq)
            return self._record_entry(party_id, "credit", amount, currency, memo, seq)

    def debit(self, party_id: str, amount: int, currency: str, seq: int,
              memo: str = "") -> LedgerEntry:
        """Remove funds (e.g. a refund or chargeback against a seller).
        Fails closed when the balance cannot cover it."""
        party_id = _check_id("party_id", party_id)
        amount = _check_amount(amount)
        currency = _check_currency(currency)
        seq = _check_seq(seq)
        memo = _check_id("memo", memo) if memo else ""
        with self._lock:
            self._advance_seq(seq)
            return self._record_entry(party_id, "debit", amount, currency, memo, seq)

    def hold(self, party_id: str, amount: int, currency: str, seq: int,
             reason: str = "") -> HoldRecord:
        """Place a reserve hold (rolling-reserve / dispute-protection
        window): held funds stay in the balance but are not schedulable."""
        party_id = _check_id("party_id", party_id)
        amount = _check_amount(amount)
        currency = _check_currency(currency)
        seq = _check_seq(seq)
        reason = _check_id("reason", reason) if reason else ""
        with self._lock:
            self._advance_seq(seq)
            key = (party_id, currency)
            free = self._balance(party_id, currency) - self._held_amount(party_id, currency) \
                - self._locked.get(key, 0)
            if amount > free:
                raise InsufficientFundsError(
                    f"hold {amount} exceeds free balance {free} for {party_id}/{currency}")
            self._hold_counter += 1
            hold_id = f"hd-{self._hold_counter}"
            self._held[key] = self._held_amount(party_id, currency) + amount
            digest = _pin("hold", self._platform_id, hold_id, party_id,
                          amount, currency, reason, self._held[key], seq)
            rec = HoldRecord(hold_id=hold_id, party_id=party_id, amount=amount,
                             currency=currency, reason=reason,
                             held_after=self._held[key], seq=seq, digest=digest)
            self._holds[hold_id] = rec
            return rec

    # -- schedules -------------------------------------------------------

    def create_schedule(
        self,
        party_id: str,
        currency: str,
        frequency: str,
        threshold: int,
        delay_days: int,
        method: str,
        seq: int,
        enabled: bool = True,
    ) -> PayoutSchedule:
        """Pin a payout schedule for one (party, currency). ``delay_days``
        records the rolling-reserve policy; the host enforces the window
        by calling :meth:`hold` (this ledger has no wall clock)."""
        party_id = _check_id("party_id", party_id)
        currency = _check_currency(currency)
        seq = _check_seq(seq)
        if not isinstance(frequency, str) or frequency not in FREQUENCIES:
            raise InvalidScheduleError(
                f"frequency must be one of {FREQUENCIES}, got {frequency!r}")
        threshold = _check_amount(threshold, allow_zero=True)
        if isinstance(delay_days, bool) or not isinstance(delay_days, int) or delay_days < 0:
            raise InvalidScheduleError(
                f"delay_days must be a non-negative int, got {delay_days!r}")
        if not isinstance(method, str) or method not in PAYOUT_METHODS:
            raise InvalidScheduleError(
                f"method must be one of {PAYOUT_METHODS}, got {method!r}")
        if not isinstance(enabled, bool):
            raise InvalidScheduleError(f"enabled must be a bool, got {enabled!r}")
        with self._lock:
            self._advance_seq(seq)
            self._schedule_counter += 1
            schedule_id = f"ps-{self._schedule_counter}"
            digest = _pin("payout-schedule", self._platform_id, schedule_id,
                          party_id, currency, frequency, threshold,
                          delay_days, method, enabled, seq)
            rec = PayoutSchedule(schedule_id=schedule_id, party_id=party_id,
                                 currency=currency, frequency=frequency,
                                 threshold=threshold, delay_days=delay_days,
                                 method=method, enabled=enabled, seq=seq,
                                 digest=digest)
            self._schedules[schedule_id] = rec
            return rec

    def set_schedule_enabled(self, schedule_id: str, enabled: bool, seq: int) -> PayoutSchedule:
        """Enable or disable a schedule (returns the updated record)."""
        schedule_id = _check_id("schedule_id", schedule_id)
        seq = _check_seq(seq)
        if not isinstance(enabled, bool):
            raise InvalidScheduleError(f"enabled must be a bool, got {enabled!r}")
        with self._lock:
            self._advance_seq(seq)
            sched = self._schedules.get(schedule_id)
            if sched is None:
                raise UnknownScheduleError(schedule_id)
            digest = _pin("payout-schedule", self._platform_id, schedule_id,
                          sched.party_id, sched.currency, sched.frequency,
                          sched.threshold, sched.delay_days, sched.method,
                          enabled, seq)
            rec = PayoutSchedule(schedule_id=schedule_id, party_id=sched.party_id,
                                 currency=sched.currency, frequency=sched.frequency,
                                 threshold=sched.threshold, delay_days=sched.delay_days,
                                 method=sched.method, enabled=enabled, seq=seq,
                                 digest=digest)
            self._schedules[schedule_id] = rec
            return rec

    # -- schedule / execute / cancel -------------------------------------

    def schedule(
        self,
        schedule_id: str,
        seq: int,
        idempotency_key: Optional[str] = None,
    ) -> PayoutOrder:
        """Lock the party's available balance (balance - held - locked)
        into a ``scheduled`` payout order. Fails closed when the schedule
        is disabled or the available amount is below the threshold."""
        schedule_id = _check_id("schedule_id", schedule_id)
        seq = _check_seq(seq)
        if idempotency_key is not None:
            idempotency_key = _check_id("idempotency_key", idempotency_key)
        with self._lock:
            self._advance_seq(seq)
            if idempotency_key is not None and idempotency_key in self._idempotency:
                return self._payouts[self._idempotency[idempotency_key]]
            sched = self._schedules.get(schedule_id)
            if sched is None:
                raise UnknownScheduleError(schedule_id)
            if not sched.enabled:
                raise InvalidScheduleError(f"schedule {schedule_id} is disabled")
            key = (sched.party_id, sched.currency)
            available = (self._balance(sched.party_id, sched.currency)
                         - self._held_amount(sched.party_id, sched.currency)
                         - self._locked.get(key, 0))
            if available < sched.threshold:
                raise BelowThresholdError(
                    f"available {available} < threshold {sched.threshold} "
                    f"for {sched.party_id}/{sched.currency}")
            self._payout_counter += 1
            payout_id = f"po-{self._payout_counter}"
            self._locked[key] = self._locked.get(key, 0) + available
            digest = _pin("payout-order", self._platform_id, payout_id,
                          schedule_id, sched.party_id, available,
                          sched.currency, sched.method, "scheduled", seq)
            rec = PayoutOrder(payout_id=payout_id, schedule_id=schedule_id,
                              party_id=sched.party_id, amount=available,
                              currency=sched.currency, method=sched.method,
                              status="scheduled",
                              idempotency_key=idempotency_key, seq=seq,
                              digest=digest)
            self._payouts[payout_id] = rec
            if idempotency_key is not None:
                self._idempotency[idempotency_key] = payout_id
            return rec

    def execute(
        self,
        payout_id: str,
        seq: int,
        idempotency_key: Optional[str] = None,
    ) -> PayoutOrder:
        """Execute a scheduled payout exactly once. A retried call with the
        same idempotency key replays the original order; executing a
        non-scheduled order fails closed."""
        payout_id = _check_id("payout_id", payout_id)
        seq = _check_seq(seq)
        if idempotency_key is not None:
            idempotency_key = _check_id("idempotency_key", idempotency_key)
        with self._lock:
            self._advance_seq(seq)
            if idempotency_key is not None and idempotency_key in self._idempotency:
                prior_id = self._idempotency[idempotency_key]
                if prior_id != payout_id:
                    raise IdempotencyMismatchError(
                        f"idempotency key {idempotency_key!r} reused for a different payout")
                return self._payouts[prior_id]
            order = self._payouts.get(payout_id)
            if order is None:
                raise UnknownPayoutError(payout_id)
            if order.status != "scheduled":
                raise TerminalPayoutError(
                    f"payout {payout_id} is {order.status}; only scheduled payouts execute")
            key = (order.party_id, order.currency)
            self._locked[key] = self._locked.get(key, 0) - order.amount
            self._balances[key] = self._balance(order.party_id, order.currency) - order.amount
            digest = _pin("payout-order", self._platform_id, payout_id,
                          order.schedule_id, order.party_id, order.amount,
                          order.currency, order.method, "executed", seq)
            rec = PayoutOrder(payout_id=payout_id, schedule_id=order.schedule_id,
                              party_id=order.party_id, amount=order.amount,
                              currency=order.currency, method=order.method,
                              status="executed",
                              idempotency_key=idempotency_key or order.idempotency_key,
                              seq=seq, digest=digest)
            self._payouts[payout_id] = rec
            if idempotency_key is not None:
                self._idempotency[idempotency_key] = payout_id
            return rec

    def cancel(self, payout_id: str, seq: int) -> PayoutOrder:
        """Cancel a scheduled payout and return its locked amount to the
        party's available balance."""
        payout_id = _check_id("payout_id", payout_id)
        seq = _check_seq(seq)
        with self._lock:
            self._advance_seq(seq)
            order = self._payouts.get(payout_id)
            if order is None:
                raise UnknownPayoutError(payout_id)
            if order.status != "scheduled":
                raise TerminalPayoutError(
                    f"payout {payout_id} is {order.status}; only scheduled payouts cancel")
            key = (order.party_id, order.currency)
            self._locked[key] = self._locked.get(key, 0) - order.amount
            digest = _pin("payout-order", self._platform_id, payout_id,
                          order.schedule_id, order.party_id, order.amount,
                          order.currency, order.method, "canceled", seq)
            rec = PayoutOrder(payout_id=payout_id, schedule_id=order.schedule_id,
                              party_id=order.party_id, amount=order.amount,
                              currency=order.currency, method=order.method,
                              status="canceled",
                              idempotency_key=order.idempotency_key,
                              seq=seq, digest=digest)
            self._payouts[payout_id] = rec
            return rec

    # -- views -----------------------------------------------------------

    def split_rule(self, rule_id: str) -> SplitRule:
        rule_id = _check_id("rule_id", rule_id)
        with self._lock:
            rec = self._rules.get(rule_id)
            if rec is None:
                raise UnknownRuleError(rule_id)
            return rec

    def schedule_record(self, schedule_id: str) -> PayoutSchedule:
        schedule_id = _check_id("schedule_id", schedule_id)
        with self._lock:
            rec = self._schedules.get(schedule_id)
            if rec is None:
                raise UnknownScheduleError(schedule_id)
            return rec

    def payout_record(self, payout_id: str) -> PayoutOrder:
        payout_id = _check_id("payout_id", payout_id)
        with self._lock:
            rec = self._payouts.get(payout_id)
            if rec is None:
                raise UnknownPayoutError(payout_id)
            return rec

    def balance(self, party_id: str, currency: str) -> int:
        party_id = _check_id("party_id", party_id)
        currency = _check_currency(currency)
        with self._lock:
            return self._balance(party_id, currency)

    def held_balance(self, party_id: str, currency: str) -> int:
        party_id = _check_id("party_id", party_id)
        currency = _check_currency(currency)
        with self._lock:
            return self._held_amount(party_id, currency)

    def available_balance(self, party_id: str, currency: str) -> int:
        party_id = _check_id("party_id", party_id)
        currency = _check_currency(currency)
        with self._lock:
            key = (party_id, currency)
            return (self._balance(party_id, currency)
                    - self._held_amount(party_id, currency)
                    - self._locked.get(key, 0))


# ---------------------------------------------------------------------------
# audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = ("split", "credited", "debited", "held",
                "scheduled", "executed", "canceled", "rejected")


def payout_engine_audit_event(kind: str, seq: int, record_id: str = "") -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record. Only ids + digest pins; never amounts."""
    if kind not in _AUDIT_KINDS:
        raise PayoutError(f"unknown audit kind: {kind!r}")
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
    e = PayoutEngine("platform-1")
    rule = e.create_split_rule("marketplace-70-30",
                               {"seller-a": 7000, "platform": 3000},
                               "proportional", seq=1)
    assert rule.rule_id == "sr-1"
    sp = e.split("sr-1", 10000, 300, "usd", seq=2, reference="order-1")
    assert sp.split_id == "sp-1"
    assert sum(ln.gross_share for ln in sp.lines) == 10000
    assert sum(ln.fee_share for ln in sp.lines) == 300
    assert sum(ln.net for ln in sp.lines) == 9700
    seller_net = next(ln.net for ln in sp.lines if ln.party_id == "seller-a")
    e.credit("seller-a", seller_net, "USD", seq=3, memo="order-1")
    sched = e.create_schedule("seller-a", "usd", "daily", 100, 2,
                              "bank_transfer", seq=4)
    assert sched.schedule_id == "ps-1"
    po = e.schedule("ps-1", seq=5)
    assert po.status == "scheduled" and po.amount == seller_net
    assert e.available_balance("seller-a", "USD") == 0
    done = e.execute(po.payout_id, seq=6, idempotency_key="exec-1")
    assert done.status == "executed"
    replay = e.execute(po.payout_id, seq=7, idempotency_key="exec-1")
    assert replay.payout_id == po.payout_id
    try:
        e.execute(po.payout_id, seq=8)
        raise AssertionError("double execute must fail")
    except TerminalPayoutError:
        pass
    # below-threshold path
    sched2 = e.create_schedule("seller-b", "usd", "weekly", 5000, 0,
                               "wallet", seq=9)
    e.credit("seller-b", 100, "USD", seq=10)
    try:
        e.schedule(sched2.schedule_id, seq=11)
        raise AssertionError("below threshold must fail")
    except BelowThresholdError:
        pass
    ev = payout_engine_audit_event("executed", 12, record_id=po.payout_id)
    assert ev["schema"] == SCHEMA and "amount" not in ev
    print("payout-engine OK: split, schedule, execute, threshold, idempotency")


if __name__ == "__main__":
    main()
