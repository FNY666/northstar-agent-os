"""Double-entry accounting ledger interface: debit/credit bookkeeping.

Research note: double-entry bookkeeping (the accounting core of every
ERP — NetSuite, SAP, QuickBooks — and of agent-facing money tooling like
billing engines and payout ledgers) rests on one invariant: *every
journal entry balances*. Each transaction touches at least two accounts,
and for every entry the sum of debits equals the sum of credits, so the
books always satisfy the accounting equation

    assets = liabilities + equity + (revenue - expenses)

The load-bearing invariants this module enforces are:

1. **Balanced entries** — ``post()`` rejects any entry whose debits do
   not equal its credits (``UnbalancedEntryError``). Nothing
   one-sided ever touches the books.
2. **Chart of accounts** — postings go to registered accounts only
   (``UnknownAccountError``). Every account has a *type* (asset,
   liability, equity, revenue, expense) which fixes its normal side.
3. **Minor-unit integers** — amounts are non-negative integers in the
   currency's smallest unit (cents), never floats (``InvalidAmountError``).
   No IEEE rounding anywhere in the money path.
4. **Trial balance** — ``trial_balance()`` recomputes every account's
   debit/credit totals from the journal and asserts total debits equal
   total credits; a mismatch raises ``TrialBalanceMismatchError`` instead
   of silently returning a bad report.
5. **Auditability** — every posted entry is frozen, carries a ``sha256:``
   digest pin over its canonical contents, and produces an audit event
   shaped for ``audit.ndjson/1``.

House style: frozen dataclasses, caller-supplied int seqs (strictly
increasing per ledger, no wall-clock, no RNG for ids — entry ids are
monotonic ``tx-<n>`` counters), RLock-guarded, fail-closed (bool/negative
amounts, unknown accounts, unbalanced entries, duplicate seqs all raise a
subclass of :class:`LedgerError`), stdlib-only, type-tagged canonical
digest encoding, ``main()`` self-check.

Honest scope: this is a *bookkeeping* ledger, not an accounting firm. It
records what the host reports; it cannot prove that a cash account really
holds cash, enforce GAAP/IFRS presentation, or detect a host that posts
fictional entries (GIGO, same boundary as every other bookkeeping
module). Multi-currency books must convert *before* posting — posting
mixed currencies to one ledger is rejected so a host cannot silently mix
money.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


#: Module version.
VERSION = "ledger.v1"

#: Schema pin for records produced by this module.
SCHEMA = "northstar.ledger.v1"


class LedgerError(ValueError):
    """Base for all ledger errors. A malformed post, not a verdict."""


class UnknownAccountError(LedgerError):
    """Posting referenced an account not in the chart of accounts."""


class UnbalancedEntryError(LedgerError):
    """A journal entry's debits did not equal its credits."""


class InvalidAmountError(LedgerError):
    """Amount was not a positive minor-unit integer."""


class DuplicateSeqError(LedgerError):
    """Caller seq was not strictly increasing for this ledger."""


class TrialBalanceMismatchError(LedgerError):
    """Recomputed trial balance did not balance; journal is corrupt."""


class CurrencyMismatchError(LedgerError):
    """Entry currency did not match the ledger's booked currency."""


#: Valid account types and their normal-balance sides.
ACCOUNT_TYPES = ("asset", "liability", "equity", "revenue", "expense")
_NORMAL_SIDE = {
    "asset": "debit",
    "expense": "debit",
    "liability": "credit",
    "equity": "credit",
    "revenue": "credit",
}


def _check_amount(amount: Any, what: str) -> int:
    if isinstance(amount, bool) or not isinstance(amount, int):
        raise InvalidAmountError(f"{what} must be an int, got {type(amount).__name__}")
    if amount <= 0:
        raise InvalidAmountError(f"{what} must be positive, got {amount}")
    return amount


def _digest(parts: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(dict(parts))).hexdigest()


@dataclass(frozen=True)
class Account:
    """One chart-of-accounts row. Name, type, and normal side."""

    name: str
    account_type: str
    currency: str
    version: str = VERSION
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise LedgerError("account name must be a non-empty string")
        if self.account_type not in ACCOUNT_TYPES:
            raise LedgerError(f"account type must be one of {ACCOUNT_TYPES}")
        if not self.currency or not isinstance(self.currency, str):
            raise LedgerError("account currency must be a non-empty string")


@dataclass(frozen=True)
class JournalLine:
    """One debit-or-credit line inside a balanced journal entry."""

    account: str
    debit: int = 0
    credit: int = 0

    def __post_init__(self) -> None:
        if not self.account or not isinstance(self.account, str):
            raise LedgerError("line account must be a non-empty string")
        for side in ("debit", "credit"):
            value = getattr(self, side)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise InvalidAmountError(f"line {side} must be a non-negative int")
        if self.debit and self.credit:
            raise LedgerError("a line must not carry both debit and credit")
        if not self.debit and not self.credit:
            raise LedgerError("a line must carry a non-zero debit or credit")


@dataclass(frozen=True)
class JournalEntry:
    """A posted, balanced double-entry transaction."""

    entry_id: str
    seq: int
    memo: str
    currency: str
    lines: tuple
    digest: str
    version: str = VERSION
    schema: str = SCHEMA

    @property
    def total_debits(self) -> int:
        return sum(line.debit for line in self.lines)

    @property
    def total_credits(self) -> int:
        return sum(line.credit for line in self.lines)


@dataclass(frozen=True)
class TrialBalanceRow:
    """One account's debit/credit totals; balanced net is implied."""

    account: str
    account_type: str
    debit_total: int
    credit_total: int
    normal_balance: int  # magnitude on the account's normal side


class Ledger:
    """A double-entry journal with a fixed chart of accounts.

    The chart is fixed at construction: postings reference accounts by
    name, and ``post()`` validates the entry balances before appending it
    to the journal. Balances are always recomputed from the journal —
    there is no cached balance state to drift.
    """

    def __init__(self, name: str, currency: str,
                 accounts: List[Mapping[str, str]]) -> None:
        if not name or not isinstance(name, str):
            raise LedgerError("ledger name must be a non-empty string")
        if not currency or not isinstance(currency, str):
            raise LedgerError("ledger currency must be a non-empty string")
        self._name = name
        self._currency = currency.upper()
        self._lock = threading.RLock()
        self._accounts: Dict[str, Account] = {}
        for spec in accounts:
            acct = Account(name=spec["name"], account_type=spec["type"],
                           currency=self._currency)
            if acct.name in self._accounts:
                raise LedgerError(f"duplicate account: {acct.name}")
            self._accounts[acct.name] = acct
        self._journal: List[JournalEntry] = []
        self._last_seq = 0
        self._counter = 0

    @property
    def name(self) -> str:
        return self._name

    @property
    def currency(self) -> str:
        return self._currency

    @property
    def chart(self) -> Dict[str, Account]:
        with self._lock:
            return dict(self._accounts)

    def post(self, lines: List[JournalLine], memo: str, *,
             currency: Optional[str] = None, seq: int) -> JournalEntry:
        """Post one balanced journal entry. Raises on any violation."""
        if not memo or not isinstance(memo, str):
            raise LedgerError("memo must be a non-empty string")
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise LedgerError("seq must be an int")
        if not lines:
            raise UnbalancedEntryError("entry must have at least one line")
        cur = (currency or self._currency).upper()
        if cur != self._currency:
            raise CurrencyMismatchError(
                f"entry currency {cur} != ledger currency {self._currency}")
        with self._lock:
            if seq <= self._last_seq:
                raise DuplicateSeqError(
                    f"seq {seq} not strictly increasing (last {self._last_seq})")
            frozen = tuple(lines)
            for line in frozen:
                if line.account not in self._accounts:
                    raise UnknownAccountError(f"unknown account: {line.account}")
            debits = sum(line.debit for line in frozen)
            credits = sum(line.credit for line in frozen)
            if debits == 0 or credits == 0:
                raise UnbalancedEntryError("entry must post both debits and credits")
            if debits != credits:
                raise UnbalancedEntryError(
                    f"debits {debits} != credits {credits}")
            self._counter += 1
            entry_id = f"tx-{self._counter}"
            digest = _digest({
                "ledger": self._name,
                "entry_id": entry_id,
                "seq": seq,
                "memo": memo,
                "currency": self._currency,
                "lines": [
                    {"account": l.account, "debit": l.debit, "credit": l.credit}
                    for l in frozen
                ],
                "schema": SCHEMA,
                "version": VERSION,
            })
            entry = JournalEntry(entry_id=entry_id, seq=seq, memo=memo,
                                 currency=self._currency, lines=frozen,
                                 digest=digest)
            self._journal.append(entry)
            self._last_seq = seq
            return entry

    def entries(self) -> List[JournalEntry]:
        """The full journal, oldest first."""
        with self._lock:
            return list(self._journal)

    def balance(self, account: str) -> Dict[str, int]:
        """Account balance: debit/credit totals plus signed net.

        ``net`` is signed on the account's *normal* side: positive means
        a debit balance for assets/expenses, a credit balance for
        liabilities/equity/revenue; negative means the account has gone
        contra.
        """
        with self._lock:
            if account not in self._accounts:
                raise UnknownAccountError(f"unknown account: {account}")
            debit = 0
            d = sum(l.debit for e in self._journal for l in e.lines
                    if l.account == account)
            c = sum(l.credit for e in self._journal for l in e.lines
                    if l.account == account)
            side = _NORMAL_SIDE[self._accounts[account].account_type]
            net = d - c if side == "debit" else c - d
            return {"account": account, "debit": d, "credit": c,
                    "normal_side": side, "net": net}

    def trial_balance(self) -> List[TrialBalanceRow]:
        """Recompute per-account totals; raise if totals do not balance."""
        with self._lock:
            accounts = list(self._accounts)
        rows = []
        total_debits = 0
        total_credits = 0
        for name in accounts:
            b = self.balance(name)
            side = b["normal_side"]
            net_mag = abs(b["net"])
            rows.append(TrialBalanceRow(
                account=name, account_type=self._accounts[name].account_type,
                debit_total=b["debit"], credit_total=b["credit"],
                normal_balance=net_mag))
            total_debits += b["debit"]
            total_credits += b["credit"]
        if total_debits != total_credits:
            raise TrialBalanceMismatchError(
                f"trial balance mismatch: debits {total_debits} "
                f"!= credits {total_credits}")
        return rows

    def accounting_equation(self) -> Dict[str, int]:
        """Check assets == liabilities + equity + (revenue - expenses)."""
        with self._lock:
            totals: Dict[str, int] = {t: 0 for t in ACCOUNT_TYPES}
            for name, acct in self._accounts.items():
                b = self.balance(name)
                totals[acct.account_type] += b["net"]
        left = totals["asset"]
        right = (totals["liability"] + totals["equity"]
                 + totals["revenue"] - totals["expense"])
        return {"assets": left,
                "liabilities_plus_equity_plus_net_income": right,
                "balanced": left == right}


def ledger_audit_event(kind: str, ledger: Ledger,
                       entry: Optional[JournalEntry] = None,
                       **fields: Any) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped event for a ledger action."""
    event: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "ledger": ledger.name,
        "kind": kind,
        "version": VERSION,
    }
    if entry is not None:
        event["entry_id"] = entry.entry_id
        event["digest"] = entry.digest
    event.update(fields)
    return event


def main() -> int:
    ledger = Ledger("books", "USD", [
        {"name": "cash", "type": "asset"},
        {"name": "revenue", "type": "revenue"},
        {"name": "expenses", "type": "expense"},
    ])
    e = ledger.post([JournalLine("cash", debit=5000),
                     JournalLine("revenue", credit=5000)],
                    memo="sale", seq=1)
    assert e.entry_id == "tx-1"
    assert e.total_debits == e.total_credits == 5000
    rows = ledger.trial_balance()
    assert sum(r.debit_total for r in rows) == sum(r.credit_total for r in rows)
    eq = ledger.accounting_equation()
    assert eq["balanced"], eq
    assert ledger.balance("cash")["net"] == 5000
    print("ledger self-check OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
