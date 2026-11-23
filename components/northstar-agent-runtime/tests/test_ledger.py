"""Tests for ledger: double-entry debit/credit bookkeeping."""

import threading
import unittest

from ledger import (
    SCHEMA,
    VERSION,
    Account,
    CurrencyMismatchError,
    DuplicateSeqError,
    InvalidAmountError,
    JournalEntry,
    JournalLine,
    Ledger,
    LedgerError,
    TrialBalanceMismatchError,
    UnbalancedEntryError,
    UnknownAccountError,
    ledger_audit_event,
)


def _ledger():
    return Ledger("books-test", "usd", [
        {"name": "cash", "type": "asset"},
        {"name": "receivable", "type": "asset"},
        {"name": "payable", "type": "liability"},
        {"name": "capital", "type": "equity"},
        {"name": "revenue", "type": "revenue"},
        {"name": "rent", "type": "expense"},
    ])


class VersionPinTests(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(VERSION, "ledger.v1")
        self.assertEqual(SCHEMA, "northstar.ledger.v1")


class PostTests(unittest.TestCase):
    def test_balanced_post_happy_path(self):
        l = _ledger()
        e = l.post([JournalLine("cash", debit=5000),
                    JournalLine("revenue", credit=5000)],
                   memo="sale", seq=1)
        self.assertIsInstance(e, JournalEntry)
        self.assertEqual(e.entry_id, "tx-1")
        self.assertEqual(e.total_debits, 5000)
        self.assertEqual(e.total_credits, 5000)
        self.assertTrue(e.digest.startswith("sha256:"))
        self.assertEqual(e.version, VERSION)
        self.assertEqual(e.schema, SCHEMA)

    def test_entry_ids_monotonic(self):
        l = _ledger()
        a = l.post([JournalLine("cash", debit=100), JournalLine("revenue", credit=100)],
                   memo="a", seq=1)
        b = l.post([JournalLine("cash", debit=200), JournalLine("revenue", credit=200)],
                   memo="b", seq=2)
        self.assertNotEqual(a.entry_id, b.entry_id)
        self.assertNotEqual(a.digest, b.digest)

    def test_multi_line_post(self):
        l = _ledger()
        e = l.post([JournalLine("rent", debit=2000),
                    JournalLine("cash", credit=1500),
                    JournalLine("payable", credit=500)],
                   memo="rent split", seq=1)
        self.assertEqual(e.total_debits, e.total_credits)

    def test_unbalanced_post_rejected(self):
        l = _ledger()
        with self.assertRaises(UnbalancedEntryError):
            l.post([JournalLine("cash", debit=5000),
                    JournalLine("revenue", credit=4999)],
                   memo="off by one", seq=1)
        self.assertEqual(len(l.entries()), 0)

    def test_unknown_account_rejected(self):
        l = _ledger()
        with self.assertRaises(UnknownAccountError):
            l.post([JournalLine("cash", debit=100),
                    JournalLine("moon", credit=100)],
                   memo="bad account", seq=1)

    def test_seq_must_be_strictly_increasing(self):
        l = _ledger()
        l.post([JournalLine("cash", debit=100), JournalLine("revenue", credit=100)],
               memo="a", seq=5)
        with self.assertRaises(DuplicateSeqError):
            l.post([JournalLine("cash", debit=100), JournalLine("revenue", credit=100)],
                   memo="b", seq=5)

    def test_currency_mismatch_rejected(self):
        l = _ledger()
        with self.assertRaises(CurrencyMismatchError):
            l.post([JournalLine("cash", debit=100), JournalLine("revenue", credit=100)],
                   memo="eur", currency="EUR", seq=1)

    def test_invalid_amounts_rejected(self):
        with self.assertRaises(InvalidAmountError):
            JournalLine("cash", debit=True)
        with self.assertRaises(InvalidAmountError):
            JournalLine("cash", debit=1.5)
        l = _ledger()
        with self.assertRaises(LedgerError):
            l.post([], memo="empty", seq=1)


class BalanceTests(unittest.TestCase):
    def test_balance_normal_side_net(self):
        l = _ledger()
        l.post([JournalLine("cash", debit=5000), JournalLine("revenue", credit=5000)],
               memo="sale", seq=1)
        self.assertEqual(l.balance("cash")["net"], 5000)
        self.assertEqual(l.balance("revenue")["net"], 5000)
        self.assertEqual(l.balance("cash")["normal_side"], "debit")
        self.assertEqual(l.balance("revenue")["normal_side"], "credit")

    def test_balance_contra_shows_negative_net(self):
        l = _ledger()
        l.post([JournalLine("cash", debit=1000), JournalLine("revenue", credit=1000)],
               memo="sale", seq=1)
        l.post([JournalLine("revenue", debit=400), JournalLine("cash", credit=400)],
               memo="refund", seq=2)
        self.assertEqual(l.balance("cash")["net"], 600)
        self.assertEqual(l.balance("revenue")["net"], 600)

    def test_balance_unknown_account(self):
        with self.assertRaises(UnknownAccountError):
            _ledger().balance("nope")

    def test_trial_balance_totals_agree(self):
        l = _ledger()
        l.post([JournalLine("cash", debit=9000), JournalLine("capital", credit=9000)],
               memo="seed", seq=1)
        l.post([JournalLine("rent", debit=2000), JournalLine("cash", credit=2000)],
               memo="rent", seq=2)
        rows = l.trial_balance()
        self.assertEqual(len(rows), 6)
        self.assertEqual(sum(r.debit_total for r in rows),
                         sum(r.credit_total for r in rows))
        by_name = {r.account: r for r in rows}
        self.assertEqual(by_name["cash"].debit_total, 9000)
        self.assertEqual(by_name["cash"].credit_total, 2000)

    def test_accounting_equation_holds(self):
        l = _ledger()
        l.post([JournalLine("cash", debit=10000), JournalLine("capital", credit=10000)],
               memo="seed", seq=1)
        l.post([JournalLine("cash", debit=3000), JournalLine("revenue", credit=3000)],
               memo="sale", seq=2)
        l.post([JournalLine("rent", debit=800), JournalLine("cash", credit=800)],
               memo="rent", seq=3)
        eq = l.accounting_equation()
        self.assertTrue(eq["balanced"], eq)
        self.assertEqual(eq["assets"], 12200)


class SafetyTests(unittest.TestCase):
    def test_journal_immutable_from_outside(self):
        l = _ledger()
        l.post([JournalLine("cash", debit=100), JournalLine("revenue", credit=100)],
               memo="a", seq=1)
        entries = l.entries()
        entries.clear()
        self.assertEqual(len(l.entries()), 1)

    def test_thread_safe_posts(self):
        l = _ledger()
        errors = []

        def worker(n):
            try:
                l.post([JournalLine("cash", debit=100),
                        JournalLine("revenue", credit=100)],
                       memo=f"w{n}", seq=100 + n)
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(l.entries()), 8)
        l.trial_balance()  # still balances

    def test_audit_event_shape(self):
        l = _ledger()
        e = l.post([JournalLine("cash", debit=100), JournalLine("revenue", credit=100)],
                   memo="a", seq=1)
        ev = ledger_audit_event("posted", l, e, seq=1)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["ledger"], "books-test")
        self.assertEqual(ev["entry_id"], "tx-1")
        self.assertEqual(ev["digest"], e.digest)


if __name__ == "__main__":
    unittest.main()
