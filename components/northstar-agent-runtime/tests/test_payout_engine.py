"""Tests for payout_engine: marketplace split/schedule/execute bookkeeping."""

import unittest

from payout_engine import (
    SCHEMA,
    VERSION,
    BelowThresholdError,
    IdempotencyMismatchError,
    InsufficientFundsError,
    InvalidScheduleError,
    InvalidSplitError,
    PayoutEngine,
    PayoutError,
    TerminalPayoutError,
    UnknownPayoutError,
    UnknownRuleError,
    UnknownScheduleError,
    payout_engine_audit_event,
)


def _eng():
    return PayoutEngine("platform-test")


def _rule(e, seq=1, fee_bearer="proportional"):
    return e.create_split_rule("rev-share",
                               {"seller-a": 7000, "seller-b": 3000},
                               fee_bearer, seq=seq)


class VersionPinTests(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(VERSION, "payout-engine.v1")
        self.assertEqual(SCHEMA, "northstar.payout-engine.v1")


class SplitRuleTests(unittest.TestCase):
    def test_split_rule_happy_path(self):
        e = _eng()
        r = _rule(e)
        self.assertEqual(r.rule_id, "sr-1")
        self.assertEqual(r.fee_bearer, "proportional")
        self.assertEqual(sum(a.share_bp for a in r.allocations), 10000)
        self.assertTrue(r.digest.startswith("sha256:"))
        self.assertEqual(r.version, VERSION)

    def test_split_rule_rejects_shares_not_10000(self):
        e = _eng()
        with self.assertRaises(InvalidSplitError):
            e.create_split_rule("bad", {"a": 6000, "b": 3000},
                                "proportional", seq=1)
        with self.assertRaises(InvalidSplitError):
            e.create_split_rule("bad2", {"a": 10001}, "platform", seq=2)

    def test_split_percentage_reconciles_exactly(self):
        e = _eng()
        _rule(e)
        sp = e.split("sr-1", 10000, 500, "usd", seq=2, reference="ord-1")
        self.assertEqual(sp.split_id, "sp-1")
        self.assertEqual(sp.currency, "USD")
        by_party = {ln.party_id: ln for ln in sp.lines}
        self.assertEqual(by_party["seller-a"].gross_share, 7000)
        self.assertEqual(by_party["seller-b"].gross_share, 3000)
        self.assertEqual(sum(ln.gross_share for ln in sp.lines), 10000)
        self.assertEqual(sum(ln.fee_share for ln in sp.lines), 500)
        self.assertEqual(sum(ln.net for ln in sp.lines), 9500)
        for ln in sp.lines:
            self.assertEqual(ln.net, ln.gross_share - ln.fee_share)

    def test_split_rounding_largest_remainder_sums_to_penny(self):
        e = _eng()
        e.create_split_rule("thirds",
                            {"a": 3333, "b": 3333, "c": 3334},
                            "platform", seq=1)
        sp = e.split("sr-1", 100, 0, "usd", seq=2)
        self.assertEqual(sum(ln.gross_share for ln in sp.lines), 100)
        self.assertEqual(sum(ln.net for ln in sp.lines), 100)
        # 34 cents must land on exactly one party (largest remainder, c first)
        shares = sorted(ln.gross_share for ln in sp.lines)
        self.assertEqual(shares, [33, 33, 34])

    def test_split_fee_platform_bearer_keeps_parties_whole(self):
        e = _eng()
        _rule(e, fee_bearer="platform")
        sp = e.split("sr-1", 10000, 400, "usd", seq=2)
        self.assertTrue(all(ln.fee_share == 0 for ln in sp.lines))
        self.assertEqual(sum(ln.net for ln in sp.lines), 10000)

    def test_split_unknown_rule_fails(self):
        e = _eng()
        with self.assertRaises(UnknownRuleError):
            e.split("sr-999", 100, 0, "usd", seq=1)


class ScheduleTests(unittest.TestCase):
    def _funded(self):
        e = _eng()
        _rule(e)
        sp = e.split("sr-1", 10000, 500, "usd", seq=2)
        net_a = next(ln.net for ln in sp.lines if ln.party_id == "seller-a")
        e.credit("seller-a", net_a, "USD", seq=3, memo="ord-1")
        sched = e.create_schedule("seller-a", "usd", "daily", 100, 2,
                                  "bank_transfer", seq=4)
        return e, sched, net_a

    def test_schedule_happy_path_locks_available(self):
        e, sched, net_a = self._funded()
        po = e.schedule(sched.schedule_id, seq=5)
        self.assertEqual(po.payout_id, "po-1")
        self.assertEqual(po.status, "scheduled")
        self.assertEqual(po.amount, net_a)
        self.assertEqual(po.method, "bank_transfer")
        # locked: available drops to zero, balance unchanged
        self.assertEqual(e.available_balance("seller-a", "USD"), 0)
        self.assertEqual(e.balance("seller-a", "USD"), net_a)

    def test_schedule_rejects_bad_frequency(self):
        e = _eng()
        with self.assertRaises(InvalidScheduleError):
            e.create_schedule("s", "usd", "hourly", 0, 0, "wallet", seq=1)

    def test_schedule_below_threshold_raises(self):
        e = _eng()
        sched = e.create_schedule("seller-x", "usd", "weekly", 5000, 0,
                                   "wallet", seq=1)
        e.credit("seller-x", 100, "USD", seq=2)
        with self.assertRaises(BelowThresholdError):
            e.schedule(sched.schedule_id, seq=3)


class ExecuteTests(unittest.TestCase):
    def _scheduled(self):
        e = _eng()
        _rule(e)
        sp = e.split("sr-1", 10000, 500, "usd", seq=2)
        net_a = next(ln.net for ln in sp.lines if ln.party_id == "seller-a")
        e.credit("seller-a", net_a, "USD", seq=3)
        sched = e.create_schedule("seller-a", "usd", "manual", 0, 0,
                                  "wallet", seq=4)
        po = e.schedule(sched.schedule_id, seq=5)
        return e, po, net_a

    def test_execute_happy_path_drains_balance(self):
        e, po, net_a = self._scheduled()
        done = e.execute(po.payout_id, seq=6)
        self.assertEqual(done.status, "executed")
        self.assertEqual(done.amount, net_a)
        self.assertTrue(done.digest.startswith("sha256:"))
        self.assertEqual(e.balance("seller-a", "USD"), 0)

    def test_execute_twice_fails_terminal(self):
        e, po, _net = self._scheduled()
        e.execute(po.payout_id, seq=6)
        with self.assertRaises(TerminalPayoutError):
            e.execute(po.payout_id, seq=7)

    def test_execute_unknown_payout_fails(self):
        e = _eng()
        with self.assertRaises(UnknownPayoutError):
            e.execute("po-999", seq=1)

    def test_amounts_refuse_floats(self):
        e = _eng()
        with self.assertRaises(PayoutError):
            e.credit("seller-a", 10.5, "USD", seq=1)

    def test_audit_event_shape(self):
        ev = payout_engine_audit_event("executed", 9, record_id="po-1")
        self.assertEqual(ev["schema"], SCHEMA)
        self.assertEqual(ev["kind"], "executed")
        self.assertNotIn("amount", ev)
        with self.assertRaises(PayoutError):
            payout_engine_audit_event("bogus", 1)


if __name__ == "__main__":
    unittest.main()
