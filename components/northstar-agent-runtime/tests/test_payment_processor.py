"""Tests for payment_processor: Stripe-style charge/refund/dispute bookkeeping."""

import threading
import unittest

from payment_processor import (
    SCHEMA,
    VERSION,
    ChargeDisputedError,
    DuplicateChargeError,
    IdempotencyMismatchError,
    PaymentError,
    PaymentProcessor,
    RefundExceedsChargeError,
    TerminalDisputeError,
    UnknownChargeError,
    UnknownRefundError,
    payment_processor_audit_event,
)


def _proc():
    return PaymentProcessor("merch-test")


class VersionPinTests(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(VERSION, "payment-processor.v1")
        self.assertEqual(SCHEMA, "northstar.payment-processor.v1")


class ChargeTests(unittest.TestCase):
    def test_charge_happy_path(self):
        p = _proc()
        ch = p.charge(2500, "usd", "cus-1", "pm-1", seq=1)
        self.assertEqual(ch.charge_id, "ch-1")
        self.assertEqual(ch.amount, 2500)
        self.assertEqual(ch.currency, "USD")
        self.assertEqual(ch.status, "succeeded")
        self.assertTrue(ch.digest.startswith("sha256:"))
        self.assertEqual(ch.version, VERSION)

    def test_charge_ids_monotonic(self):
        p = _proc()
        a = p.charge(100, "eur", "cus-1", "pm-1", seq=1)
        b = p.charge(200, "eur", "cus-1", "pm-1", seq=2)
        self.assertNotEqual(a.charge_id, b.charge_id)

    def test_amount_must_be_positive_int_minor_units(self):
        p = _proc()
        for bad in (0, -5, 2.5, True, "100"):
            with self.assertRaises(PaymentError, msg=f"amount={bad!r}"):
                p.charge(bad, "usd", "cus-1", "pm-1", seq=1)

    def test_floats_refused_in_money_path(self):
        p = _proc()
        with self.assertRaises(PaymentError):
            p.charge(10.99, "usd", "cus-1", "pm-1", seq=1)

    def test_currency_must_be_3_letter_iso(self):
        p = _proc()
        for bad in ("us", "USDD", "12$", 123, ""):
            with self.assertRaises(PaymentError, msg=f"currency={bad!r}"):
                p.charge(100, bad, "cus-1", "pm-1", seq=1)

    def test_empty_ids_rejected(self):
        p = _proc()
        with self.assertRaises(PaymentError):
            p.charge(100, "usd", "", "pm-1", seq=1)
        with self.assertRaises(PaymentError):
            p.charge(100, "usd", "cus-1", "  ", seq=1)

    def test_seq_must_strictly_increase(self):
        p = _proc()
        p.charge(100, "usd", "cus-1", "pm-1", seq=5)
        with self.assertRaises(PaymentError):
            p.charge(100, "usd", "cus-1", "pm-1", seq=5)
        with self.assertRaises(PaymentError):
            p.charge(100, "usd", "cus-1", "pm-1", seq=4)

    def test_charge_lookup_unknown(self):
        p = _proc()
        with self.assertRaises(UnknownChargeError):
            p.charge_record("ch-999")


class IdempotencyTests(unittest.TestCase):
    def test_idempotent_replay_returns_original(self):
        p = _proc()
        a = p.charge(2500, "usd", "cus-1", "pm-1", seq=1, idempotency_key="k-1")
        b = p.charge(2500, "usd", "cus-1", "pm-1", seq=2, idempotency_key="k-1")
        self.assertEqual(a.charge_id, b.charge_id)
        self.assertEqual(a.digest, b.digest)

    def test_idempotency_key_mismatch_fails_closed(self):
        p = _proc()
        p.charge(2500, "usd", "cus-1", "pm-1", seq=1, idempotency_key="k-1")
        with self.assertRaises(IdempotencyMismatchError):
            p.charge(9999, "usd", "cus-1", "pm-1", seq=2, idempotency_key="k-1")

    def test_different_keys_mint_different_charges(self):
        p = _proc()
        a = p.charge(2500, "usd", "cus-1", "pm-1", seq=1, idempotency_key="k-1")
        b = p.charge(2500, "usd", "cus-1", "pm-1", seq=2, idempotency_key="k-2")
        self.assertNotEqual(a.charge_id, b.charge_id)


class RefundTests(unittest.TestCase):
    def test_full_refund_default(self):
        p = _proc()
        p.charge(2500, "usd", "cus-1", "pm-1", seq=1)
        re = p.refund("ch-1", seq=2)
        self.assertEqual(re.amount, 2500)
        self.assertEqual(re.cumulative_refunded, 2500)
        self.assertEqual(p.remaining_refundable("ch-1"), 0)

    def test_partial_refunds_accumulate(self):
        p = _proc()
        p.charge(2500, "usd", "cus-1", "pm-1", seq=1)
        r1 = p.refund("ch-1", seq=2, amount=1000)
        r2 = p.refund("ch-1", seq=3, amount=500)
        self.assertEqual(r1.refund_id, "re-1")
        self.assertEqual(r2.refund_id, "re-2")
        self.assertEqual(p.refunded_total("ch-1"), 1500)
        self.assertEqual(p.remaining_refundable("ch-1"), 1000)

    def test_refund_cannot_exceed_charged(self):
        p = _proc()
        p.charge(2500, "usd", "cus-1", "pm-1", seq=1)
        p.refund("ch-1", seq=2, amount=2000)
        with self.assertRaises(RefundExceedsChargeError):
            p.refund("ch-1", seq=3, amount=501)

    def test_refund_unknown_charge(self):
        p = _proc()
        with self.assertRaises(UnknownChargeError):
            p.refund("ch-999", seq=1)

    def test_refund_record_lookup_unknown(self):
        p = _proc()
        with self.assertRaises(UnknownRefundError):
            p.refund_record("re-999")


class DisputeTests(unittest.TestCase):
    def test_dispute_happy_path(self):
        p = _proc()
        p.charge(2500, "usd", "cus-1", "pm-1", seq=1)
        dp = p.dispute("ch-1", "fraudulent", seq=2)
        self.assertEqual(dp.dispute_id, "dp-1")
        self.assertEqual(dp.status, "open")
        self.assertEqual(dp.amount, 2500)

    def test_bad_dispute_reason_rejected(self):
        p = _proc()
        p.charge(2500, "usd", "cus-1", "pm-1", seq=1)
        with self.assertRaises(PaymentError):
            p.dispute("ch-1", "aliens", seq=2)

    def test_refund_refused_during_open_dispute(self):
        p = _proc()
        p.charge(2500, "usd", "cus-1", "pm-1", seq=1)
        p.dispute("ch-1", "fraudulent", seq=2)
        with self.assertRaises(ChargeDisputedError):
            p.refund("ch-1", seq=3, amount=100)

    def test_double_dispute_rejected(self):
        p = _proc()
        p.charge(2500, "usd", "cus-1", "pm-1", seq=1)
        p.dispute("ch-1", "fraudulent", seq=2)
        with self.assertRaises(TerminalDisputeError):
            p.dispute("ch-1", "duplicate", seq=3)

    def test_resolve_dispute_terminal(self):
        p = _proc()
        p.charge(2500, "usd", "cus-1", "pm-1", seq=1)
        p.dispute("ch-1", "fraudulent", seq=2)
        res = p.resolve_dispute("ch-1", "won", seq=3)
        self.assertEqual(res.status, "won")
        self.assertEqual(res.dispute_id, "dp-1")
        with self.assertRaises(TerminalDisputeError):
            p.resolve_dispute("ch-1", "lost", seq=4)

    def test_resolve_without_open_dispute(self):
        p = _proc()
        p.charge(2500, "usd", "cus-1", "pm-1", seq=1)
        with self.assertRaises(TerminalDisputeError):
            p.resolve_dispute("ch-1", "won", seq=2)

    def test_dispute_unknown_charge(self):
        p = _proc()
        with self.assertRaises(UnknownChargeError):
            p.dispute("ch-999", "fraudulent", seq=1)


class DigestTests(unittest.TestCase):
    def test_charge_digest_deterministic(self):
        p1, p2 = _proc(), _proc()
        a = p1.charge(2500, "usd", "cus-1", "pm-1", seq=1)
        b = p2.charge(2500, "usd", "cus-1", "pm-1", seq=1)
        self.assertEqual(a.digest, b.digest)

    def test_charge_digest_content_binding(self):
        p1, p2 = _proc(), _proc()
        a = p1.charge(2500, "usd", "cus-1", "pm-1", seq=1)
        b = p2.charge(2501, "usd", "cus-1", "pm-1", seq=1)
        self.assertNotEqual(a.digest, b.digest)


class AuditTests(unittest.TestCase):
    def test_audit_shapes(self):
        ev = payment_processor_audit_event("charged", 1, record_id="ch-1")
        self.assertEqual(ev["kind"], "charged")
        self.assertEqual(ev["seq"], 1)
        self.assertEqual(ev["schema"], SCHEMA)
        self.assertNotIn("amount", ev)  # never leak money amounts

    def test_audit_bad_kind_rejected(self):
        with self.assertRaises(PaymentError):
            payment_processor_audit_event("paid", 1)


class ConcurrencyTests(unittest.TestCase):
    def test_concurrent_charges_mint_unique_ids(self):
        p = _proc()
        ids = []
        lock = threading.Lock()

        def work(i):
            ch = p.charge(100 + i, "usd", f"cus-{i}", "pm-1", seq=i + 1)
            with lock:
                ids.append(ch.charge_id)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(set(ids)), 8)


class MainSelfCheck(unittest.TestCase):
    def test_main(self):
        import payment_processor as m
        m.main()


if __name__ == "__main__":
    unittest.main()
