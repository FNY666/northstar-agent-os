"""Tests for signed_receipt_reflux: the approval-loop closer."""

from __future__ import annotations

import unittest

import ed25519
import signed_receipt_reflux as srr
from signed_receipt_reflux import (
    ReceiptError,
    RefluxChannel,
    SignedReceipt,
    authorize_action,
    issue_receipt,
    receipt_digest,
    verify_receipt,
)


def _keys(seed_byte: int = 0):
    secret = bytes([(seed_byte + i) % 256 for i in range(32)])
    return secret, ed25519.public_key(secret)


SECRET, PUBKEY = _keys(0)
SECRET2, PUBKEY2 = _keys(100)


def _receipt(**kw):
    args = {
        "request_id": "req-1",
        "action": "tool:delete:/tmp/x",
        "approver": "human:alice",
        "approved_at_seq": 42,
        "approver_secret": SECRET,
    }
    args.update(kw)
    return issue_receipt(**args)


class IssueTests(unittest.TestCase):
    def test_round_trip_verifies(self):
        r = _receipt()
        self.assertTrue(verify_receipt(r, PUBKEY))

    def test_signature_is_64_bytes(self):
        r = _receipt()
        self.assertEqual(len(r.signature), 64)

    def test_receipt_is_frozen(self):
        r = _receipt()
        with self.assertRaises(Exception):
            r.action = "other"  # type: ignore

    def test_empty_request_id_rejected(self):
        with self.assertRaises(ReceiptError):
            _receipt(request_id="")

    def test_empty_action_rejected(self):
        with self.assertRaises(ReceiptError):
            _receipt(action="")

    def test_empty_approver_rejected(self):
        with self.assertRaises(ReceiptError):
            _receipt(approver="")

    def test_negative_seq_rejected(self):
        with self.assertRaises(ReceiptError):
            _receipt(approved_at_seq=-1)

    def test_bool_seq_rejected(self):
        with self.assertRaises(ReceiptError):
            _receipt(approved_at_seq=True)

    def test_short_secret_rejected(self):
        with self.assertRaises(ReceiptError):
            _receipt(approver_secret=b"short")

    def test_as_dict_round_shape(self):
        d = _receipt().as_dict()
        self.assertEqual(d["request_id"], "req-1")
        self.assertEqual(d["schema"], srr.SCHEMA_PIN)
        self.assertEqual(d["version"], srr.SIGNED_RECEIPT_VERSION)
        self.assertEqual(len(d["signature"]), 128)  # 64 bytes hex


class VerifyTests(unittest.TestCase):
    def test_wrong_pubkey_fails(self):
        self.assertFalse(verify_receipt(_receipt(), PUBKEY2))

    def test_tampered_action_fails(self):
        r = _receipt()
        tampered = SignedReceipt(r.request_id, "tool:delete:/tmp/OTHER",
                                 r.approver, r.approved_at_seq, r.signature)
        self.assertFalse(verify_receipt(tampered, PUBKEY))

    def test_tampered_request_id_fails(self):
        r = _receipt()
        tampered = SignedReceipt("req-2", r.action, r.approver,
                                 r.approved_at_seq, r.signature)
        self.assertFalse(verify_receipt(tampered, PUBKEY))

    def test_tampered_seq_fails(self):
        r = _receipt()
        tampered = SignedReceipt(r.request_id, r.action, r.approver,
                                 999, r.signature)
        self.assertFalse(verify_receipt(tampered, PUBKEY))

    def test_tampered_approver_fails(self):
        r = _receipt()
        tampered = SignedReceipt(r.request_id, r.action, "human:bob",
                                 r.approved_at_seq, r.signature)
        self.assertFalse(verify_receipt(tampered, PUBKEY))

    def test_non_receipt_returns_false_not_raise(self):
        self.assertFalse(verify_receipt("not-a-receipt", PUBKEY))
        self.assertFalse(verify_receipt(None, PUBKEY))
        self.assertFalse(verify_receipt(42, PUBKEY))

    def test_bad_pubkey_length_returns_false(self):
        self.assertFalse(verify_receipt(_receipt(), b"short"))

    def test_schema_pin_covered(self):
        # A signature made without the schema pin must not verify.
        r = _receipt()
        body_no_pin = {"request_id": r.request_id, "action": r.action,
                       "approver": r.approver,
                       "approved_at_seq": r.approved_at_seq}
        import json
        raw = json.dumps(body_no_pin, sort_keys=True,
                         separators=(",", ":")).encode()
        forged = SignedReceipt(r.request_id, r.action, r.approver,
                               r.approved_at_seq,
                               ed25519.sign(SECRET, raw))
        self.assertFalse(verify_receipt(forged, PUBKEY))


class ChannelTests(unittest.TestCase):
    def test_deliver_collect_round_trip(self):
        ch = RefluxChannel()
        r = _receipt()
        self.assertTrue(ch.deliver(r))
        self.assertEqual(ch.collect("req-1"), r)

    def test_collect_consumes(self):
        ch = RefluxChannel()
        ch.deliver(_receipt())
        ch.collect("req-1")
        self.assertIsNone(ch.collect("req-1"))

    def test_collect_missing_returns_none(self):
        self.assertIsNone(RefluxChannel().collect("nope"))

    def test_redelivery_refused(self):
        ch = RefluxChannel()
        r = _receipt()
        self.assertTrue(ch.deliver(r))
        self.assertFalse(ch.deliver(r))

    def test_deliver_non_receipt_raises(self):
        with self.assertRaises(ReceiptError):
            RefluxChannel().deliver("nope")  # type: ignore

    def test_peek_does_not_consume(self):
        ch = RefluxChannel()
        r = _receipt()
        ch.deliver(r)
        self.assertEqual(ch.peek("req-1"), r)
        self.assertEqual(ch.collect("req-1"), r)

    def test_pending_lists_ids(self):
        ch = RefluxChannel()
        ch.deliver(_receipt(request_id="req-b"))
        ch.deliver(_receipt(request_id="req-a"))
        self.assertEqual(ch.pending(), ["req-a", "req-b"])
        self.assertEqual(len(ch), 2)


class AuthorizeTests(unittest.TestCase):
    def test_happy_path(self):
        r = _receipt()
        self.assertTrue(authorize_action(r, PUBKEY, "req-1",
                                        "tool:delete:/tmp/x"))

    def test_wrong_action_rejected(self):
        r = _receipt()
        self.assertFalse(authorize_action(r, PUBKEY, "req-1",
                                         "tool:delete:/tmp/y"))

    def test_wrong_request_id_rejected(self):
        r = _receipt()
        self.assertFalse(authorize_action(r, PUBKEY, "req-2",
                                         "tool:delete:/tmp/x"))

    def test_wrong_key_rejected(self):
        r = _receipt()
        self.assertFalse(authorize_action(r, PUBKEY2, "req-1",
                                         "tool:delete:/tmp/x"))

    def test_non_receipt_rejected(self):
        self.assertFalse(authorize_action(None, PUBKEY, "req-1",
                                         "tool:delete:/tmp/x"))

    def test_never_raises(self):
        # Garbage in, False out — gates fail closed.
        self.assertFalse(authorize_action(object(), b"bad", None, None))


class DigestTests(unittest.TestCase):
    def test_digest_stable(self):
        r = _receipt()
        self.assertEqual(receipt_digest(r), receipt_digest(r))
        self.assertTrue(receipt_digest(r).startswith("sha256:"))

    def test_digest_changes_with_action(self):
        r1 = _receipt()
        r2 = _receipt(action="tool:read:/tmp/x")
        self.assertNotEqual(receipt_digest(r1), receipt_digest(r2))


class EndToEndTests(unittest.TestCase):
    def test_full_reflux_loop(self):
        # abstain -> approve -> receipt -> deliver -> collect -> authorize
        ch = RefluxChannel()
        receipt = issue_receipt("req-9", "tool:write:/data/f",
                                "human:alice", 7, SECRET)
        self.assertTrue(ch.deliver(receipt))
        got = ch.collect("req-9")
        self.assertIsNotNone(got)
        self.assertTrue(authorize_action(got, PUBKEY, "req-9",
                                        "tool:write:/data/f"))
        # Receipt is consumed: replaying the loop fails.
        self.assertIsNone(ch.collect("req-9"))

    def test_main_self_check(self):
        srr.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
