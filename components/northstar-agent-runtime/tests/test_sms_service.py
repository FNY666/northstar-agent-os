"""Targeted tests for the sms_service module (15 tests)."""

import unittest

from sms_service import (
    SMS_SERVICE_VERSION,
    SCHEMA_PIN,
    BodyTooLongError,
    EmptyBodyError,
    IdempotencyMismatchError,
    InvalidPhoneError,
    MessageRecord,
    OptedOutError,
    OptOutRecord,
    SMSError,
    SMSService,
    StatusReport,
    TerminalMessageError,
    UnknownMessageError,
    sms_service_audit_event,
)

_FROM = "+15550001111"
_TO = "+15550002222"


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(SMS_SERVICE_VERSION, "sms-service.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.sms-service.v1")


class TestSend(unittest.TestCase):
    def test_send_happy_path(self):
        svc = SMSService(_FROM)
        rec = svc.send(_TO, "hello", 1)
        self.assertIsInstance(rec, MessageRecord)
        self.assertEqual(rec.message_id, "sm-1")
        self.assertEqual(rec.to_number, _TO)
        self.assertEqual(rec.from_number, _FROM)
        self.assertEqual(rec.status, "queued")
        self.assertEqual(rec.segments, 1)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertNotIn("hello", rec.as_dict().values())

    def test_send_bad_to_number(self):
        svc = SMSService(_FROM)
        for bad in ("5550002222", "+0", "+1", "+", "+155500022222222222", 12345):
            with self.assertRaises((InvalidPhoneError, TypeError)):
                svc.send(bad, "hi", 1)

    def test_send_empty_body(self):
        svc = SMSService(_FROM)
        for bad in ("", "   "):
            with self.assertRaises(EmptyBodyError):
                svc.send(_TO, bad, 1)

    def test_send_body_too_long(self):
        svc = SMSService(_FROM)
        with self.assertRaises(BodyTooLongError):
            svc.send(_TO, "x" * 1601, 1)
        ok = svc.send(_TO, "x" * 1600, 2)
        self.assertEqual(ok.segments, 10)

    def test_send_segments(self):
        svc = SMSService(_FROM)
        self.assertEqual(svc.send(_TO, "x" * 160, 1).segments, 1)
        self.assertEqual(svc.send(_TO, "x" * 161, 2).segments, 2)

    def test_send_idempotency(self):
        svc = SMSService(_FROM)
        a = svc.send(_TO, "hi", 1, idempotency_key="k1")
        b = svc.send(_TO, "hi", 2, idempotency_key="k1")
        self.assertEqual(a.message_id, b.message_id)
        self.assertEqual(len(svc.message_ids()), 1)
        with self.assertRaises(IdempotencyMismatchError):
            svc.send(_TO, "different", 3, idempotency_key="k1")

    def test_send_seq_monotonic(self):
        svc = SMSService(_FROM)
        svc.send(_TO, "a", 1)
        with self.assertRaises(SMSError):
            svc.send(_TO, "b", 1)  # rewind refused


class TestStatus(unittest.TestCase):
    def test_lifecycle(self):
        svc = SMSService(_FROM)
        rec = svc.send(_TO, "hi", 1)
        self.assertEqual(svc.status(rec.message_id).status, "queued")
        rep = svc.report(rec.message_id, "sent", 2)
        self.assertIsInstance(rep, StatusReport)
        self.assertEqual(svc.status(rec.message_id).status, "sent")
        svc.report(rec.message_id, "delivered", 3)
        self.assertEqual(svc.status(rec.message_id).status, "delivered")

    def test_terminal_refuses_report(self):
        svc = SMSService(_FROM)
        rec = svc.send(_TO, "hi", 1)
        svc.report(rec.message_id, "failed", 2)
        with self.assertRaises(TerminalMessageError):
            svc.report(rec.message_id, "sent", 3)

    def test_unknown_message(self):
        svc = SMSService(_FROM)
        with self.assertRaises(UnknownMessageError):
            svc.status("sm-999")
        with self.assertRaises(UnknownMessageError):
            svc.report("sm-999", "sent", 1)

    def test_bad_outcome(self):
        svc = SMSService(_FROM)
        rec = svc.send(_TO, "hi", 1)
        with self.assertRaises(ValueError):
            svc.report(rec.message_id, "exploded", 2)


class TestOptOut(unittest.TestCase):
    def test_optout_blocks_send(self):
        svc = SMSService(_FROM)
        oo = svc.optout(_TO, 1)
        self.assertIsInstance(oo, OptOutRecord)
        self.assertTrue(svc.is_opted_out(_TO))
        self.assertFalse(svc.is_opted_out("+15550009999"))
        with self.assertRaises(OptedOutError):
            svc.send(_TO, "nope", 2)

    def test_optout_suppresses_inflight(self):
        svc = SMSService(_FROM)
        rec = svc.send(_TO, "hi", 1)
        svc.optout(_TO, 2)
        self.assertEqual(svc.status(rec.message_id).status, "suppressed")
        with self.assertRaises(TerminalMessageError):
            svc.report(rec.message_id, "sent", 3)

    def test_audit_never_carries_body(self):
        svc = SMSService(_FROM)
        rec = svc.send(_TO, "secret-code 1234", 1)
        ev = sms_service_audit_event("sent", 2, message=rec)
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        for key in ev:
            self.assertNotIn("secret-code", str(ev[key]))
        self.assertNotIn("body", [k for k in ev if k != "body_digest"])


if __name__ == "__main__":
    unittest.main()
