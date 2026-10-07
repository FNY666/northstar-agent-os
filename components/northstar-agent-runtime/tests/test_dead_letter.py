"""Tests for the dead_letter module."""

from __future__ import annotations

import unittest

from dead_letter import (
    AUDIT_SCHEMA,
    DEAD_LETTER_SCHEMA,
    DEAD_LETTER_VERSION,
    PERMANENT,
    TRANSIENT,
    DeadLetter,
    DeadLetterError,
    DiscardRecord,
    DuplicateMessageError,
    InspectionReport,
    PrematureDiscardError,
    QuarantinedMessage,
    RetryExhaustedError,
    RetryTicket,
    UnknownMessageError,
    UnreviewedDiscardError,
    classify_failure,
    dead_letter_audit_event,
)


def _dlq() -> DeadLetter:
    return DeadLetter(max_retries=2)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(DEAD_LETTER_VERSION, "dead-letter.v1")

    def test_schema_pin(self):
        self.assertEqual(DEAD_LETTER_SCHEMA, "northstar.dead-letter.v1")

    def test_audit_schema(self):
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")


class TestClassify(unittest.TestCase):
    def test_transient_markers(self):
        self.assertEqual(classify_failure("connection timeout"), TRANSIENT)
        self.assertEqual(classify_failure("service unavailable"), TRANSIENT)
        self.assertEqual(classify_failure("throttled by upstream"), TRANSIENT)
        self.assertEqual(classify_failure("deadlock detected"), TRANSIENT)

    def test_permanent_markers(self):
        self.assertEqual(classify_failure("schema validation failed"), PERMANENT)
        self.assertEqual(classify_failure("malformed payload"), PERMANENT)
        self.assertEqual(classify_failure("deserialization error"), PERMANENT)
        self.assertEqual(classify_failure("poison message"), PERMANENT)

    def test_unknown_defaults_transient(self):
        self.assertEqual(classify_failure("weird new error"), TRANSIENT)

    def test_bad_reason(self):
        with self.assertRaises(DeadLetterError):
            classify_failure("")
        with self.assertRaises(DeadLetterError):
            classify_failure(123)


class TestQuarantine(unittest.TestCase):
    def test_happy_path(self):
        dlq = _dlq()
        msg = dlq.quarantine("m-1", {"op": "x"}, "timeout", 1, 0)
        self.assertIsInstance(msg, QuarantinedMessage)
        self.assertEqual(msg.message_id, "m-1")
        self.assertEqual(msg.failure_class, TRANSIENT)
        self.assertEqual(msg.attempts, 1)
        self.assertEqual(msg.version, DEAD_LETTER_VERSION)
        self.assertEqual(msg.schema, DEAD_LETTER_SCHEMA)
        self.assertTrue(msg.digest.startswith("sha256:"))
        self.assertTrue(msg.payload_digest.startswith("sha256:"))
        self.assertEqual(dlq.size(), 1)
        self.assertEqual(dlq.quarantined_ids(), ("m-1",))

    def test_duplicate_refused(self):
        dlq = _dlq()
        dlq.quarantine("m-1", {"op": "x"}, "timeout", 1, 0)
        with self.assertRaises(DuplicateMessageError):
            dlq.quarantine("m-1", {"op": "y"}, "timeout", 1, 1)

    def test_bad_message_id(self):
        dlq = _dlq()
        for bad in ("", None, 123, b"m"):
            with self.assertRaises(DeadLetterError):
                dlq.quarantine(bad, {"op": "x"}, "timeout", 0, 0)

    def test_bad_payload(self):
        dlq = _dlq()
        with self.assertRaises(DeadLetterError):
            dlq.quarantine("m-1", object(), "timeout", 0, 0)
        with self.assertRaises(DeadLetterError):
            dlq.quarantine("m-1", {"k": float("nan")}, "timeout", 0, 0)

    def test_bad_failure_reason(self):
        dlq = _dlq()
        with self.assertRaises(DeadLetterError):
            dlq.quarantine("m-1", {"op": "x"}, "", 0, 0)

    def test_bad_attempts(self):
        dlq = _dlq()
        for bad in (True, -1, 1.5, "2"):
            with self.assertRaises(DeadLetterError):
                dlq.quarantine("m-1", {"op": "x"}, "timeout", bad, 0)

    def test_seq_must_increase(self):
        dlq = _dlq()
        dlq.quarantine("m-1", {"op": "x"}, "timeout", 0, 5)
        with self.assertRaises(DeadLetterError):
            dlq.quarantine("m-2", {"op": "y"}, "timeout", 0, 5)
        dlq.quarantine("m-2", {"op": "y"}, "timeout", 0, 6)  # fine

    def test_bad_seq(self):
        dlq = _dlq()
        for bad in (True, -1, "0"):
            with self.assertRaises(DeadLetterError):
                dlq.quarantine("m-1", {"op": "x"}, "timeout", 0, bad)

    def test_max_retries_validation(self):
        with self.assertRaises(DeadLetterError):
            DeadLetter(max_retries=0)
        with self.assertRaises(DeadLetterError):
            DeadLetter(max_retries=True)

    def test_as_dict_roundtrip(self):
        dlq = _dlq()
        msg = dlq.quarantine("m-1", {"op": "x"}, "timeout", 0, 0)
        d = msg.as_dict()
        self.assertEqual(d["message_id"], "m-1")
        self.assertEqual(d["digest"], msg.digest)


class TestRetry(unittest.TestCase):
    def test_retry_happy_path(self):
        dlq = _dlq()
        dlq.quarantine("m-1", {"op": "x"}, "timeout", 2, 0)
        ticket = dlq.retry("m-1", 1)
        self.assertIsInstance(ticket, RetryTicket)
        self.assertEqual(ticket.attempt_number, 3)
        self.assertEqual(ticket.remaining_attempts, 1)
        self.assertTrue(ticket.digest.startswith("sha256:"))

    def test_retry_exhaustion(self):
        dlq = _dlq()
        dlq.quarantine("m-1", {"op": "x"}, "timeout", 0, 0)
        dlq.retry("m-1", 1)
        dlq.retry("m-1", 2)
        with self.assertRaises(RetryExhaustedError):
            dlq.retry("m-1", 3)
        self.assertEqual(dlq.poisoned_ids(), ("m-1",))

    def test_retry_unknown(self):
        dlq = _dlq()
        with self.assertRaises(UnknownMessageError):
            dlq.retry("nope", 0)

    def test_permanent_is_poison_immediately(self):
        dlq = _dlq()
        dlq.quarantine("m-1", {"op": "x"}, "schema violation", 0, 0)
        self.assertEqual(dlq.poisoned_ids(), ("m-1",))

    def test_inspect_reflects_retries(self):
        dlq = _dlq()
        dlq.quarantine("m-1", {"op": "x"}, "timeout", 0, 0)
        dlq.retry("m-1", 1)
        report = dlq.inspect("m-1")
        self.assertIsInstance(report, InspectionReport)
        self.assertEqual(report.retry_events, 1)
        self.assertEqual(report.attempts, 1)
        self.assertTrue(report.was_reviewed)
        self.assertFalse(report.is_poison)


class TestInspect(unittest.TestCase):
    def test_inspect_unknown(self):
        dlq = _dlq()
        with self.assertRaises(UnknownMessageError):
            dlq.inspect("nope")

    def test_inspect_bad_id(self):
        dlq = _dlq()
        with self.assertRaises(DeadLetterError):
            dlq.inspect("")


class TestDiscard(unittest.TestCase):
    def test_discard_happy_path(self):
        dlq = _dlq()
        dlq.quarantine("m-1", {"op": "x"}, "timeout", 0, 0)
        dlq.retry("m-1", 1)
        dlq.retry("m-1", 2)
        dlq.inspect("m-1")
        rec = dlq.discard("m-1", 3)
        self.assertIsInstance(rec, DiscardRecord)
        self.assertEqual(rec.message_id, "m-1")
        self.assertEqual(dlq.size(), 0)
        self.assertEqual(dlq.poisoned_ids(), ())

    def test_premature_discard_refused(self):
        dlq = _dlq()
        dlq.quarantine("m-1", {"op": "x"}, "timeout", 0, 0)
        dlq.inspect("m-1")
        with self.assertRaises(PrematureDiscardError):
            dlq.discard("m-1", 1)

    def test_unreviewed_discard_refused(self):
        dlq = _dlq()
        dlq.quarantine("m-1", {"op": "x"}, "schema violation", 0, 0)
        with self.assertRaises(UnreviewedDiscardError):
            dlq.discard("m-1", 1)

    def test_discard_unknown(self):
        dlq = _dlq()
        with self.assertRaises(UnknownMessageError):
            dlq.discard("nope", 0)

    def test_inspect_after_discard_unknown(self):
        dlq = _dlq()
        dlq.quarantine("m-1", {"op": "x"}, "timeout", 0, 0)
        dlq.retry("m-1", 1)
        dlq.retry("m-1", 2)
        dlq.inspect("m-1")
        dlq.discard("m-1", 3)
        with self.assertRaises(UnknownMessageError):
            dlq.inspect("m-1")

    def test_quarantine_again_after_discard(self):
        dlq = _dlq()
        dlq.quarantine("m-1", {"op": "x"}, "timeout", 0, 0)
        dlq.retry("m-1", 1)
        dlq.retry("m-1", 2)
        dlq.inspect("m-1")
        dlq.discard("m-1", 3)
        msg = dlq.quarantine("m-1", {"op": "z"}, "timeout", 0, 4)
        self.assertEqual(msg.message_id, "m-1")
        self.assertEqual(dlq.size(), 1)

    def test_discard_record_shape(self):
        dlq = _dlq()
        dlq.quarantine("m-1", {"op": "x"}, "timeout", 1, 0)
        dlq.retry("m-1", 1)
        dlq.retry("m-1", 2)
        dlq.inspect("m-1")
        rec = dlq.discard("m-1", 3)
        d = rec.as_dict()
        self.assertEqual(d["attempts"], 3)  # 1 initial + 2 retries
        self.assertEqual(d["version"], DEAD_LETTER_VERSION)


class TestAudit(unittest.TestCase):
    def test_event_shape(self):
        ev = dead_letter_audit_event("quarantined", 7, "m-1")
        self.assertEqual(ev["schema"], AUDIT_SCHEMA)
        self.assertEqual(ev["kind"], "dead-letter.quarantined")
        self.assertEqual(ev["seq"], 7)
        self.assertEqual(ev["message_id"], "m-1")

    def test_all_kinds(self):
        for kind in ("quarantined", "retried", "retry-exhausted",
                     "inspected", "discarded"):
            ev = dead_letter_audit_event(kind, 0)
            self.assertEqual(ev["kind"], f"dead-letter.{kind}")

    def test_detail(self):
        ev = dead_letter_audit_event("retried", 1, "m-1",
                                     {"attempt": 3})
        self.assertEqual(ev["detail"], {"attempt": 3})

    def test_bad_kind(self):
        with self.assertRaises(DeadLetterError):
            dead_letter_audit_event("nope", 0)

    def test_bad_seq(self):
        with self.assertRaises(DeadLetterError):
            dead_letter_audit_event("quarantined", -1)

    def test_bad_detail(self):
        with self.assertRaises(DeadLetterError):
            dead_letter_audit_event("quarantined", 0, detail="x")

    def test_no_raw_payload_in_event(self):
        ev = dead_letter_audit_event("quarantined", 0, "m-1")
        self.assertNotIn("payload", ev)


class TestMain(unittest.TestCase):
    def test_main(self):
        from dead_letter import main
        main()


if __name__ == "__main__":
    unittest.main()
