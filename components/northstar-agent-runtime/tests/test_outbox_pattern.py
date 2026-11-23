"""Tests for outbox_pattern.py (15 required)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from outbox_pattern import (  # noqa: E402
    OUTBOX_PATTERN_VERSION,
    SCHEMA_PIN,
    DispatchReport,
    MessageState,
    Outbox,
    OutboxError,
    OutboxEvent,
    OutboxMessage,
    main,
    outbox_audit_event,
)


def _msg(mid="m1", dest="webhook", payload=None, seq=0):
    return OutboxMessage(mid, dest, payload or {"ok": True}, seq=seq)


def _ok_transport(message):
    return True


def _raising_transport(message):
    raise ConnectionError("endpoint down")


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(OUTBOX_PATTERN_VERSION, "outbox-pattern.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.outbox-pattern.v1")


class TestMessageValidation(unittest.TestCase):
    def test_empty_message_id_rejected(self):
        with self.assertRaises(OutboxError):
            OutboxMessage("", "webhook", {"ok": True}, seq=0)

    def test_empty_destination_rejected(self):
        with self.assertRaises(OutboxError):
            OutboxMessage("m1", "", {"ok": True}, seq=0)

    def test_non_mapping_payload_rejected(self):
        with self.assertRaises(OutboxError):
            OutboxMessage("m1", "webhook", ["not", "a", "mapping"], seq=0)

    def test_negative_seq_rejected(self):
        with self.assertRaises(OutboxError):
            OutboxMessage("m1", "webhook", {"ok": True}, seq=-1)

    def test_bool_seq_rejected(self):
        with self.assertRaises(OutboxError):
            OutboxMessage("m1", "webhook", {"ok": True}, seq=True)

    def test_message_frozen(self):
        m = _msg()
        with self.assertRaises(AttributeError):
            m.message_id = "other"  # type: ignore[misc]

    def test_as_dict_shape(self):
        d = _msg("m9", "bus", {"n": 1}, seq=4).as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["message_id"], "m9")
        self.assertEqual(d["destination"], "bus")
        self.assertEqual(d["payload"], {"n": 1})
        self.assertEqual(d["seq"], 4)


class TestPublish(unittest.TestCase):
    def test_publish_stages_pending(self):
        box = Outbox()
        box.publish(_msg(), seq=0)
        self.assertEqual(box.state("m1"), MessageState.PENDING)
        self.assertEqual([m.message_id for m in box.pending()], ["m1"])

    def test_duplicate_message_id_rejected(self):
        box = Outbox()
        box.publish(_msg(), seq=0)
        with self.assertRaises(OutboxError):
            box.publish(_msg(), seq=1)

    def test_publish_non_message_rejected(self):
        box = Outbox()
        with self.assertRaises(OutboxError):
            box.publish("not-a-message", seq=0)  # type: ignore[arg-type]

    def test_publish_event_logged(self):
        box = Outbox()
        box.publish(_msg(), seq=7)
        events = box.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "published")
        self.assertEqual(events[0].message_id, "m1")
        self.assertEqual(events[0].seq, 7)

    def test_bad_max_attempts_rejected(self):
        with self.assertRaises(OutboxError):
            Outbox(max_attempts=0)
        with self.assertRaises(OutboxError):
            Outbox(max_attempts=True)

    def test_unknown_state_keyerror(self):
        box = Outbox()
        with self.assertRaises(KeyError):
            box.state("nope")


class TestPendingOrder(unittest.TestCase):
    def test_pending_in_seq_order(self):
        box = Outbox()
        box.publish(_msg("b", seq=5), seq=0)
        box.publish(_msg("a", seq=2), seq=1)
        box.publish(_msg("c", seq=9), seq=2)
        self.assertEqual([m.message_id for m in box.pending()], ["a", "b", "c"])


class TestDispatch(unittest.TestCase):
    def test_dispatch_happy_path(self):
        box = Outbox()
        box.publish(_msg("m1", seq=0), seq=0)
        box.publish(_msg("m2", seq=1), seq=1)
        report = box.dispatch(_ok_transport, seq=2)
        self.assertEqual(report.sent, ("m1", "m2"))
        self.assertEqual(report.failed, ())
        self.assertEqual(report.still_pending, ())
        self.assertEqual(box.state("m1"), MessageState.SENT)
        self.assertEqual(box.pending(), ())
        self.assertEqual([m.message_id for m in box.sent()], ["m1", "m2"])

    def test_transport_exception_leaves_pending(self):
        box = Outbox(max_attempts=3)
        box.publish(_msg(), seq=0)
        report = box.dispatch(_raising_transport, seq=1)
        self.assertEqual(report.sent, ())
        self.assertEqual(report.still_pending, ("m1",))
        self.assertEqual(box.state("m1"), MessageState.PENDING)
        self.assertEqual(box.attempts("m1"), 1)

    def test_falsy_transport_result_is_failure(self):
        box = Outbox(max_attempts=3)
        box.publish(_msg(), seq=0)
        report = box.dispatch(lambda m: "", seq=1)
        self.assertEqual(report.still_pending, ("m1",))
        self.assertEqual(box.attempts("m1"), 1)

    def test_retry_after_failure_succeeds(self):
        box = Outbox(max_attempts=3)
        box.publish(_msg(), seq=0)
        box.dispatch(_raising_transport, seq=1)
        report = box.dispatch(_ok_transport, seq=2)
        self.assertEqual(report.sent, ("m1",))
        self.assertEqual(box.state("m1"), MessageState.SENT)

    def test_max_attempts_dead_letters(self):
        box = Outbox(max_attempts=2)
        box.publish(_msg(), seq=0)
        box.dispatch(_raising_transport, seq=1)
        report = box.dispatch(_raising_transport, seq=2)
        self.assertEqual(report.failed, ("m1",))
        self.assertEqual(box.state("m1"), MessageState.FAILED)
        self.assertEqual([m.message_id for m in box.failed()], ["m1"])

    def test_failed_message_not_redispatched(self):
        box = Outbox(max_attempts=1)
        box.publish(_msg(), seq=0)
        calls = []

        def counting(m):
            calls.append(m.message_id)
            return False

        box.dispatch(counting, seq=1)
        report = box.dispatch(counting, seq=2)
        self.assertEqual(len(calls), 1)
        self.assertEqual(report.sent, ())
        self.assertEqual(report.failed, ())

    def test_dispatch_empty_outbox(self):
        box = Outbox()
        report = box.dispatch(_ok_transport, seq=0)
        self.assertEqual(report.sent, ())
        self.assertEqual(report.failed, ())
        self.assertEqual(report.still_pending, ())

    def test_non_callable_transport_rejected(self):
        box = Outbox()
        box.publish(_msg(), seq=0)
        with self.assertRaises(OutboxError):
            box.dispatch("not-callable", seq=1)  # type: ignore[arg-type]

    def test_failed_event_carries_reason(self):
        box = Outbox(max_attempts=1)
        box.publish(_msg(), seq=0)
        box.dispatch(_raising_transport, seq=1)
        failed_events = [e for e in box.events() if e.kind == "failed"]
        self.assertEqual(len(failed_events), 1)
        self.assertIn("ConnectionError", failed_events[0].reason)
        self.assertEqual(failed_events[0].attempts, 1)

    def test_dispatch_report_shape(self):
        report = DispatchReport(sent=("a",), failed=(), still_pending=("b",))
        d = report.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["sent"], ["a"])
        self.assertEqual(d["still_pending"], ["b"])


class TestAuditEvents(unittest.TestCase):
    def test_audit_event_message(self):
        record = outbox_audit_event(_msg(), audit_seq=3)
        self.assertEqual(record["audit_seq"], 3)
        self.assertEqual(record["schema"], SCHEMA_PIN)

    def test_audit_event_report(self):
        record = outbox_audit_event(DispatchReport(), audit_seq=0)
        self.assertEqual(record["audit_seq"], 0)

    def test_audit_event_bad_type(self):
        with self.assertRaises(TypeError):
            outbox_audit_event({"not": "a record"}, audit_seq=0)

    def test_audit_event_bad_seq(self):
        with self.assertRaises(ValueError):
            outbox_audit_event(_msg(), audit_seq=-1)
        with self.assertRaises(TypeError):
            outbox_audit_event(_msg(), audit_seq=True)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        main()


if __name__ == "__main__":
    unittest.main()
