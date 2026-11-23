"""Tests for inbox_pattern.py (15 required)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from inbox_pattern import (  # noqa: E402
    INBOX_PATTERN_VERSION,
    SCHEMA_PIN,
    AckReport,
    Inbox,
    InboxError,
    InboxEvent,
    InboxMessage,
    MessageState,
    ProcessReport,
    ReceiveReport,
    inbox_audit_event,
    main,
)


def _msg(mid="m1", source="upstream", payload=None, seq=0):
    return InboxMessage(mid, source, payload or {"n": 1}, seq=seq)


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(INBOX_PATTERN_VERSION, "inbox-pattern.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.inbox-pattern.v1")


class TestReceiveDedupe(unittest.TestCase):
    def test_receive_stored(self):
        box = Inbox()
        report = box.receive(_msg(), seq=0)
        self.assertFalse(report.duplicate)
        self.assertEqual(report.outcome, "stored")
        self.assertEqual(box.state("m1"), MessageState.RECEIVED)

    def test_redelivery_is_duplicate_data_not_error(self):
        box = Inbox()
        box.receive(_msg(), seq=0)
        report = box.receive(_msg(seq=1), seq=1)
        self.assertTrue(report.duplicate)
        self.assertEqual(report.outcome, "redelivered")
        self.assertEqual(box.state("m1"), MessageState.RECEIVED)
        self.assertEqual(box.pending(), (_msg(),))

    def test_redelivery_of_done_reports_duplicate_done(self):
        box = Inbox()
        box.receive(_msg(), seq=0)
        box.ack("m1", seq=1)
        report = box.receive(_msg(seq=2), seq=2)
        self.assertTrue(report.duplicate)
        self.assertEqual(report.outcome, "redelivered-duplicate-done")
        self.assertEqual(box.state("m1"), MessageState.DONE)

    def test_conflicting_payload_refused(self):
        box = Inbox()
        box.receive(_msg(), seq=0)
        with self.assertRaises(InboxError):
            box.receive(_msg(payload={"n": 2}, seq=1), seq=1)

    def test_dedupe_view(self):
        box = Inbox()
        self.assertFalse(box.dedupe("m1"))
        box.receive(_msg(), seq=0)
        self.assertTrue(box.dedupe("m1"))


class TestAck(unittest.TestCase):
    def test_ack_marks_done(self):
        box = Inbox()
        box.receive(_msg(), seq=0)
        report = box.ack("m1", seq=1)
        self.assertFalse(report.already)
        self.assertEqual(report.outcome, "ok")
        self.assertEqual(box.state("m1"), MessageState.DONE)
        self.assertEqual(box.pending(), ())

    def test_ack_is_idempotent(self):
        box = Inbox()
        box.receive(_msg(), seq=0)
        box.ack("m1", seq=1)
        report = box.ack("m1", seq=2)
        self.assertTrue(report.already)
        self.assertEqual(report.outcome, "already-done")
        kinds = [e.kind for e in box.events()]
        self.assertEqual(kinds.count("acked"), 1)

    def test_ack_unknown_raises_keyerror(self):
        box = Inbox()
        with self.assertRaises(KeyError):
            box.ack("nope", seq=0)


class TestProcess(unittest.TestCase):
    def test_process_acks_successful_handler(self):
        box = Inbox()
        box.receive(_msg(), seq=0)
        report = box.process(lambda m: True, seq=1)
        self.assertEqual(report.processed, ("m1",))
        self.assertEqual(report.still_pending, ())
        self.assertEqual(box.state("m1"), MessageState.DONE)

    def test_handler_failure_poison_after_max_attempts(self):
        box = Inbox(max_attempts=2)
        box.receive(_msg(), seq=0)

        def fails(m):
            raise ConnectionError("down")

        report = box.process(fails, seq=1)
        self.assertEqual(report.still_pending, ("m1",))
        self.assertEqual(box.attempts("m1"), 1)
        report2 = box.process(fails, seq=2)
        self.assertEqual(report2.poisoned, ("m1",))
        self.assertEqual(box.state("m1"), MessageState.POISONED)
        self.assertEqual(box.pending(), ())

    def test_reprocess_recovers_poisoned(self):
        box = Inbox(max_attempts=1)
        box.receive(_msg(), seq=0)
        box.process(lambda m: False, seq=1)
        self.assertEqual(box.state("m1"), MessageState.POISONED)
        box.reprocess("m1", seq=2)
        self.assertEqual(box.state("m1"), MessageState.RECEIVED)
        self.assertEqual(box.attempts("m1"), 0)
        report = box.ack("m1", seq=3)
        self.assertFalse(report.already)
        self.assertEqual(box.state("m1"), MessageState.DONE)


class TestAuditAndMain(unittest.TestCase):
    def test_audit_shapes(self):
        box = Inbox()
        box.receive(_msg(), seq=0)
        shaped = inbox_audit_event(box.events()[0], audit_seq=0)
        self.assertEqual(shaped["schema"], SCHEMA_PIN)
        self.assertEqual(shaped["audit_seq"], 0)
        with self.assertRaises(TypeError):
            inbox_audit_event(object(), audit_seq=0)
        with self.assertRaises(TypeError):
            inbox_audit_event(box.events()[0], audit_seq=True)
        with self.assertRaises(ValueError):
            inbox_audit_event(box.events()[0], audit_seq=-1)

    def test_main(self):
        import io
        import subprocess

        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / "inbox_pattern.py")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("inbox-pattern OK", result.stdout)
        buf = io.StringIO()
        import contextlib

        with contextlib.redirect_stdout(buf):
            main()
        self.assertIn("inbox-pattern OK", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
