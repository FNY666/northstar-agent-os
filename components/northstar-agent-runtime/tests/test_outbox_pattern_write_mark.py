"""Tests for the outbox_pattern.py write()/mark() spec entry points (15 required)."""

import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from outbox_pattern import (  # noqa: E402
    OUTBOX_PATTERN_VERSION,
    SCHEMA_PIN,
    MessageState,
    Outbox,
    OutboxError,
    OutboxMessage,
    outbox_audit_event,
)


def _msg(mid="m1", dest="webhook", payload=None, seq=0):
    return OutboxMessage(mid, dest, payload or {"ok": True}, seq=seq)


def _ok_transport(message):
    return True


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(OUTBOX_PATTERN_VERSION, "outbox-pattern.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.outbox-pattern.v1")


class TestWrite(unittest.TestCase):
    def test_write_stores_pending(self):
        box = Outbox()
        returned = box.write(_msg(), seq=0)
        self.assertIsInstance(returned, OutboxMessage)
        self.assertIs(box.state("m1"), MessageState.PENDING)
        self.assertEqual(len(box.pending()), 1)

    def test_write_emits_published_event(self):
        box = Outbox()
        box.write(_msg("m2"), seq=3)
        events = box.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "published")
        self.assertEqual(events[0].message_id, "m2")
        self.assertEqual(events[0].seq, 3)

    def test_write_duplicate_id_refused(self):
        box = Outbox()
        box.write(_msg(), seq=0)
        with self.assertRaises(OutboxError):
            box.write(_msg(), seq=1)

    def test_write_bad_inputs_refused(self):
        box = Outbox()
        with self.assertRaises(OutboxError):
            box.write("not-a-message", seq=0)  # type: ignore[arg-type]
        for bad in (-1, True, "0", 1.5, None):
            with self.assertRaises(OutboxError, msg=f"seq={bad!r}"):
                box.write(_msg(), seq=bad)  # type: ignore[arg-type]


class TestMark(unittest.TestCase):
    def test_mark_sent(self):
        box = Outbox()
        box.write(_msg(), seq=0)
        new_state = box.mark("m1", seq=1)
        self.assertIs(new_state, MessageState.SENT)
        self.assertIs(box.state("m1"), MessageState.SENT)

    def test_mark_sent_emits_event(self):
        box = Outbox()
        box.write(_msg("m2"), seq=0)
        box.mark("m2", seq=2)
        kinds = [e.kind for e in box.events()]
        self.assertEqual(kinds, ["published", "sent"])

    def test_mark_failed_dead_letters(self):
        box = Outbox()
        box.write(_msg(), seq=0)
        box.mark("m1", seq=1, outcome="failed", reason="poison payload")
        self.assertIs(box.state("m1"), MessageState.FAILED)
        failed_event = box.events()[-1]
        self.assertEqual(failed_event.kind, "failed")
        self.assertEqual(failed_event.reason, "poison payload")

    def test_mark_unknown_id_raises_keyerror(self):
        box = Outbox()
        with self.assertRaises(KeyError):
            box.mark("nope", seq=0)

    def test_mark_terminal_refused_fail_closed(self):
        box = Outbox()
        box.write(_msg(), seq=0)
        box.mark("m1", seq=1)
        with self.assertRaises(OutboxError):
            box.mark("m1", seq=2)
        # dispatch-dead-lettered message is also refused
        box2 = Outbox(max_attempts=1)
        box2.write(_msg(), seq=0)
        box2.dispatch(lambda m: (_ for _ in ()).throw(ConnectionError("x")), seq=1)
        with self.assertRaises(OutboxError):
            box2.mark("m1", seq=2, outcome="sent")

    def test_mark_bad_outcome_refused(self):
        box = Outbox()
        box.write(_msg(), seq=0)
        with self.assertRaises(OutboxError):
            box.mark("m1", seq=1, outcome="delivered")
        self.assertIs(box.state("m1"), MessageState.PENDING)

    def test_mark_bad_seq_refused(self):
        box = Outbox()
        box.write(_msg(), seq=0)
        for bad in (-1, True, "1", 1.5, None):
            with self.assertRaises(OutboxError, msg=f"seq={bad!r}"):
                box.mark("m1", seq=bad)  # type: ignore[arg-type]
        self.assertIs(box.state("m1"), MessageState.PENDING)

    def test_mark_sent_excluded_from_dispatch(self):
        box = Outbox()
        box.write(_msg("m1", seq=0), seq=0)
        box.write(_msg("m2", seq=1), seq=1)
        box.mark("m1", seq=2)
        report = box.dispatch(_ok_transport, seq=3)
        self.assertEqual(report.sent, ("m2",))
        self.assertEqual(report.still_pending, ())
        self.assertEqual([m.message_id for m in box.sent()], ["m1", "m2"])

    def test_mark_failed_never_dispatched(self):
        box = Outbox(max_attempts=5)
        box.write(_msg(), seq=0)
        box.mark("m1", seq=1, outcome="failed", reason="poison")
        report = box.dispatch(_ok_transport, seq=2)
        self.assertEqual(report.sent, ())
        self.assertEqual([m.message_id for m in box.failed()], ["m1"])

    def test_mark_sent_audit_event_shape(self):
        box = Outbox()
        box.write(_msg("m9", "bus", {"n": 1}, seq=4), seq=4)
        box.mark("m9", seq=5)
        shaped = outbox_audit_event(box.events()[-1], audit_seq=7)
        self.assertEqual(shaped["kind"], "sent")
        self.assertEqual(shaped["message_id"], "m9")
        self.assertEqual(shaped["audit_seq"], 7)

    def test_main_still_passes(self):
        module_path = (
            Path(__file__).resolve().parents[1] / "outbox_pattern.py"
        )
        result = subprocess.run(
            [sys.executable, str(module_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("outbox-pattern OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
