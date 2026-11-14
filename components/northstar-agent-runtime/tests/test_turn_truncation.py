"""Tests for turn truncation: an interrupted turn is recorded as the prefix
that was actually delivered.

The rule under test comes from the OpenAI Agents SDK Realtime guide
("Interruptions and playback tracking", read 2026-11-14): when the user
interrupts the assistant, the session updates history so the server-side
conversation stays aligned with **what the user actually heard**, using
``RealtimePlaybackTracker`` so the interrupted response is truncated at the
actual playback position rather than assuming all generated audio has
already been heard.

Northstar extensions marked as such in the design doc: the delivery position
is generalised to a caller-reported ``delivered_len`` in content units; the
state is three-valued (``DELIVERED`` / ``PARTIAL`` / ``UNKNOWN``); every
truncation record carries a summary pin of the item it truncated.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

from turn_truncation import (
    DELIVERED,
    PARTIAL,
    UNKNOWN,
    DeliveryRangeError,
    HistoryEntry,
    PinMismatchError,
    ReextendRefusedError,
    TurnItem,
    TurnTruncationError,
    delivered_prefix,
    delivery_status,
    history_for_resume,
    item_pin,
    make_item,
    stdlib_only,
    truncate,
    verify_record,
)


class TruncateToDeliveredPrefixTests(unittest.TestCase):
    """A partial delivery keeps the prefix and drops the rest for good."""

    def test_prefix_is_the_delivered_part(self):
        item = make_item("t1", "The answer is forty two.")
        outcome = truncate(item, 9, seq=3)
        self.assertEqual(outcome.item.status, PARTIAL)
        self.assertEqual(delivered_prefix(outcome.item), "The answe")

    def test_undelivered_suffix_is_unreachable(self):
        item = make_item("t1", "The answer is forty two.")
        outcome = truncate(item, 9, seq=3)
        self.assertNotIn("forty two", delivered_prefix(outcome.item))
        self.assertNotIn("forty two", outcome.item.generated_text[: outcome.item.delivered_len])

    def test_record_carries_pin_lengths_and_seq(self):
        item = make_item("t1", "The answer is forty two.")
        outcome = truncate(item, 9, seq=3)
        record = outcome.record
        self.assertIsNotNone(record)
        self.assertEqual(record.item_id, "t1")
        self.assertEqual(record.pin, item_pin(item))
        self.assertEqual(record.delivered_len, 9)
        self.assertEqual(record.truncated_len, item.generated_len - 9)
        self.assertEqual(record.seq, 3)

    def test_zero_delivery_leaves_no_said_text(self):
        item = make_item("t1", "The answer is forty two.")
        outcome = truncate(item, 0, seq=1)
        self.assertEqual(delivered_prefix(outcome.item), "")
        self.assertEqual(outcome.record.truncated_len, item.generated_len)
        entry = history_for_resume([outcome.item])[0]
        self.assertEqual(entry.text, "")
        self.assertNotIn("answer", entry.text)


class RangeAndReextendRefusalTests(unittest.TestCase):
    """Fail-closed: an out-of-range report is refused, never rounded."""

    def test_delivered_len_above_generated_len_is_refused(self):
        item = make_item("t1", "short")
        with self.assertRaises(DeliveryRangeError):
            truncate(item, len("short") + 1, seq=1)

    def test_negative_delivered_len_is_refused(self):
        item = make_item("t1", "short")
        with self.assertRaises(DeliveryRangeError):
            truncate(item, -1, seq=1)

    def test_re_extending_a_truncated_item_is_refused(self):
        item = make_item("t1", "The answer is forty two.")
        outcome = truncate(item, 9, seq=1)
        with self.assertRaises(ReextendRefusedError):
            truncate(outcome.item, 20, seq=2)

    def test_shortening_an_already_truncated_item_is_refused(self):
        item = make_item("t1", "The answer is forty two.")
        outcome = truncate(item, 9, seq=1)
        with self.assertRaises(DeliveryRangeError):
            truncate(outcome.item, 4, seq=2)

    def test_mismatched_summary_pin_is_refused(self):
        item = make_item("t1", "The answer is forty two.")
        record = truncate(item, 9, seq=1).record
        other = make_item("t2", "A completely different turn entirely.")
        with self.assertRaises(PinMismatchError):
            verify_record(other, record)

    def test_tampered_pin_is_refused(self):
        item = make_item("t1", "The answer is forty two.")
        outcome = truncate(item, 9, seq=1)
        tampered = type(outcome.record)(
            item_id=outcome.record.item_id,
            pin="sha256:" + "0" * 64,
            delivered_len=outcome.record.delivered_len,
            truncated_len=outcome.record.truncated_len,
            seq=outcome.record.seq,
            generated_len=outcome.record.generated_len,
        )
        with self.assertRaises(PinMismatchError):
            verify_record(item, tampered)

    def test_item_with_inconsistent_status_is_refused(self):
        with self.assertRaises(TurnTruncationError):
            TurnItem(
                item_id="t1",
                generated_text="hello",
                generated_len=5,
                delivered_len=5,
                status=UNKNOWN,
            )


class DeliveryStateTests(unittest.TestCase):
    """Three states: delivered, partial, and unknown (no report at all)."""

    def test_no_report_stays_unknown(self):
        item = make_item("t1", "Something was said.")
        self.assertIsNone(item.delivered_len)
        self.assertEqual(item.status, UNKNOWN)
        self.assertEqual(delivery_status(None, len("Something was said.")), UNKNOWN)

    def test_no_report_is_not_silently_marked_delivered(self):
        item = make_item("t1", "Something was said.")
        self.assertNotEqual(item.status, DELIVERED)
        self.assertEqual(delivered_prefix(item), "")

    def test_unknown_history_entry_is_flagged(self):
        item = make_item("t1", "Something was said.")
        entry = history_for_resume([item])[0]
        self.assertTrue(entry.delivery_unknown)
        self.assertEqual(entry.text, "")
        self.assertIn("delivery-unknown", entry.marker)

    def test_full_delivery_is_delivered(self):
        item = make_item("t1", "Fully heard.", delivered_len=len("Fully heard."))
        self.assertEqual(item.status, DELIVERED)
        self.assertEqual(delivered_prefix(item), "Fully heard.")

    def test_partial_delivery_is_partial(self):
        item = make_item("t1", "Fully heard.", delivered_len=4)
        self.assertEqual(item.status, PARTIAL)
        self.assertEqual(delivered_prefix(item), "Full")


class HistoryForResumeTests(unittest.TestCase):
    """The history a resumed turn reads, per state."""

    def test_partial_entry_is_prefix_plus_marker(self):
        item = make_item("t1", "The answer is forty two.")
        outcome = truncate(item, 9, seq=2)
        entry = history_for_resume([outcome.item])[0]
        self.assertEqual(entry.text, "The answe")
        self.assertIsNotNone(entry.marker)
        self.assertIn("truncated", entry.marker)
        self.assertNotIn("forty two", entry.text)
        self.assertEqual(entry.truncated_len, item.generated_len - 9)

    def test_delivered_entry_is_unchanged(self):
        text = "The answer is forty two."
        item = make_item("t1", text, delivered_len=len(text))
        entry = history_for_resume([item])[0]
        self.assertEqual(entry.text, text)
        self.assertIsNone(entry.marker)
        self.assertEqual(entry.truncated_len, 0)
        self.assertFalse(entry.delivery_unknown)

    def test_unknown_entry_carries_no_text(self):
        item = make_item("t1", "The answer is forty two.")
        entry = history_for_resume([item])[0]
        self.assertEqual(entry.text, "")
        self.assertTrue(entry.delivery_unknown)
        self.assertNotIn("answer", entry.text)

    def test_history_never_contains_the_undelivered_suffix(self):
        item = make_item("t1", "The answer is forty two.")
        outcome = truncate(item, 9, seq=2)
        blob = "\n".join(e.text for e in history_for_resume([outcome.item]))
        self.assertNotIn("forty two", blob)
        self.assertNotIn("is forty", blob)


class DrivenPathTests(unittest.TestCase):
    """The three real paths, driven end to end through the module.

    The numbers come from the source's worked example (the Realtime API
    ``conversation.item.truncate`` scenario): a 6-second answer whose speaker
    had written 77,760 bytes of 24 kHz 16-bit mono PCM -- 48,000 bytes per
    second, so 1.62 seconds of audio -- is truncated with
    ``audio_end_ms=1620``.  Here the delivery position is reported in
    content units; the module does no audio arithmetic.
    """

    ANSWER = (
        "The answer is forty two. Let me also explain why it matters, "
        "because the reasoning runs on for a while."
    )

    def test_path_a_interrupted_at_the_delivery_position(self):
        """Interrupted mid-answer: history keeps the prefix and the marker."""
        item = make_item("turn-1", self.ANSWER)
        outcome = truncate(item, 18, seq=1)
        self.assertEqual(outcome.item.status, PARTIAL)
        self.assertEqual(outcome.record.delivered_len, 18)
        self.assertEqual(outcome.record.truncated_len, item.generated_len - 18)

        entry = history_for_resume([outcome.item])[0]
        self.assertEqual(entry.text, self.ANSWER[:18])
        self.assertIn("truncated", entry.marker)
        # The part the user never heard is not in the history at all.
        self.assertNotIn("Let me also explain", entry.text)
        self.assertNotIn("Let me also explain", entry.marker)

    def test_path_b_zero_delivery(self):
        """Interrupted before anything was delivered: no said text at all."""
        item = make_item("turn-1", self.ANSWER)
        outcome = truncate(item, 0, seq=1)
        self.assertEqual(delivered_prefix(outcome.item), "")
        self.assertEqual(outcome.record.truncated_len, item.generated_len)

        entry = history_for_resume([outcome.item])[0]
        self.assertEqual(entry.text, "")
        self.assertIn("truncated", entry.marker)
        self.assertNotIn("answer", entry.text)

    def test_path_c_undisturbed_delivery(self):
        """No interruption: the whole turn was delivered, no record."""
        item = make_item("turn-1", self.ANSWER)
        outcome = truncate(item, item.generated_len, seq=1)
        self.assertEqual(outcome.item.status, DELIVERED)
        self.assertIsNone(outcome.record)
        self.assertFalse(outcome.truncated)

        entry = history_for_resume([outcome.item])[0]
        self.assertEqual(entry.text, self.ANSWER)
        self.assertIsNone(entry.marker)


class ModuleHygieneTests(unittest.TestCase):
    """The module stays a pure, standard-library-only bookkeeping library."""

    def test_stdlib_only(self):
        self.assertTrue(stdlib_only())

    def test_module_does_no_audio_arithmetic(self):
        """The code has no audio arithmetic; only the source quotes may."""
        source = Path(__file__).resolve().parent.parent / "turn_truncation.py"
        text = source.read_text(encoding="utf-8")
        code = re.sub(r'""".*?"""', "", text, flags=re.DOTALL)
        for forbidden in ("48000", "48_000", "77760", "audio_end_ms", "byte", "24000"):
            self.assertNotIn(forbidden, code)

    def test_delivery_position_is_the_callers_number(self):
        """Whatever the caller reports is what is truncated (after range check)."""
        item = make_item("turn-1", "abcdefgh")
        for delivered in range(0, len("abcdefgh") + 1):
            outcome = truncate(item, delivered, seq=1)
            self.assertEqual(delivered_prefix(outcome.item), "abcdefgh"[:delivered])
