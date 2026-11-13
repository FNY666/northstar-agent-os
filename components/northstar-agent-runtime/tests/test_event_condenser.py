"""Tests for ``event_condenser``.

The module's claim is that condensation is an **event in the log** and the
model-visible view is **derived** from the log.  So the tests drive real
paths, not isolated helpers:

* **(a) append-is-record** -- condensing appends one record and rewrites
  nothing; the pre-condensation log is recoverable verbatim.
* **(b) derive** -- forgotten events are gone, the condensation meta-event is
  gone, the summary observation sits at ``summary_offset``, and an
  out-of-range offset fails closed.
* **(c) throttle** -- only the throttled source loses events; other sources
  are untouched.
* **(d) reactive limit** -- one condensation plus one retry; a retry that
  still exceeds raises instead of dropping data.
* **(e) keep-first** -- the head of the log is never swallowed by the middle
  summary.
* **(f) audit** -- every condensation's forgotten set and summary are
  listable from the log.

Mutations this file must kill: an out-of-range offset that is clamped instead
of refused; a ``forgotten`` set that is silently empty; a summary inserted at
index 0 when ``summary_offset`` says otherwise; a duplicate condensation that
is silently ignored; a throttle that touches every source; a reactive path
that drops data instead of raising.
"""
from __future__ import annotations

import unittest

from event_condenser import (
    ATTENTION_WINDOW,
    KEEP_FIRST,
    MAX_SIZE,
    CondensationEvent,
    CondensationObservation,
    ContextStillExceededError,
    DuplicateCondensationError,
    InvalidCondensationError,
    ViewDerivationError,
    append_condensation,
    append_event,
    audit_condensations,
    condense_by_importance,
    condense_on_limit,
    derive_view,
    new_log,
    replay,
    throttle_by_source,
)


def _log_with(sources, start=0):
    """A log with one event per source in ``sources``."""
    log = new_log()
    for offset, source in enumerate(sources):
        append_event(log, start + offset, source, f"payload {start + offset}")
    return log


def _view_ids(view):
    """The ids of the ordinary events in a derived view."""
    return [item["id"] for item in view if isinstance(item, dict)
            and item.get("type") == "event"]


class AppendIsRecordTests(unittest.TestCase):
    """Condensation appends to the log; it never rewrites it."""

    def test_append_leaves_the_previous_log_byte_for_byte(self):
        log = _log_with(["user", "browser", "user", "browser"])
        before = [dict(record) for record in log]
        event = append_condensation(log, [1], "one browser event folded", 1)
        self.assertIsInstance(event, CondensationEvent)
        self.assertEqual(event.forgotten, (1,))
        self.assertEqual(log[:4], before)
        self.assertEqual(len(log), 5)
        self.assertEqual(log[4]["type"], "condensation")
        self.assertEqual(log[4]["forgotten"], [1])
        self.assertEqual(log[4]["summary"], "one browser event folded")
        self.assertEqual(log[4]["summary_offset"], 1)

    def test_replay_reproduces_the_view_and_the_original_log_survives(self):
        """The pre-condensation log is still there after the condensation."""
        log = _log_with(["user", "browser", "user", "browser"])
        original_ids = _view_ids(derive_view(log))
        append_condensation(log, [1, 3], "two browser events folded", 1)
        view = derive_view(log)
        self.assertEqual(_view_ids(view), [0, 2])
        self.assertEqual(replay(log), view)
        # The original events are still in the log, not just in the view.
        surviving = [r for r in log if r.get("type") == "event"]
        self.assertEqual([r["id"] for r in surviving], [0, 1, 2, 3])

    def test_duplicate_condensation_of_the_same_id_is_refused(self):
        """Forgetting is idempotent-refusing, not a silent no-op."""
        log = _log_with(["user", "browser", "user"])
        append_condensation(log, [1], "folded", 1)
        before = [dict(record) for record in log]
        with self.assertRaises(DuplicateCondensationError):
            append_condensation(log, [1], "folded again", 1)
        self.assertEqual(log, before)

    def test_forgetting_an_id_that_is_not_in_the_log_is_refused(self):
        log = _log_with(["user", "browser"])
        with self.assertRaises(InvalidCondensationError):
            append_condensation(log, [99], "never happened", 0)

    def test_empty_forgotten_set_is_refused(self):
        """A condensation that forgets nothing is not a condensation."""
        log = _log_with(["user"])
        with self.assertRaises(InvalidCondensationError):
            append_condensation(log, [], "nothing", 0)

    def test_malformed_condensation_arguments_are_refused(self):
        log = _log_with(["user", "browser"])
        with self.assertRaises(InvalidCondensationError):
            append_condensation(log, [1], 42, 0)
        with self.assertRaises(InvalidCondensationError):
            append_condensation(log, ["1"], "summary", 0)
        with self.assertRaises(InvalidCondensationError):
            append_condensation(log, [1], "summary", "0")

    def test_a_negative_offset_is_refused_when_the_view_is_derived(self):
        """The log records what was asked; the refusal happens at derivation."""
        log = _log_with(["user", "browser", "user"])
        append_condensation(log, [1], "folded", -1)
        with self.assertRaises(ViewDerivationError):
            derive_view(log)


class DeriveViewTests(unittest.TestCase):
    """The view is derived from the log, and a bad offset fails closed."""

    def test_forgotten_events_and_meta_events_are_absent_from_the_view(self):
        log = _log_with(["user", "browser", "user", "browser"])
        append_condensation(log, [1, 3], "folded", 1)
        view = derive_view(log)
        self.assertEqual(_view_ids(view), [0, 2])
        self.assertNotIn("condensation", [item.get("type") for item in view
                                           if isinstance(item, dict)])

    def test_summary_observation_sits_at_the_summary_offset(self):
        log = _log_with(["user", "browser", "user", "browser", "user"])
        append_condensation(log, [1, 3], "folded", 2)
        view = derive_view(log)
        self.assertEqual(len(view), 4)
        self.assertIsInstance(view[2], CondensationObservation)
        self.assertEqual(view[2].summary, "folded")
        self.assertEqual(view[2].summary_offset, 2)
        self.assertEqual(view[2].forgotten, (1, 3))

    def test_summary_at_offset_zero_is_inserted_at_the_front(self):
        log = _log_with(["user", "browser", "user"])
        append_condensation(log, [0], "first event folded", 0)
        view = derive_view(log)
        self.assertIsInstance(view[0], CondensationObservation)
        self.assertEqual(view[0].summary, "first event folded")
        self.assertEqual(_view_ids(view), [1, 2])

    def test_offset_beyond_the_view_fails_closed(self):
        """An out-of-range offset is refused, not clamped or padded."""
        log = _log_with(["user", "browser", "user"])
        append_condensation(log, [1], "folded", 99)
        with self.assertRaises(ViewDerivationError):
            derive_view(log)

    def test_negative_offset_fails_closed(self):
        log = _log_with(["user", "browser", "user"])
        append_condensation(log, [1], "folded", -1)
        with self.assertRaises(ViewDerivationError):
            derive_view(log)

    def test_two_condensations_are_replayed_in_log_order(self):
        """A replay applies each condensation to the view the earlier ones made."""
        log = _log_with(["user", "browser", "user", "browser", "user"])
        append_condensation(log, [1], "first", 1)
        append_condensation(log, [3], "second", 1)
        view = derive_view(log)
        observations = [item for item in view
                        if isinstance(item, CondensationObservation)]
        # "first" was inserted at 1; the view then grew to 6 items, and
        # "second" was inserted at 1 of *that* view -- in front of "first".
        self.assertEqual([o.summary for o in observations], ["second", "first"])
        self.assertEqual(_view_ids(view), [0, 2, 4])


class ThrottleTests(unittest.TestCase):
    """Per-source throttling: the ``BrowserOutputCondenser`` shape."""

    def test_only_the_most_recent_events_of_the_source_survive(self):
        log = _log_with(["browser", "browser", "browser", "browser"])
        event = throttle_by_source(log, "browser")
        self.assertIsInstance(event, CondensationEvent)
        self.assertEqual(event.forgotten, (0, 1))
        self.assertEqual(_view_ids(derive_view(log)), [2, 3])

    def test_keep_last_defaults_to_the_verbatim_attention_window(self):
        self.assertEqual(ATTENTION_WINDOW, 2)
        log = _log_with(["browser"] * 5)
        event = throttle_by_source(log, "browser")
        self.assertEqual(event.forgotten, (0, 1, 2))
        self.assertEqual(_view_ids(derive_view(log)), [3, 4])

    def test_other_sources_are_not_throttled(self):
        log = _log_with(["browser", "user", "browser", "user", "browser"])
        throttle_by_source(log, "browser")
        view = derive_view(log)
        self.assertIn(1, _view_ids(view))
        self.assertIn(3, _view_ids(view))

    def test_throttling_fewer_events_than_keep_last_does_nothing(self):
        log = _log_with(["browser", "browser"])
        self.assertIsNone(throttle_by_source(log, "browser"))
        self.assertEqual(len(log), 2)

    def test_throttled_events_are_still_in_the_log(self):
        log = _log_with(["browser"] * 4)
        throttle_by_source(log, "browser")
        surviving = [r for r in log if r.get("type") == "event"]
        self.assertEqual([r["id"] for r in surviving], [0, 1, 2, 3])
        self.assertEqual(audit_condensations(log)[0]["forgotten"], [0, 1])


class ReactiveLimitTests(unittest.TestCase):
    """The ``ContextWindowExceededError`` path: condense the middle, retry once."""

    def test_no_signal_means_nothing_is_appended(self):
        log = _log_with(["user"] * 6)
        result = condense_on_limit(log, is_exceeded=lambda view: False)
        self.assertIsNone(result)
        self.assertEqual(len(log), 6)

    def test_a_signal_condenses_the_middle_and_retries_once(self):
        log = _log_with(["user"] * 8)
        calls = []

        def exceeded(view):
            calls.append(len(view))
            # Exceeded until the view shrinks below 8 items.
            return len(view) >= 8

        event = condense_on_limit(log, is_exceeded=exceeded)
        self.assertIsInstance(event, CondensationEvent)
        self.assertEqual(len(calls), 2)
        # keep_first=4, keep_recent=2 -> the middle is ids 4 and 5.
        self.assertEqual(event.forgotten, (4, 5))
        view = derive_view(log)
        self.assertEqual(_view_ids(view), [0, 1, 2, 3, 6, 7])

    def test_the_head_is_never_swallowed_by_the_middle_summary(self):
        """keep_first=4: the first four events always survive."""
        log = _log_with(["user"] * 12)

        def exceeded(view):
            return len(view) > 9

        event = condense_on_limit(log, is_exceeded=exceeded)
        self.assertIsInstance(event, CondensationEvent)
        for head_id in (0, 1, 2, 3):
            self.assertNotIn(head_id, event.forgotten)
        self.assertEqual(_view_ids(derive_view(log))[:4], [0, 1, 2, 3])

    def test_a_retry_that_still_exceeds_raises_instead_of_dropping_data(self):
        log = _log_with(["user"] * 8)
        with self.assertRaises(ContextStillExceededError) as caught:
            condense_on_limit(log, is_exceeded=lambda view: True)
        self.assertIn("still exceeded", str(caught.exception))
        # Nothing was silently dropped: every event is still in the log.
        surviving = [r for r in log if r.get("type") == "event"]
        self.assertEqual([r["id"] for r in surviving], list(range(8)))

    def test_a_log_too_short_to_condense_raises(self):
        log = _log_with(["user"] * 3)
        with self.assertRaises(ContextStillExceededError):
            condense_on_limit(log, is_exceeded=lambda view: True)

    def test_the_verbatim_source_numbers_are_pinned(self):
        """keep_first=4 and max_size=120 are the OpenHands numbers."""
        self.assertEqual(KEEP_FIRST, 4)
        self.assertEqual(MAX_SIZE, 120)


class AuditTests(unittest.TestCase):
    """Every condensation is listable from the log."""

    def test_the_audit_lists_the_forgotten_set_and_the_summary(self):
        log = _log_with(["user", "browser", "user", "browser"])
        append_condensation(log, [1], "first fold", 1)
        append_condensation(log, [3], "second fold", 2)
        audit = audit_condensations(log)
        self.assertEqual(len(audit), 2)
        self.assertEqual(audit[0]["forgotten"], [1])
        self.assertEqual(audit[0]["summary"], "first fold")
        self.assertEqual(audit[1]["forgotten"], [3])
        self.assertEqual(audit[1]["summary"], "second fold")
        self.assertEqual(audit[1]["summary_offset"], 2)

    def test_the_audit_shows_nothing_before_any_condensation(self):
        log = _log_with(["user", "browser"])
        self.assertEqual(audit_condensations(log), [])


class ImportanceExtensionTests(unittest.TestCase):
    """Importance scoring is a Northstar extension, opt-in and never default."""

    def test_the_least_important_events_are_condensed(self):
        log = _log_with(["user"] * 4)
        event = condense_by_importance(log, lambda record: float(record["id"]),
                                       keep=2)
        self.assertIsInstance(event, CondensationEvent)
        self.assertEqual(event.forgotten, (0, 1))
        self.assertEqual(_view_ids(derive_view(log)), [2, 3])

    def test_keeping_everything_condenses_nothing(self):
        log = _log_with(["user"] * 3)
        self.assertIsNone(condense_by_importance(log, lambda r: 1.0, keep=3))

    def test_the_default_path_stays_positional(self):
        """The default paths condense by position, never by score."""
        log = _log_with(["user"] * 10)
        condense_on_limit(log, is_exceeded=lambda view: len(view) >= 9)
        forgotten = audit_condensations(log)[0]["forgotten"]
        # The middle between the head and the recent window -- not the
        # lowest-scored events, because there is no score here at all.
        self.assertEqual(forgotten, [4, 5, 6, 7])
