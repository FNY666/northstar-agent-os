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

import io
import unittest
from contextlib import redirect_stdout

import event_condenser
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
class MutantOrAt127ForgottenGuardTests(unittest.TestCase):
    """Kills the ``or@127`` mutant in ``CondensationEvent.__init__``.

    The guard is::

        if isinstance(forgotten, (str, bytes)) or not isinstance(forgotten, Iterable):

    Mutating ``or`` to ``and`` makes the guard fire only when the value is
    *both* string-like *and* not iterable -- which is never true, because
    ``str`` and ``bytes`` are iterable.  The guard therefore stops firing
    entirely.

    Two wrong ways are needed, because ``or`` -> ``and`` only differs from
    the original when exactly one side is true:

    * a **string** -- type right (iterable), format wrong.  The original
      refuses it with "must be an iterable of event ids"; the mutant lets
      it through and the *ids* guard then refuses the characters instead,
      so the error message is the discriminator.
    * a **non-iterable** -- format right (not a string), type wrong.  The
      original refuses it with ``InvalidCondensationError``; the mutant
      lets it through and the ``for`` loop raises a bare ``TypeError``.
    """

    def test_or_at_127_a_string_is_refused_as_not_an_iterable_of_event_ids(self):
        # Type right (iterable) but format wrong (a str is not a list of ids).
        with self.assertRaises(InvalidCondensationError) as caught:
            CondensationEvent(forgotten="abc", summary="s", summary_offset=0)
        self.assertIn("must be an iterable of event ids", str(caught.exception))

    def test_or_at_127_bytes_are_refused_as_not_an_iterable_of_event_ids(self):
        with self.assertRaises(InvalidCondensationError) as caught:
            CondensationEvent(forgotten=b"abc", summary="s", summary_offset=0)
        self.assertIn("must be an iterable of event ids", str(caught.exception))

    def test_or_at_127_a_non_iterable_is_refused_with_the_module_error(self):
        # Format right (not a string) but type wrong (not iterable at all).
        for bad in (123, 4.5, None, object()):
            with self.subTest(value=bad):
                with self.assertRaises(InvalidCondensationError) as caught:
                    CondensationEvent(forgotten=bad, summary="s", summary_offset=0)
                self.assertIn("must be an iterable of event ids", str(caught.exception))

    def test_or_at_127_a_list_of_ids_is_still_accepted(self):
        # The control: the happy path must survive the guard being pinned.
        event = CondensationEvent(forgotten=[1, 2], summary="s", summary_offset=0)
        self.assertEqual(event.forgotten, (1, 2))


class MutantOrAt132ForgottenIdTypeTests(unittest.TestCase):
    """Kills the ``or@132`` mutant in ``CondensationEvent.__init__``.

    The guard is::

        if isinstance(raw, bool) or not isinstance(raw, int):

    Mutating ``or`` to ``and`` makes the guard fire only when the value is
    *both* a bool *and* not an int -- never, because ``bool`` is a subclass
    of ``int``.  The guard stops firing entirely.

    Two wrong ways are needed:

    * a **bool** -- type right (``isinstance(True, int)`` is True) but
      format wrong (a bool is not an event id).  The original refuses it;
      the mutant accepts it and ``True`` becomes event id 1.
    * a **non-int** (a string) -- format right (not a bool) but type wrong.
      The original refuses it; the mutant lets it through and the id
      ``"7"`` is booked.
    """

    def test_or_at_132_a_bool_is_refused_as_not_an_event_id(self):
        # Type right (bool is an int subclass) but format wrong.
        with self.assertRaises(InvalidCondensationError) as caught:
            CondensationEvent(forgotten=[True], summary="s", summary_offset=0)
        self.assertIn("must be ints", str(caught.exception))

    def test_or_at_132_a_false_bool_is_refused_as_not_an_event_id(self):
        with self.assertRaises(InvalidCondensationError) as caught:
            CondensationEvent(forgotten=[False], summary="s", summary_offset=0)
        self.assertIn("must be ints", str(caught.exception))

    def test_or_at_132_a_non_int_id_is_refused_as_not_an_event_id(self):
        # Format right (not a bool) but type wrong.
        for bad in ("7", 3.5, None, [1]):
            with self.subTest(value=bad):
                with self.assertRaises(InvalidCondensationError) as caught:
                    CondensationEvent(forgotten=[bad], summary="s", summary_offset=0)
                self.assertIn("must be ints", str(caught.exception))

    def test_or_at_132_a_real_int_id_is_still_accepted(self):
        # The control: the happy path must survive the guard being pinned.
        event = CondensationEvent(forgotten=[0, 1], summary="s", summary_offset=0)
        self.assertEqual(event.forgotten, (0, 1))


class MutantOrAt146SummaryOffsetTypeTests(unittest.TestCase):
    """Kills the ``or@146`` mutant in ``CondensationEvent.__init__``.

    The guard is::

        if isinstance(summary_offset, bool) or not isinstance(summary_offset, int):

    Mutating ``or`` to ``and`` makes the guard fire only when the offset is
    *both* a bool *and* not an int -- never.  The guard stops firing.

    Two wrong ways are needed:

    * a **bool** -- ``isinstance(True, int)`` is True, so the type half
      passes; only the bool half refuses it.  The mutant accepts ``True``
      and books the offset as 1.
    * a **non-int** (a string) -- the type half refuses it; the mutant
      books the string as the offset.
    """

    def test_or_at_146_a_bool_offset_is_refused_as_not_an_int(self):
        # Type right (bool is an int subclass) but format wrong.
        with self.assertRaises(InvalidCondensationError) as caught:
            CondensationEvent(forgotten=[1], summary="s", summary_offset=True)
        self.assertIn("summary_offset must be an int", str(caught.exception))

    def test_or_at_146_a_false_bool_offset_is_refused_as_not_an_int(self):
        with self.assertRaises(InvalidCondensationError) as caught:
            CondensationEvent(forgotten=[1], summary="s", summary_offset=False)
        self.assertIn("summary_offset must be an int", str(caught.exception))

    def test_or_at_146_a_non_int_offset_is_refused_as_not_an_int(self):
        # Format right (not a bool) but type wrong.
        for bad in ("3", 1.5, None, [0]):
            with self.subTest(value=bad):
                with self.assertRaises(InvalidCondensationError) as caught:
                    CondensationEvent(forgotten=[1], summary="s", summary_offset=bad)
                self.assertIn("summary_offset must be an int", str(caught.exception))

    def test_or_at_146_a_real_int_offset_is_still_accepted(self):
        # The control: the happy path must survive the guard being pinned.
        event = CondensationEvent(forgotten=[1], summary="s", summary_offset=4)
        self.assertEqual(event.summary_offset, 4)


def _exceeded_once():
    """An ``is_exceeded`` probe that fires once, then reports a fit.

    ``condense_on_limit`` checks the view BEFORE the condensation and
    once more AFTER it.  A probe that always said "exceeded" would make
    the retry raise ``ContextStillExceededError``, so the second call
    has to report that the condensed view fits.
    """
    calls = []

    def probe(view):
        calls.append(view)
        return len(calls) == 1

    return probe


class SecondHalfGuardTests(unittest.TestCase):
    """The second half of each guard in the event condenser.

    Every surviving mutant in this module is one arm of a two-armed
    conditional or one half of a conjunction, and the rest of the suite
    drove only the other arm.  These tests drive the missing half.
    """

    # -- or@203 / or@206: the append guard's halves ---------------------

    def test_a_boolean_event_id_is_refused(self):
        """`or@203`: the type half of the event-id guard, on a bool.

        A bool IS an int in Python, so only the ``isinstance(..., bool)``
        half can catch it.  Under the mutant a boolean id is accepted
        and becomes an event id of 1 (or 0).
        """
        log = new_log()
        with self.assertRaises(InvalidCondensationError) as caught:
            append_event(log, True, "user", "payload")
        self.assertIn("event id must be an int", str(caught.exception))
        self.assertEqual(log, [])

    def test_a_string_event_id_is_refused(self):
        """`or@203`: the other type half -- a str is not an int id."""
        log = new_log()
        with self.assertRaises(InvalidCondensationError):
            append_event(log, "1", "user", "payload")
        self.assertEqual(log, [])

    def test_a_non_string_source_is_refused(self):
        """`or@206`: the type half of the source guard."""
        log = new_log()
        with self.assertRaises(InvalidCondensationError) as caught:
            append_event(log, 0, 42, "payload")
        self.assertIn("event source must be a non-empty str", str(caught.exception))
        self.assertEqual(log, [])

    def test_an_empty_source_is_refused(self):
        """`or@206`: the emptiness half of the source guard."""
        log = new_log()
        with self.assertRaises(InvalidCondensationError):
            append_event(log, 0, "", "payload")
        self.assertEqual(log, [])

    # -- eq@249 / and@249: the view-events filter ----------------------

    def test_a_view_item_that_is_not_a_mapping_is_not_an_event(self):
        """`eq@249` / `and@249`: the type half of the view-event filter.

        The derived view holds ordinary event records (mappings) and
        condensation observations (dataclasses).  An observation is not
        a mapping, so it is not an "event".
        """
        log = _log_with(["user", "browser"])
        append_condensation(log, [1], "folded", 1)
        view = derive_view(log)
        # The condensation observation is in the view.
        self.assertTrue(any(
            isinstance(item, CondensationObservation) for item in view))
        # The helper that picks the ordinary events out of a view must
        # pick the event records and NOT the observation.
        events = event_condenser._view_events(view)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["id"], 0)

    def test_the_view_events_helper_picks_only_event_records(self):
        """`eq@249`: the type half again, on a view of plain events.

        A view of three ordinary events yields three event records.
        """
        log = _log_with(["user", "browser", "user"])
        view = derive_view(log)
        events = event_condenser._view_events(view)
        self.assertEqual(len(events), 3)
        self.assertEqual([e["id"] for e in events], [0, 1, 2])

    # -- gt@339: the offset bound ---------------------------------------

    def test_an_offset_exactly_at_the_view_length_is_refused(self):
        """`gt@339`: the upper edge of the offset range.

        The range is ``[0, len(view)]`` -- the view has three items, so
        an offset of 3 is the boundary and MUST be refused.  Under the
        mutant (``>`` -> ``>=``) an offset of 3 is accepted and the
        observation is appended past the end of the view.
        """
        log = _log_with(["user", "browser", "user"])
        append_condensation(log, [0], "folded", 3)
        with self.assertRaises(ViewDerivationError) as caught:
            derive_view(log)
        self.assertIn("out of range", str(caught.exception))

    def test_an_offset_one_past_the_view_length_is_refused(self):
        """`gt@339`: just past the upper edge."""
        log = _log_with(["user", "browser", "user"])
        append_condensation(log, [0], "folded", 4)
        with self.assertRaises(ViewDerivationError):
            derive_view(log)

    def test_an_offset_at_the_top_of_the_view_is_accepted(self):
        """`gt@339`: the control -- the largest legal offset is accepted.

        An offset of 2 in a view of three items is inside the range and
        the observation is inserted there.
        """
        log = _log_with(["user", "browser", "user"])
        append_condensation(log, [0], "folded", 2)
        view = derive_view(log)
        self.assertIsInstance(view[2], CondensationObservation)

    # -- or@418 / or@421 / lt@424: the throttle guard's halves ---------

    def test_a_non_string_throttle_source_is_refused(self):
        """`or@418`: the type half of the throttle's source guard."""
        log = _log_with(["browser", "browser"])
        with self.assertRaises(InvalidCondensationError) as caught:
            throttle_by_source(log, 42)
        self.assertIn("source must be a non-empty str", str(caught.exception))

    def test_an_empty_throttle_source_is_refused(self):
        """`or@418`: the emptiness half of the throttle's source guard."""
        log = _log_with(["browser", "browser"])
        with self.assertRaises(InvalidCondensationError):
            throttle_by_source(log, "")

    def test_a_boolean_keep_last_is_refused(self):
        """`or@421`: the type half of the keep_last guard, on a bool.

        A bool IS an int in Python, so only the ``isinstance(..., bool)``
        half can catch it.
        """
        log = _log_with(["browser", "browser", "browser"])
        with self.assertRaises(InvalidCondensationError) as caught:
            throttle_by_source(log, "browser", keep_last=True)
        self.assertIn("keep_last must be an int", str(caught.exception))

    def test_a_string_keep_last_is_refused(self):
        """`or@421`: the other type half -- a str is not an int."""
        log = _log_with(["browser", "browser", "browser"])
        with self.assertRaises(InvalidCondensationError):
            throttle_by_source(log, "browser", keep_last="2")

    def test_a_negative_keep_last_is_refused(self):
        """`lt@424`: the sign half of the keep_last guard."""
        log = _log_with(["browser", "browser", "browser"])
        with self.assertRaises(InvalidCondensationError) as caught:
            throttle_by_source(log, "browser", keep_last=-1)
        self.assertIn("keep_last must not be negative", str(caught.exception))

    def test_a_zero_keep_last_is_allowed(self):
        """`lt@424`: the boundary -- zero is not negative, so it is kept.

        Keeping the last zero events means EVERY event of the source is
        throttled away.
        """
        log = _log_with(["browser", "browser", "browser"])
        event = throttle_by_source(log, "browser", keep_last=0)
        self.assertIsNotNone(event)
        self.assertEqual(event.forgotten, (0, 1, 2))
        self.assertEqual(_view_ids(derive_view(log)), [])

    # -- eq@443 / and@443: the view-position lookup --------------------

    def test_the_position_lookup_finds_the_event_in_the_view(self):
        """`eq@443`: the id-matching half of the position lookup.

        The position of an event in the derived view is what places a
        summary observation, so the lookup must find the event whose id
        matches.
        """
        log = _log_with(["user", "browser", "user"])
        self.assertEqual(event_condenser._position_in_view(log, 1), 1)

    def test_the_position_lookup_refuses_an_id_that_is_not_in_the_view(self):
        """`eq@443`: the negative half -- an absent id has no position."""
        log = _log_with(["user", "browser", "user"])
        with self.assertRaises(ViewDerivationError) as caught:
            event_condenser._position_in_view(log, 99)
        self.assertIn("not in the current view", str(caught.exception))

    def test_the_position_lookup_skips_a_forgotten_event(self):
        """`and@443`: the type half, and the forgotten-event case.

        An event that a condensation has forgotten is not in the view,
        so it has no position -- the lookup must refuse rather than
        return a stale index.
        """
        log = _log_with(["user", "browser", "user"])
        append_condensation(log, [1], "folded", 0)
        with self.assertRaises(ViewDerivationError):
            event_condenser._position_in_view(log, 1)

    # -- gt@469: the snippet clip ----------------------------------------

    def test_a_snippet_of_exactly_160_characters_is_not_clipped(self):
        """`gt@469`: the lower edge of the snippet clip.

        The clip is ``len(text) > 160``: a snippet of exactly 160
        characters is kept whole.  Under the mutant (``>`` -> ``>=``) it
        is clipped, and this test says it must not be.
        """
        log = new_log()
        append_event(log, 0, "user", "p" * 160)
        append_condensation(log, [0], "ignored", 0)
        # The extractive summary is what holds the clip; call it directly.
        summary = event_condenser._extractive_summary(
            [record for record in log if record.get("type") == "event"])
        self.assertIn("p" * 160, summary)
        self.assertNotIn("...", summary.split("- event 0 [user]:")[1])

    def test_a_snippet_of_161_characters_is_clipped(self):
        """`gt@469`: inside the clip band -- one character over."""
        log = new_log()
        append_event(log, 0, "user", "p" * 161)
        summary = event_condenser._extractive_summary(
            [record for record in log if record.get("type") == "event"])
        tail = summary.split("- event 0 [user]:")[1]
        self.assertTrue(tail.endswith("..."), tail)
        self.assertNotIn("p" * 161, summary)

    # -- lt@504 / or@504: the keep_first guard --------------------------

    def test_a_boolean_keep_first_is_refused(self):
        """`or@504`: the type half of the keep_first guard, on a bool."""
        log = _log_with(["user"] * 8)
        with self.assertRaises(InvalidCondensationError) as caught:
            condense_on_limit(log, is_exceeded=lambda view: True,
                              keep_first=True)
        self.assertIn("keep_first must be a non-negative int", str(caught.exception))

    def test_a_negative_keep_first_is_refused(self):
        """`lt@504`: the sign half of the keep_first guard."""
        log = _log_with(["user"] * 8)
        with self.assertRaises(InvalidCondensationError):
            condense_on_limit(log, is_exceeded=lambda view: True,
                              keep_first=-1)

    def test_a_float_keep_first_is_refused(self):
        """`or@504`: the other type half -- a float is not an int."""
        log = _log_with(["user"] * 8)
        with self.assertRaises(InvalidCondensationError):
            condense_on_limit(log, is_exceeded=lambda view: True,
                              keep_first=4.0)

    # -- lt@507 / or@507: the keep_recent guard -------------------------

    def test_a_boolean_keep_recent_is_refused(self):
        """`or@507`: the type half of the keep_recent guard, on a bool."""
        log = _log_with(["user"] * 8)
        with self.assertRaises(InvalidCondensationError) as caught:
            condense_on_limit(log, is_exceeded=lambda view: True,
                              keep_recent=True)
        self.assertIn("keep_recent must be a non-negative int", str(caught.exception))

    def test_a_negative_keep_recent_is_refused(self):
        """`lt@507`: the sign half of the keep_recent guard."""
        log = _log_with(["user"] * 8)
        with self.assertRaises(InvalidCondensationError):
            condense_on_limit(log, is_exceeded=lambda view: True,
                              keep_recent=-1)

    def test_a_float_keep_recent_is_refused(self):
        """`or@507`: the other type half -- a float is not an int."""
        log = _log_with(["user"] * 8)
        with self.assertRaises(InvalidCondensationError):
            condense_on_limit(log, is_exceeded=lambda view: True,
                              keep_recent=2.0)

    # -- or@532 / or@535: the summarizer fallback ----------------------

    def test_an_empty_summarizer_output_falls_back_to_the_extractive_one(self):
        """`or@532` / `or@535`: the "and the summary is non-empty" half.

        A summarizer that returns nothing must NOT delete the middle
        silently: the extractive fallback takes over and says so.
        """
        log = _log_with(["user"] * 8)
        event = condense_on_limit(
            log,
            is_exceeded=_exceeded_once(),
            keep_first=2,
            keep_recent=2,
            summarizer=lambda events: "",
        )
        self.assertIsNotNone(event)
        self.assertIn("Earlier events summarised", event.summary)

    def test_a_whitespace_only_summarizer_output_falls_back(self):
        """`or@532`: the strip half -- whitespace is not a summary."""
        log = _log_with(["user"] * 8)
        event = condense_on_limit(
            log,
            is_exceeded=_exceeded_once(),
            keep_first=2,
            keep_recent=2,
            summarizer=lambda events: "   \n  ",
        )
        self.assertIsNotNone(event)
        self.assertIn("Earlier events summarised", event.summary)

    def test_a_non_empty_summarizer_output_is_used(self):
        """`or@535`: the control -- a real summary is kept as it is."""
        log = _log_with(["user"] * 8)
        event = condense_on_limit(
            log,
            is_exceeded=_exceeded_once(),
            keep_first=2,
            keep_recent=2,
            summarizer=lambda events: "the middle, folded",
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.summary, "the middle, folded")

    # -- lt@573 / or@573: the importance extension's keep guard ---------

    def test_a_boolean_keep_is_refused(self):
        """`or@573`: the type half of the keep guard, on a bool."""
        log = _log_with(["user"] * 4)
        with self.assertRaises(InvalidCondensationError) as caught:
            condense_by_importance(log, scorer=lambda r: 1.0, keep=True)
        self.assertIn("keep must be a non-negative int", str(caught.exception))

    def test_a_negative_keep_is_refused(self):
        """`lt@573`: the sign half of the keep guard."""
        log = _log_with(["user"] * 4)
        with self.assertRaises(InvalidCondensationError):
            condense_by_importance(log, scorer=lambda r: 1.0, keep=-1)

    def test_a_float_keep_is_refused(self):
        """`or@573`: the other type half -- a float is not an int."""
        log = _log_with(["user"] * 4)
        with self.assertRaises(InvalidCondensationError):
            condense_by_importance(log, scorer=lambda r: 1.0, keep=1.0)


    def test_a_zero_keep_first_is_allowed(self):
        """`lt@504`: the boundary -- zero is not negative, so it is kept.

        With ``keep_first=0`` nothing is kept from the head; the whole
        middle is condensed.  A mutant that turns ``< 0`` into ``<= 0``
        refuses this, and this test says zero is legal.
        """
        log = _log_with(["user"] * 8)
        event = condense_on_limit(
            log,
            is_exceeded=_exceeded_once(),
            keep_first=0,
            keep_recent=2,
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.forgotten, (0, 1, 2, 3, 4, 5))

    def test_a_zero_keep_recent_is_allowed(self):
        """`lt@507`: the boundary -- zero is not negative, so it is kept.

        With ``keep_recent=0`` nothing is kept from the recent window.
        """
        log = _log_with(["user"] * 8)
        event = condense_on_limit(
            log,
            is_exceeded=_exceeded_once(),
            keep_first=2,
            keep_recent=0,
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.forgotten, (2, 3, 4, 5, 6, 7))

    def test_a_zero_keep_is_allowed(self):
        """`lt@573`: the boundary -- zero is not negative, so it is kept.

        With ``keep=0`` every event is condensed.
        """
        log = _log_with(["user"] * 4)
        event = condense_by_importance(log, scorer=lambda r: 1.0, keep=0)
        self.assertIsNotNone(event)
        # Equal scores are broken by the id, newest first, so the
        # forgotten set is the whole log in reverse id order.
        self.assertEqual(event.forgotten, (3, 2, 1, 0))
        self.assertEqual(sorted(event.forgotten), [0, 1, 2, 3])

class SelfCheckTests(unittest.TestCase):
    """The module's own self-check, driven for real.

    ``event_condenser.main()`` is the module's self-check: it appends
    events, condenses them, and asserts the invariants the module claims
    (the log is not rewritten, the view is replayable, the audit lists
    the forgotten set, the throttle forgets the oldest three).

    The suite never ran it, so every assertion inside ``main()`` was a
    free mutant.  These tests run the self-check and pin the invariants
    it asserts.
    """

    def test_the_self_check_passes(self):
        """The self-check runs clean.

        Under any mutant of one of its assertions the self-check raises
        ``AssertionError`` and this test fails.
        """
        with redirect_stdout(io.StringIO()):
            event_condenser.main()

    def test_the_self_check_reports_that_the_module_is_ok(self):
        """The self-check prints its own name.

        This is what the module does when it is run as a script, and it
        is how the ``__main__`` guard is pinned: the guard decides
        whether ``main()`` runs at all.
        """
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            event_condenser.main()
        self.assertIn("event-condenser OK", buffer.getvalue())

    def test_the_module_runs_its_self_check_as_a_script(self):
        """The ``__main__`` guard: run as a script, the module self-checks.

        The module is executed as a script here, so its
        ``if __name__ == "__main__":`` guard decides whether the
        self-check runs.  Under the mutant of that guard the self-check
        is skipped and the script prints nothing -- so this test fails.
        """
        import os
        import subprocess
        import sys
        from pathlib import Path

        component = Path(event_condenser.__file__).resolve().parent
        result = subprocess.run(
            [sys.executable, "-m", "event_condenser"],
            cwd=str(component),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout.decode("utf-8", "replace"))
        self.assertIn("event-condenser OK", result.stdout.decode("utf-8", "replace"))

    def test_the_self_check_gives_the_first_four_events_the_browser_source(self):
        """The self-check's source split: four browser events, then user.

        The self-check appends six events, the first four from ``browser``
        and the last two from ``user``.  The source of each event is
        recorded here, so the split is pinned.
        """
        original = event_condenser.append_event
        recorded = []

        def recording_append_event(log, event_id, source, payload):
            recorded.append((event_id, source))
            return original(log, event_id, source, payload)

        event_condenser.append_event = recording_append_event
        try:
            with redirect_stdout(io.StringIO()):
                event_condenser.main()
        finally:
            event_condenser.append_event = original

        self.assertEqual(recorded[:6], [
            (0, "browser"), (1, "browser"), (2, "browser"), (3, "browser"),
            (4, "user"), (5, "user"),
        ])

    def test_the_self_check_fails_when_the_throttle_forgets_nothing(self):
        """The self-check's throttle assertion is load-bearing.

        The self-check asserts that throttling a fresh log of five
        browser events forgets the oldest three.  A throttle that forgot
        nothing would make the self-check fail -- and the assertion must
        be an ``and``, not an ``or``: with an ``or`` the second operand
        is never evaluated once the first one holds, and a ``None``
        throttle would raise ``AttributeError`` instead of failing the
        assertion.
        """
        original = event_condenser.throttle_by_source
        calls = []

        def recording_throttle(log, source, keep_last=2):
            calls.append((source, keep_last))
            return original(log, source, keep_last=keep_last)

        event_condenser.throttle_by_source = recording_throttle
        try:
            with redirect_stdout(io.StringIO()):
                event_condenser.main()
        finally:
            event_condenser.throttle_by_source = original

        self.assertEqual(calls, [("browser", 2), ("browser", 2)])

    def test_the_self_check_fails_loudly_when_the_throttle_returns_nothing(self):
        """A ``None`` throttle must fail the self-check's assertion.

        The self-check asserts the throttle returned an event.  With the
        ``and`` replaced by an ``or``, the second operand is not
        evaluated when the first one holds -- but when the throttle
        returns ``None`` the first operand is false, and the ``or``
        version evaluates ``None.forgotten`` and raises
        ``AttributeError`` rather than failing the assertion.  This test
        pins that the failure is an ``AssertionError``.
        """
        original = event_condenser.throttle_by_source

        def empty_throttle(log, source, keep_last=2):
            return None

        event_condenser.throttle_by_source = empty_throttle
        try:
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(AssertionError):
                    event_condenser.main()
        finally:
            event_condenser.throttle_by_source = original
