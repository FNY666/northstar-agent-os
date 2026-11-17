"""The session panel must know every record type the runtime writes.

The panel (``examples/session-panel/session-panel.html``) is an
offline viewer over a session transcript.  It mirrors the runtime's
record vocabulary by hand -- a ``RECORD_TYPES`` list, a ``TYPE_COLOR``
map, and a ``summarize`` case per type.

THE RULE THIS SLICE PINS:

> **The panel's vocabulary is the runtime's vocabulary.**  Every record
> type the runtime writes is a record type the panel knows: it is
> classified as that type, it has a colour, and it is summarised as
> itself.

Commit ``695a25b7`` (B173 tombstone) added ``cancellation`` to the
runtime's ``RECORD_TYPES`` and left the panel behind, so the panel
rendered the sticky revocation that says "stop, do not publish" as a
raw JSON blob of an unknown type.

The second rule this slice pins is about the panel's errors-only
filter:

> **The errors-and-denials-only filter answers a boolean, and it does
> not hide a cancellation.**

``isErrorRecord`` used to return a summary *string* for a checkpoint and
for a postconditions record.  A string is truthy, so the filter treated
both as errors and listed them among the errors.  And it returned
``false`` for a cancellation -- the one record type whose whole point is
that it must not be missed.

The detector lives in ``tests/panel_record_vocabulary.py`` rather than
in this file, for the same reason the other guards' detectors live in
modules:  the mutant probe mutates a MODULE and reruns the slice's
tests, and a test file is excluded from the probe by name.  A guard
whose logic lives entirely inside a test file cannot be mutation-probed
at all.

Where node is available the guard runs the panel's REAL JavaScript
against the runtime's REAL records;  where node is not, the behavioural
half is skipped, never silently assumed to have passed.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import panel_record_vocabulary as detector  # noqa: E402

NODE = detector.node_available()


class PanelVocabularyTests(unittest.TestCase):
    """The rules, against the REAL panel and the REAL runtime."""

    def test_the_panel_knows_every_record_type_the_runtime_writes(self):
        missing = detector.missing_panel_record_types()
        self.assertEqual(
            missing,
            [],
            "the runtime writes these record types but the panel does not "
            "know them, so they render as an unknown type with no colour "
            "and no summary: %s" % ", ".join(missing),
        )

    def test_every_record_type_the_panel_knows_has_a_colour(self):
        uncoloured = detector.uncoloured_panel_record_types()
        self.assertEqual(
            uncoloured,
            [],
            "these panel record types have no colour of their own and "
            "fall back to a generic one: %s" % ", ".join(uncoloured),
        )

    def test_the_panel_declares_no_type_the_runtime_does_not_write(self):
        # The mirror may lag; it may not invent.  A type the panel
        # expects but the runtime never writes is a stale entry.
        runtime = set(detector.runtime_record_types())
        extra = [k for k in detector.panel_record_types() if k not in runtime]
        self.assertEqual(
            extra,
            [],
            "the panel expects record types the runtime never writes: %s"
            % ", ".join(extra),
        )

    @unittest.skipUnless(NODE, "node is not installed")
    def test_the_panel_classifies_each_record_type_as_itself(self):
        behaviour = detector.panel_behaviour()
        unknown = [
            kind
            for kind in detector.runtime_record_types()
            if not behaviour["known"].get(kind, False)
        ]
        self.assertEqual(
            unknown,
            [],
            "the panel does not classify these record types as their own "
            "type: %s" % ", ".join(unknown),
        )

    @unittest.skipUnless(NODE, "node is not installed")
    def test_the_error_filter_answers_a_boolean_for_every_record_type(self):
        # `isErrorRecord` returning a STRING is truthy, so every record
        # that has a summary is treated as an error by the filter.  That
        # is how a checkpoint or a postconditions record ends up in the
        # "errors only" list.
        behaviour = detector.panel_behaviour()
        not_boolean = [
            kind
            for kind, value in behaviour["is_error"].items()
            if not isinstance(value, bool)
        ]
        self.assertEqual(
            not_boolean,
            [],
            "the panel's isErrorRecord answers a non-boolean for these "
            "record types, so the errors-only filter treats them all as "
            "errors: %s" % ", ".join(not_boolean),
        )

    @unittest.skipUnless(NODE, "node is not installed")
    def test_the_error_filter_does_not_hide_a_cancellation(self):
        # The panel's "errors & denials only" filter must not hide the
        # one record whose whole purpose is that it must not be missed.
        behaviour = detector.panel_behaviour()
        self.assertIs(
            behaviour["is_error"].get("cancellation"),
            True,
            "the panel's errors-and-denials-only filter hides a "
            "cancellation record",
        )

    @unittest.skipUnless(NODE, "node is not installed")
    def test_the_error_filter_does_not_list_a_checkpoint_as_an_error(self):
        # A checkpoint is a resumable boundary, not an error.  It used
        # to be listed among the errors because isErrorRecord returned
        # its summary string.
        behaviour = detector.panel_behaviour()
        self.assertIs(
            behaviour["is_error"].get("checkpoint"),
            False,
            "the panel's errors-only filter lists a checkpoint as an error",
        )

    @unittest.skipUnless(NODE, "node is not installed")
    def test_a_cancellation_is_summarised_as_a_cancellation(self):
        # The summary must say WHAT is revoked and WHY it was declared.
        # A tombstone rendered as a raw JSON blob is not legible as the
        # stop it is, and the whole reason a cancellation is a record of
        # its own type is that a summary cannot carry it.
        behaviour = detector.panel_behaviour()
        summary = behaviour["summarize"].get("cancellation")
        self.assertIsInstance(summary, str)
        records = detector.runtime_records()
        tombstone = records["cancellation"]["tombstone"]
        self.assertIn("cancellation", summary.lower())
        self.assertIn(tombstone["action"], summary)
        self.assertIn(tombstone["subject"], summary)
        self.assertIn(tombstone["declarer"], summary)

    @unittest.skipUnless(NODE, "node is not installed")
    def test_a_lifted_cancellation_says_it_was_lifted(self):
        # The lift is a record too: without it a reader cannot tell a
        # standing stop from a lifted one.
        behaviour = detector.panel_behaviour()
        summary = behaviour["summarize"].get("cancellation_lifted")
        self.assertIsInstance(summary, str)
        self.assertIn("lift", summary.lower())


class GuardUnitTests(unittest.TestCase):
    """The detector against CRAFTED inputs.

    The repository-wide checks read the REAL panel, which -- once the
    fix lands -- knows every record type.  On their own they could not
    tell a working detector from one that never fires.
    """

    def test_the_detector_finds_nothing_missing_in_the_real_pair(self):
        self.assertEqual(
            detector.missing_panel_record_types(),
            [],
            "the real panel and the real runtime agree, so the detector "
            "must find nothing missing",
        )

    def test_the_runtime_vocabulary_is_read_in_declaration_order(self):
        kinds = detector.runtime_record_types()
        self.assertEqual(kinds[0], "session_start")
        self.assertIn("cancellation", kinds)

    def test_the_detector_reports_a_type_the_runtime_does_not_write(self):
        runtime = set(detector.runtime_record_types())
        self.assertNotIn("not_a_record_type", runtime)
        self.assertEqual(
            [k for k in detector.panel_record_types() if k not in runtime],
            [],
        )

    def test_the_runtime_writes_one_real_record_per_type(self):
        # The detector's records come from the runtime itself, so their
        # shapes are the shapes the runtime writes.  A record that the
        # runtime would refuse to write would mean the probe's payload
        # does not match the runtime.
        records = detector.runtime_records()
        self.assertEqual(
            sorted(records),
            sorted(detector.runtime_record_types()),
        )
        for kind, record in records.items():
            with self.subTest(kind=kind):
                self.assertEqual(record["type"], kind)

    def test_a_cancellation_record_carries_its_tombstone(self):
        records = detector.runtime_records()
        tombstone = records["cancellation"]["tombstone"]
        self.assertIn("grant_id", tombstone)
        self.assertIn("action", tombstone)
        self.assertIn("kind", tombstone)


if __name__ == "__main__":
    unittest.main()
