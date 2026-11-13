"""Tests for the silent-failure detector.

Shapes used here are the ones the runtime actually writes (``sessions.py``:
``RECORD_TYPES``, ``record_assistant``, ``record_user``, ``record_system``;
``providers/base.py``: ``TextBlock.to_api``):

* assistant record: ``{"type": "assistant", "content": [{"type": "text", "text": ...}]}``
* tool result record: ``{"type": "tool_result", "content": [{"type": "tool_result", ...}]}``
* compaction record: ``{"type": "compact_boundary", "subtype": "compact_boundary", ...}``
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from silent_failure_detector import (
    OK,
    SILENT_FAILURE,
    SILENT_FAILURE_AT_SEAM,
    UNDECIDABLE,
    VERDICTS,
    classify_session,
    compaction_count,
    died_on_compaction_seam,
    ended_on_tool_result,
    ended_with_no_prose,
    final_event_type,
    has_prose,
    is_silent_failure,
    load_events,
    summarize_sessions,
)


def assistant(text: str) -> dict:
    """One assistant record carrying a text block."""
    return {
        "type": "assistant",
        "role": "assistant",
        "content": [{"type": "text", "text": text}],
    }


def tool_result(text: str = "tool output") -> dict:
    """One tool_result record, as the runtime writes it."""
    return {
        "type": "tool_result",
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": "t1", "content": text, "is_error": False}],
    }


def compaction(summary: str = "summary of earlier turns") -> dict:
    """One compaction record (``compact_boundary``)."""
    return {
        "type": "compact_boundary",
        "subtype": "compact_boundary",
        "content": summary,
        "data": {},
    }


def tool_use_only() -> dict:
    """An assistant record that carries a tool call but no text."""
    return {
        "type": "assistant",
        "role": "assistant",
        "content": [{"type": "tool_use", "id": "t1", "name": "read_file", "input": {}}],
    }


def write_session(directory: Path, name: str, events: list[dict]) -> str:
    """Write one session JSONL file and return its path."""
    path = directory / name
    lines = [json.dumps(event) for event in events]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


class VerdictVocabularyTests(unittest.TestCase):
    def test_the_four_verdicts_are_exactly_the_documented_set(self):
        self.assertEqual(
            set(VERDICTS),
            {OK, SILENT_FAILURE, SILENT_FAILURE_AT_SEAM, UNDECIDABLE},
        )


class ClassificationTests(unittest.TestCase):
    def test_a_session_that_ends_with_prose_is_ok(self):
        events = [assistant("working on it"), tool_result(), assistant("done")]
        self.assertEqual(classify_session(events), OK)
        self.assertTrue(has_prose(events))
        self.assertFalse(is_silent_failure(events))

    def test_a_session_with_no_prose_at_all_ending_on_a_tool_result_is_a_silent_failure(self):
        events = [tool_use_only(), tool_result()]
        self.assertEqual(classify_session(events), SILENT_FAILURE)
        self.assertTrue(is_silent_failure(events))
        self.assertFalse(has_prose(events))
        self.assertEqual(final_event_type(events), "tool_result")

    def test_a_session_that_talked_then_ended_on_a_tool_result_is_not_a_silent_failure(self):
        """The source's fail definition is about the whole stream, not the tail."""
        events = [assistant("here is the answer"), tool_result()]
        self.assertEqual(classify_session(events), OK)
        self.assertTrue(ended_on_tool_result(events))

    def test_a_dead_session_on_the_compaction_seam_is_flagged_as_a_seam_death(self):
        events = [assistant("starting"), compaction(), tool_result()]
        self.assertEqual(classify_session(events), SILENT_FAILURE_AT_SEAM)
        self.assertTrue(died_on_compaction_seam(events))
        self.assertEqual(compaction_count(events), 1)

    def test_prose_after_the_compaction_seam_means_the_session_did_not_die_there(self):
        events = [assistant("starting"), compaction(), assistant("still here"), tool_result()]
        self.assertEqual(classify_session(events), OK)
        self.assertFalse(died_on_compaction_seam(events))

    def test_a_compaction_seam_death_is_also_a_silent_failure_by_the_whole_stream_rule(self):
        """A seam death has no prose at all in the source's shapes, so both rules fire."""
        events = [compaction(), tool_result()]
        self.assertTrue(is_silent_failure(events))
        self.assertTrue(died_on_compaction_seam(events))
        # The seam shape wins the verdict.
        self.assertEqual(classify_session(events), SILENT_FAILURE_AT_SEAM)

    def test_an_empty_stream_is_undecidable_not_ok(self):
        self.assertEqual(classify_session([]), UNDECIDABLE)
        self.assertIsNone(final_event_type([]))
        self.assertEqual(compaction_count([]), 0)
        self.assertFalse(has_prose([]))

    def test_a_record_without_a_type_field_is_undecidable(self):
        self.assertEqual(classify_session([{"content": "no type here"}]), UNDECIDABLE)
        self.assertEqual(classify_session([assistant("hi"), {"no": "type"}]), UNDECIDABLE)

    def test_a_non_dict_record_is_undecidable(self):
        self.assertEqual(classify_session([assistant("hi"), "not a record"]), UNDECIDABLE)


class ProseRuleTests(unittest.TestCase):
    def test_whitespace_only_assistant_text_is_not_prose(self):
        events = [assistant("   \n\t  ")]
        self.assertFalse(has_prose(events))
        self.assertTrue(is_silent_failure(events))

    def test_a_tool_result_record_is_never_prose(self):
        events = [tool_result("a very chatty tool output that says things")]
        self.assertFalse(has_prose(events))
        self.assertTrue(is_silent_failure(events))

    def test_a_thinking_block_is_not_prose(self):
        events = [
            {
                "type": "assistant",
                "content": [{"type": "thinking", "thinking": "the user asked me to think"}],
            }
        ]
        self.assertFalse(has_prose(events))

    def test_an_assistant_record_with_a_tool_use_block_only_is_not_prose(self):
        events = [tool_use_only()]
        self.assertFalse(has_prose(events))
        self.assertTrue(is_silent_failure(events))

    def test_prose_anywhere_in_the_stream_counts(self):
        events = [assistant("said it early"), tool_use_only(), tool_result()]
        self.assertTrue(has_prose(events))
        self.assertFalse(is_silent_failure(events))

    def test_the_tail_measurement_reports_the_final_record_type(self):
        """The source's cheap metric: the event type of the final record."""
        self.assertTrue(ended_with_no_prose([assistant("said it"), tool_result()]))
        self.assertFalse(ended_with_no_prose([assistant("said it")]))
        self.assertTrue(ended_on_tool_result([assistant("said it"), tool_result()]))
        self.assertFalse(ended_on_tool_result([assistant("said it")]))
        self.assertEqual(final_event_type([assistant("x"), tool_result()]), "tool_result")
        self.assertEqual(final_event_type([assistant("x")]), "assistant")
        self.assertIsNone(final_event_type([]))


class CompactionCountTests(unittest.TestCase):
    def test_one_compaction_is_counted(self):
        events = [assistant("hi"), compaction(), tool_result()]
        self.assertEqual(compaction_count(events), 1)

    def test_two_compactions_are_counted(self):
        events = [compaction(), assistant("mid"), compaction(), tool_result()]
        self.assertEqual(compaction_count(events), 2)

    def test_three_or_more_compactions_are_counted(self):
        events = [compaction(), compaction(), compaction(), tool_result()]
        self.assertEqual(compaction_count(events), 3)

    def test_only_compact_boundary_records_count_as_compactions(self):
        events = [assistant("hi"), tool_result(), {"type": "informational", "content": "not a compaction"}]
        self.assertEqual(compaction_count(events), 0)

    def test_the_seam_is_the_last_compaction_not_the_first(self):
        """Prose after the *last* compaction means the session did not die on the seam."""
        events = [compaction(), tool_result(), assistant("recovered"), compaction(), tool_result()]
        self.assertEqual(compaction_count(events), 2)
        self.assertTrue(died_on_compaction_seam(events))
        self.assertEqual(classify_session(events), SILENT_FAILURE_AT_SEAM)


class FileReadingTests(unittest.TestCase):
    def test_a_missing_file_is_undecidable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "does-not-exist.jsonl"
            self.assertIsNone(load_events(path))

    def test_an_unparseable_file_is_undecidable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.jsonl"
            path.write_text('{"type": "assistant"}\nnot json at all\n', encoding="utf-8")
            self.assertIsNone(load_events(path))

    def test_an_empty_file_is_undecidable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.jsonl"
            path.write_text("", encoding="utf-8")
            self.assertEqual(load_events(path), [])
            self.assertEqual(classify_session(load_events(path)), UNDECIDABLE)

    def test_a_readable_session_file_classifies_from_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_session(Path(tmp), "s1.jsonl", [assistant("done"), tool_result()])
            events = load_events(path)
            self.assertEqual(classify_session(events), OK)

    def test_a_malformed_file_makes_the_summary_count_it_as_undecidable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.jsonl"
            path.write_text("{oops\n", encoding="utf-8")
            counts = summarize_sessions([str(path)])
            self.assertEqual(counts["total"], 1)
            self.assertEqual(counts["undecidable"], 1)
            self.assertEqual(counts["no_compaction"], 0)
            self.assertEqual(counts["silent_failures"], 0)


class SummaryTests(unittest.TestCase):
    def test_the_six_counts_match_a_hand_counted_fleet(self):
        """Ten sessions in the source's shape, counted by hand and by the detector."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            paths = []
            # 8 sessions, no compaction, ending with prose.
            for index in range(8):
                paths.append(
                    write_session(
                        directory,
                        f"ok-{index}.jsonl",
                        [assistant("thinking out loud"), tool_result(), assistant("the answer")],
                    )
                )
            paths.append(
                write_session(
                    directory,
                    "seam.jsonl",
                    [assistant("starting"), compaction(), tool_result()],
                )
            )
            # 1 session, no prose anywhere, ends on a tool result.
            paths.append(
                write_session(
                    directory,
                    "silent.jsonl",
                    [tool_use_only(), tool_result()],
                )
            )
            counts = summarize_sessions(paths)
            self.assertEqual(counts["total"], 10)
            self.assertEqual(counts["no_compaction"], 9)
            self.assertEqual(counts["compacted"], 1)
            self.assertEqual(counts["silent_failures"], 2)
            self.assertEqual(counts["seam_deaths"], 1)
            self.assertEqual(counts["undecidable"], 0)
            # The invariant that keeps undecidable off the success side.
            self.assertEqual(
                counts["no_compaction"] + counts["compacted"],
                counts["total"] - counts["undecidable"],
            )

    def test_the_seam_deaths_are_a_subset_of_the_silent_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            paths = [
                write_session(directory, "seam.jsonl", [compaction(), tool_result()]),
                write_session(directory, "silent.jsonl", [tool_use_only(), tool_result()]),
                write_session(directory, "ok.jsonl", [assistant("fine"), assistant("bye")]),
            ]
            counts = summarize_sessions(paths)
            self.assertLessEqual(counts["seam_deaths"], counts["silent_failures"])
            self.assertEqual(counts["seam_deaths"], 1)
            self.assertEqual(counts["silent_failures"], 2)

    def test_a_session_that_talked_and_then_ended_on_a_tool_result_counts_as_a_failure(self):
        """The source counts the final record's type: it ended with no prose."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            path = write_session(
                directory, "trailing.jsonl", [assistant("here is the answer"), tool_result()]
            )
            counts = summarize_sessions([path])
            self.assertEqual(counts["silent_failures"], 1)
            self.assertEqual(counts["seam_deaths"], 0)
            # But the session's verdict is still OK: it did talk.
            self.assertEqual(classify_session(load_events(path) or []), OK)

    def test_a_missing_file_is_counted_as_undecidable_and_not_as_a_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = write_session(
                Path(tmp), "ok.jsonl", [assistant("fine"), assistant("the answer")]
            )
            counts = summarize_sessions([good, str(Path(tmp) / "missing.jsonl")])
            self.assertEqual(counts["total"], 2)
            self.assertEqual(counts["undecidable"], 1)
            self.assertEqual(counts["no_compaction"], 1)
            self.assertEqual(counts["compacted"], 0)
            self.assertEqual(counts["silent_failures"], 0)

    def test_an_empty_path_list_summarizes_to_all_zeroes(self):
        counts = summarize_sessions([])
        self.assertEqual(
            counts,
            {
                "total": 0,
                "no_compaction": 0,
                "compacted": 0,
                "silent_failures": 0,
                "seam_deaths": 0,
                "undecidable": 0,
            },
        )


class SourceShapeTests(unittest.TestCase):
    def test_the_source_fleet_shape_reproduces_the_source_rates(self):
        """617 sessions: 522 with no compaction, 95 compacted, 5 with no prose.

        The detector is not asked to reproduce the source's fleet -- it is
        asked to produce the same *counting shape* from a synthetic fleet
        with the same shape, so the rates line up the way the source's do.
        """
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            paths = []
            for index in range(522):
                paths.append(
                    write_session(
                        directory,
                        f"plain-{index}.jsonl",
                        [assistant("hello"), tool_result(), assistant("bye")],
                    )
                )
            # 95 compacted sessions: 64 with one compaction, 27 with two, 4 with three.
            # 5 of them died with no prose anywhere (3 of the 1-compaction ones,
            # 2 of the 2-compaction ones); 4 of those 5 died on the seam --
            # the fifth's file simply ends after the compaction.
            compacted_spec = [1] * 64 + [2] * 27 + [3] * 4
            failures = {0, 1, 2, 3, 4}  # indices within the compacted fleet
            seam_failures = {0, 1, 2, 3}
            for index, count in enumerate(compacted_spec):
                events: list[dict] = []
                if index in failures:
                    # No prose at all in the stream: the source's fail shape.
                    events.extend(compaction() for _ in range(count))
                    if index in seam_failures:
                        events.append(tool_result())
                    else:
                        events.append({"type": "informational", "content": "run stopped"})
                else:
                    events.append(assistant("working"))
                    events.extend(compaction() for _ in range(count))
                    events.append(assistant("still going"))
                paths.append(
                    write_session(directory, f"comp-{index}.jsonl", events)
                )
            counts = summarize_sessions(paths)
            self.assertEqual(counts["total"], 617)
            self.assertEqual(counts["no_compaction"], 522)
            self.assertEqual(counts["compacted"], 95)
            self.assertEqual(counts["silent_failures"], 5)
            self.assertEqual(counts["seam_deaths"], 4)
            # 5 failures among 95 compacted sessions = 5.26% -> the source's 5.3%.
            self.assertAlmostEqual(
                100.0 * counts["silent_failures"] / counts["compacted"], 5.3, places=1
            )
            # 0 failures among the 522 that never compacted.
            self.assertEqual(
                sum(
                    1
                    for path in paths[:522]
                    if classify_session(load_events(path) or []) != OK
                ),
                0,
            )
            # The fifth failure is a silent failure but not a seam death.
            self.assertEqual(classify_session(load_events(paths[522 + 4]) or []), SILENT_FAILURE)
            # Every one of the five failures carries no prose at all.
            self.assertEqual(
                sum(
                    1
                    for path in paths[522:]
                    if is_silent_failure(load_events(path) or [])
                ),
                5,
            )
