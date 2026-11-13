"""Stuck detector: five repetition patterns, semantic comparison, the window rule.

The patterns and their thresholds come from the OpenHands SDK guide "Stuck
Detector" (https://docs.openhands.dev/sdk/guides/agent-stuck-detector).  The
input here is Northstar's own session event stream: the records a
``SessionStore`` writes, read back from the JSONL transcript.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import support  # noqa: F401
from support import RuntimeTestCase

import stuck_detector
from stuck_detector import (
    DEFAULT_THRESHOLDS,
    PATTERN_ALTERNATING,
    PATTERN_CONTEXT_WINDOW_ERRORS,
    PATTERN_MONOLOGUE,
    PATTERN_REPEAT_ACTION_ERROR,
    PATTERN_REPEAT_ACTION_OBSERVATION,
    StuckDetector,
    StuckThresholds,
    detect,
    is_stuck,
)


def assistant_tool(tool_id: str, name: str, tool_input: dict, *, agent: str = "main", thinking: str = "") -> dict:
    """One assistant record carrying a single tool_use block."""
    content: list[dict] = []
    if thinking:
        content.append({"type": "thinking", "thinking": thinking})
    content.append({"type": "tool_use", "id": tool_id, "name": name, "input": tool_input})
    return {"type": "assistant", "agent": agent, "role": "assistant", "content": content}


def tool_result(tool_id: str, content: str, *, is_error: bool = False, tool_name: str = "") -> dict:
    """One tool_result record, as the session recorder writes it."""
    block: dict = {"type": "tool_result", "tool_use_id": tool_id, "content": content, "is_error": is_error}
    if tool_name:
        block["tool_name"] = tool_name
    return {"type": "tool_result", "agent": "main", "role": "user", "content": [block]}


def assistant_text(text: str, *, agent: str = "main") -> dict:
    return {"type": "assistant", "agent": agent, "role": "assistant", "content": [{"type": "text", "text": text}]}


def user_prompt(text: str, *, is_meta: bool = False) -> dict:
    return {
        "type": "user_prompt",
        "agent": "main",
        "role": "user",
        "is_meta": is_meta,
        "content": [{"type": "text", "text": text}],
    }


def assistant_tool_with_thought(tool_id: str, name: str, tool_input: dict, thought: str) -> dict:
    """One assistant record carrying a thinking block and a tool_use block."""
    return {
        "type": "assistant",
        "agent": "main",
        "role": "assistant",
        "content": [
            {"type": "thinking", "thinking": thought},
            {"type": "tool_use", "id": tool_id, "name": name, "input": tool_input},
        ],
    }


def action_observation_pair(tool_id: str, name: str, tool_input: dict, observation: str, *, is_error: bool = False) -> list[dict]:
    return [
        assistant_tool(tool_id, name, tool_input),
        tool_result(tool_id, observation, is_error=is_error),
    ]


class ThresholdTests(unittest.TestCase):
    def test_defaults_match_the_openhands_document(self):
        """4+ action-observation, 3+ action-error, 3+ monologue, 6+ cycles."""
        self.assertEqual(DEFAULT_THRESHOLDS.repeat_action_observation, 4)
        self.assertEqual(DEFAULT_THRESHOLDS.repeat_action_error, 3)
        self.assertEqual(DEFAULT_THRESHOLDS.monologue, 3)
        self.assertEqual(DEFAULT_THRESHOLDS.alternating_cycles, 6)
        # The OpenHands document gives no number for context-window errors;
        # 3 is Northstar's own threshold.
        self.assertEqual(DEFAULT_THRESHOLDS.context_window_errors, 3)

    def test_thresholds_are_configurable_and_frozen(self):
        thresholds = StuckThresholds(repeat_action_observation=2)
        self.assertEqual(thresholds.repeat_action_observation, 2)
        self.assertEqual(thresholds.repeat_action_error, 3)
        with self.assertRaises(Exception):
            thresholds.repeat_action_observation = 9  # type: ignore[misc]


class EmptyAndWindowTests(unittest.TestCase):
    def test_empty_history_is_not_stuck_and_does_not_raise(self):
        verdict = detect([])
        self.assertFalse(verdict.is_stuck)
        self.assertEqual(verdict.pattern, "")
        self.assertIsNone(verdict.evidence_pointer)

    def test_user_message_resets_the_window(self):
        records: list[dict] = []
        for index in range(3):
            records.extend(action_observation_pair(f"tu{index}", "Bash", {"command": "ls"}, "a b c"))
        records.append(user_prompt("now do something else"))
        verdict = detect(records)
        self.assertFalse(verdict.is_stuck)
        self.assertEqual(verdict.pattern, "")

    def test_only_the_history_after_the_last_user_message_is_examined(self):
        """Three repeats before the user turn, three after: not stuck."""
        records: list[dict] = []
        for index in range(3):
            records.extend(action_observation_pair(f"a{index}", "Bash", {"command": "ls"}, "same"))
        records.append(user_prompt("go on"))
        for index in range(3):
            records.extend(action_observation_pair(f"b{index}", "Bash", {"command": "ls"}, "same"))
        self.assertFalse(detect(records).is_stuck)

    def test_meta_prompt_does_not_reset_the_window(self):
        """A meta prompt is host context, not user input."""
        records: list[dict] = []
        for index in range(3):
            records.extend(action_observation_pair(f"a{index}", "Bash", {"command": "ls"}, "same"))
        records.append(user_prompt("[host context]", is_meta=True))
        records.extend(action_observation_pair("b0", "Bash", {"command": "ls"}, "same"))
        self.assertTrue(detect(records).is_stuck)


class RepeatActionObservationTests(unittest.TestCase):
    """OpenHands: "The same action produces the same observation repeatedly (4+ times)"."""

    def test_four_identical_pairs_are_stuck(self):
        records: list[dict] = []
        for index in range(4):
            records.extend(action_observation_pair(f"tu{index}", "Bash", {"command": "ls"}, "a b c"))
        verdict = detect(records)
        self.assertTrue(verdict.is_stuck)
        self.assertEqual(verdict.pattern, PATTERN_REPEAT_ACTION_OBSERVATION)
        self.assertEqual(verdict.evidence_pointer.count, 4)

    def test_three_identical_pairs_are_not_stuck(self):
        records: list[dict] = []
        for index in range(3):
            records.extend(action_observation_pair(f"tu{index}", "Bash", {"command": "ls"}, "a b c"))
        verdict = detect(records)
        self.assertFalse(verdict.is_stuck)

    def test_the_fifth_identical_pair_is_also_stuck(self):
        records: list[dict] = []
        for index in range(5):
            records.extend(action_observation_pair(f"tu{index}", "Bash", {"command": "ls"}, "a b c"))
        verdict = detect(records)
        self.assertTrue(verdict.is_stuck)
        self.assertEqual(verdict.evidence_pointer.count, 5)

    def test_a_different_observation_breaks_the_run(self):
        records: list[dict] = []
        for index in range(4):
            observation = "a b c" if index < 3 else "totally different"
            records.extend(action_observation_pair(f"tu{index}", "Bash", {"command": "ls"}, observation))
        self.assertFalse(detect(records).is_stuck)


class RepeatActionErrorTests(unittest.TestCase):
    """OpenHands: "The same action repeatedly results in errors (3+ times)"."""

    def test_three_identical_errors_are_stuck(self):
        records: list[dict] = []
        for index in range(3):
            records.extend(
                action_observation_pair(f"tu{index}", "Bash", {"command": "rm x"}, "boom", is_error=True)
            )
        verdict = detect(records)
        self.assertTrue(verdict.is_stuck)
        self.assertEqual(verdict.pattern, PATTERN_REPEAT_ACTION_ERROR)
        self.assertEqual(verdict.evidence_pointer.count, 3)

    def test_two_identical_errors_are_not_stuck(self):
        records: list[dict] = []
        for index in range(2):
            records.extend(
                action_observation_pair(f"tu{index}", "Bash", {"command": "rm x"}, "boom", is_error=True)
            )
        self.assertFalse(detect(records).is_stuck)

    def test_a_different_action_error_does_not_accumulate(self):
        records: list[dict] = []
        for index in range(3):
            records.extend(
                action_observation_pair(f"tu{index}", "Bash", {"command": f"cmd{index}"}, "boom", is_error=True)
            )
        self.assertFalse(detect(records).is_stuck)


class MonologueTests(unittest.TestCase):
    """OpenHands: "The agent sends multiple consecutive messages without user input or meaningful progress (3+ messages)"."""

    def test_three_consecutive_messages_are_stuck(self):
        records = [assistant_text("one"), assistant_text("two"), assistant_text("three")]
        verdict = detect(records)
        self.assertTrue(verdict.is_stuck)
        self.assertEqual(verdict.pattern, PATTERN_MONOLOGUE)
        self.assertEqual(verdict.evidence_pointer.count, 3)

    def test_two_consecutive_messages_are_not_stuck(self):
        self.assertFalse(detect([assistant_text("one"), assistant_text("two")]).is_stuck)

    def test_a_successful_tool_call_breaks_the_monologue(self):
        records: list[dict] = [
            assistant_text("one"),
            assistant_text("two"),
            assistant_tool("tu0", "Bash", {"command": "ls"}),
            tool_result("tu0", "a b c"),
            assistant_text("three"),
        ]
        self.assertFalse(detect(records).is_stuck)

    def test_a_failed_tool_call_is_not_progress(self):
        records: list[dict] = [
            assistant_text("one"),
            assistant_tool("tu0", "Bash", {"command": "rm x"}),
            tool_result("tu0", "boom", is_error=True),
            assistant_text("two"),
            assistant_text("three"),
        ]
        self.assertTrue(detect(records).is_stuck)


class AlternatingTests(unittest.TestCase):
    """OpenHands: "Two different action-observation pairs alternate in a ping-pong pattern (6+ cycles)".

    Northstar counts complete cycles: A-B-A-B for 6 cycles is 12 steps.
    """

    def _alternating(self, cycles: int) -> list[dict]:
        records: list[dict] = []
        for index in range(cycles):
            records.extend(action_observation_pair(f"a{index}", "Read", {"path": "a.py"}, "alpha"))
            records.extend(action_observation_pair(f"b{index}", "Grep", {"pattern": "x"}, "beta"))
        return records

    def test_six_complete_cycles_are_stuck(self):
        verdict = detect(self._alternating(6))
        self.assertTrue(verdict.is_stuck)
        self.assertEqual(verdict.pattern, PATTERN_ALTERNATING)
        self.assertEqual(verdict.evidence_pointer.count, 6)

    def test_five_complete_cycles_are_not_stuck(self):
        self.assertFalse(detect(self._alternating(5)).is_stuck)

    def test_eleven_steps_are_five_cycles_and_a_half(self):
        """Six cycles needs 12 steps; 11 steps is not enough."""
        records = self._alternating(5)
        records.extend(action_observation_pair("a5", "Read", {"path": "a.py"}, "alpha"))
        self.assertFalse(detect(records).is_stuck)

    def test_a_third_distinct_pair_breaks_the_ping_pong(self):
        """A-B-C repeated: no two-key alternation ever reaches 12 steps."""
        records: list[dict] = []
        for index in range(6):
            records.extend(action_observation_pair(f"a{index}", "Read", {"path": "a.py"}, "alpha"))
            records.extend(action_observation_pair(f"b{index}", "Grep", {"pattern": "x"}, "beta"))
            records.extend(action_observation_pair(f"c{index}", "Write", {"path": "c.py"}, "gamma"))
        self.assertFalse(detect(records).is_stuck)


class ContextWindowErrorTests(unittest.TestCase):
    """OpenHands names the pattern but gives no threshold; 3 is Northstar's."""

    def test_three_context_window_errors_are_stuck(self):
        # Different commands each time, so the repeated *action* error pattern
        # does not trip first: what repeats here is the error kind.
        records: list[dict] = []
        for index in range(3):
            records.extend(
                action_observation_pair(
                    f"tu{index}", "Bash", {"command": f"cmd{index}"},
                    "Error: prompt is too long: 210000 tokens > 200000 maximum",
                    is_error=True,
                )
            )
        verdict = detect(records)
        self.assertTrue(verdict.is_stuck)
        self.assertEqual(verdict.pattern, PATTERN_CONTEXT_WINDOW_ERRORS)
        self.assertEqual(verdict.evidence_pointer.count, 3)

    def test_two_context_window_errors_are_not_stuck(self):
        records: list[dict] = []
        for index in range(2):
            records.extend(
                action_observation_pair(
                    f"tu{index}", "Bash", {"command": "x"},
                    "Error: context window exceeded",
                    is_error=True,
                )
            )
        self.assertFalse(detect(records).is_stuck)

    def test_ordinary_errors_are_not_context_window_errors(self):
        records: list[dict] = []
        for index in range(4):
            records.extend(
                action_observation_pair(f"tu{index}", "Bash", {"command": f"c{index}"}, "boom", is_error=True)
            )
        verdict = detect(records)
        self.assertFalse(verdict.is_stuck)

    def test_the_threshold_is_configurable(self):
        records: list[dict] = []
        for index in range(2):
            records.extend(
                action_observation_pair(
                    f"tu{index}", "Bash", {"command": "x"},
                    "Error: context window exceeded",
                    is_error=True,
                )
            )
        thresholds = StuckThresholds(context_window_errors=2)
        verdict = detect(records, thresholds)
        self.assertTrue(verdict.is_stuck)
        self.assertEqual(verdict.pattern, PATTERN_CONTEXT_WINDOW_ERRORS)


class SemanticComparisonTests(unittest.TestCase):
    """OpenHands: "compares events based on their semantic content rather than object identity"."""

    def test_changing_the_tool_call_id_does_not_change_the_verdict(self):
        records: list[dict] = []
        for index in range(4):
            records.extend(action_observation_pair(f"different-id-{index}", "Bash", {"command": "ls"}, "a b c"))
        self.assertTrue(detect(records).is_stuck)

    def test_changing_the_timestamp_does_not_change_the_verdict(self):
        records: list[dict] = []
        for index in range(4):
            records.extend(action_observation_pair(f"tu{index}", "Bash", {"command": "ls"}, "a b c"))
            records[-2]["ts"] = f"2026-11-14T00:00:{index:02d}Z"
        self.assertTrue(detect(records).is_stuck)

    def test_changing_the_input_metrics_does_not_change_the_verdict(self):
        records: list[dict] = []
        for index in range(4):
            records.extend(
                action_observation_pair(
                    f"tu{index}", "Bash",
                    {"command": "ls", "metrics": {"latency_ms": index * 100}, "turn_index": index},
                    "a b c",
                )
            )
        self.assertTrue(detect(records).is_stuck)

    def test_changing_the_action_content_does_change_the_verdict(self):
        records: list[dict] = []
        for index in range(4):
            records.extend(action_observation_pair(f"tu{index}", "Bash", {"command": f"ls {index}"}, "a b c"))
        self.assertFalse(detect(records).is_stuck)

    def test_changing_the_observation_content_does_change_the_verdict(self):
        records: list[dict] = []
        for index in range(4):
            records.extend(action_observation_pair(f"tu{index}", "Bash", {"command": "ls"}, f"listing {index}"))
        self.assertFalse(detect(records).is_stuck)

    def test_changing_the_tool_name_does_change_the_verdict(self):
        records: list[dict] = []
        for index in range(4):
            records.extend(action_observation_pair(f"tu{index}", f"Tool{index}", {"command": "ls"}, "a b c"))
        self.assertFalse(detect(records).is_stuck)

    def test_the_thought_is_part_of_the_action_key(self):
        """The OpenHands action key includes the thought."""
        records: list[dict] = []
        for index in range(3):
            records.extend(
                action_observation_pair(f"tu{index}", "Bash", {"command": "ls"}, "a b c")
            )
        records.append(assistant_tool_with_thought("tu3", "Bash", {"command": "ls"}, "something else entirely"))
        records.append(tool_result("tu3", "a b c"))
        # The fourth differs in thought, so the run of identical action keys
        # is only three long.
        self.assertFalse(detect(records).is_stuck)

    def test_the_same_thought_keeps_the_run_together(self):
        records: list[dict] = []
        for index in range(4):
            records.append(
                assistant_tool_with_thought(f"tu{index}", "Bash", {"command": "ls"}, "checking the listing")
            )
            records.append(tool_result(f"tu{index}", "a b c"))
        self.assertTrue(detect(records).is_stuck)

    def test_the_message_key_is_content_and_source(self):
        """Two agents saying the same thing are not the same message."""
        records = [
            assistant_text("same words", agent="main"),
            assistant_text("same words", agent="main"),
            assistant_text("same words", agent="subagent"),
        ]
        self.assertFalse(detect(records).is_stuck)


class FailClosedTests(unittest.TestCase):
    """An event that cannot be normalised does not participate in matching."""

    def test_a_tool_use_without_a_name_is_ignored(self):
        records: list[dict] = []
        for index in range(4):
            records.append(
                {"type": "assistant", "agent": "main", "content": [{"type": "tool_use", "id": f"tu{index}", "input": {"command": "ls"}}]}
            )
            records.append(tool_result(f"tu{index}", "a b c"))
        verdict = detect(records)
        self.assertFalse(verdict.is_stuck)

    def test_an_unnormalisable_event_does_not_stand_in_for_a_repeat(self):
        """Three real repeats plus a broken event is still only three."""
        records: list[dict] = []
        for index in range(3):
            records.extend(action_observation_pair(f"tu{index}", "Bash", {"command": "ls"}, "a b c"))
        records.append({"type": "assistant", "agent": "main", "content": [{"type": "tool_use", "id": "bad"}]})
        records.append(tool_result("bad", "a b c"))
        self.assertFalse(detect(records).is_stuck)

    def test_an_empty_tool_result_content_is_not_a_observation_key(self):
        records: list[dict] = []
        for index in range(4):
            records.extend(action_observation_pair(f"tu{index}", "Bash", {"command": "ls"}, ""))
        verdict = detect(records)
        # An empty observation normalises to the empty string; four of them are
        # still four identical observations.
        self.assertTrue(verdict.is_stuck)

    def test_a_non_dict_record_is_skipped(self):
        records: list[dict] = ["not a record", 42, None]  # type: ignore[list-item]
        self.assertFalse(detect(records).is_stuck)


class VerdictShapeTests(unittest.TestCase):
    """The verdict carries the pattern, the evidence and where the evidence is."""

    def test_the_verdict_names_the_pattern_and_points_at_the_evidence(self):
        records: list[dict] = []
        for index in range(4):
            records.extend(action_observation_pair(f"tu{index}", "Bash", {"command": "ls"}, "a b c"))
        verdict = detect(records)
        self.assertTrue(verdict.is_stuck)
        self.assertEqual(verdict.pattern, PATTERN_REPEAT_ACTION_OBSERVATION)
        self.assertTrue(verdict.summary)
        self.assertTrue(verdict.evidence)
        pointer = verdict.evidence_pointer
        self.assertIsNotNone(pointer)
        assert pointer is not None
        self.assertEqual(pointer.count, 4)
        self.assertGreaterEqual(pointer.first_index, 0)
        self.assertGreater(pointer.last_index, pointer.first_index)
        self.assertEqual(verdict.as_dict()["pattern"], PATTERN_REPEAT_ACTION_OBSERVATION)

    def test_is_stuck_is_a_pure_query(self):
        """Two queries over the same history give the same answer."""
        records: list[dict] = []
        for index in range(4):
            records.extend(action_observation_pair(f"tu{index}", "Bash", {"command": "ls"}, "a b c"))
        detector = StuckDetector()
        first = detector.is_stuck(records)
        second = detector.is_stuck(records)
        self.assertEqual(first, second)
        self.assertTrue(is_stuck(records))

    def test_the_detector_does_not_halt_and_does_not_mutate_the_history(self):
        records: list[dict] = []
        for index in range(4):
            records.extend(action_observation_pair(f"tu{index}", "Bash", {"command": "ls"}, "a b c"))
        before = [dict(record) for record in records]
        StuckDetector().detect(records)
        self.assertEqual(records, before)
        # The verdict is a report, not an action: it has no stop/halt member.
        verdict = StuckDetector().detect(records)
        self.assertFalse(hasattr(verdict, "halt"))
        self.assertFalse(hasattr(verdict, "stop"))

    def test_a_stuck_verdict_carries_no_halt_action(self):
        """The caller decides what to do; the detector only reports."""
        verdict = detect([
            assistant_text("a"), assistant_text("b"), assistant_text("c"),
        ])
        self.assertTrue(verdict.is_stuck)
        self.assertNotIn("halt", verdict.as_dict())
        self.assertNotIn("action", verdict.as_dict())

    def test_the_public_names_are_the_documented_ones(self):
        self.assertEqual(
            stuck_detector.STUCK_PATTERNS,
            (
                PATTERN_REPEAT_ACTION_OBSERVATION,
                PATTERN_REPEAT_ACTION_ERROR,
                PATTERN_MONOLOGUE,
                PATTERN_ALTERNATING,
                PATTERN_CONTEXT_WINDOW_ERRORS,
            ),
        )

    def test_the_verdict_and_its_pointer_are_public_types(self):
        verdict = StuckDetector().detect([
            assistant_text("a"), assistant_text("b"), assistant_text("c"),
        ])
        self.assertIsInstance(verdict, stuck_detector.StuckVerdict)
        self.assertIsInstance(verdict.evidence_pointer, stuck_detector.EvidencePointer)
        pointer = verdict.evidence_pointer
        assert pointer is not None
        self.assertEqual(
            pointer.as_dict(),
            {"first_index": pointer.first_index, "last_index": pointer.last_index, "count": pointer.count},
        )

    def test_the_normalised_events_are_exposed_for_inspection(self):
        """A caller can look at the keys the detector compared."""
        records = action_observation_pair("tu0", "Bash", {"command": "ls"}, "a b c")
        events = StuckDetector().normalised_events(records)
        kinds = {event.kind for event in events}
        self.assertIn("action", kinds)
        self.assertIn("observation", kinds)
        action = next(event for event in events if event.kind == "action")
        self.assertEqual(action.action_key[0], "Bash")
        observation = next(event for event in events if event.kind == "observation")
        self.assertEqual(observation.observation_key[1], "Bash")


class RealTranscriptTests(RuntimeTestCase):
    """The three real paths, driven through a real session transcript.

    The records are written by a real ``SessionStore`` into a real JSONL file
    and read back, so the detector sees exactly the records a Northstar run
    would leave behind.
    """

    def _store(self):
        from sessions import SessionStore

        directory = self.temp_dir()
        return SessionStore(directory=directory, session_id="stuck-test")

    def _write_assistant_tool(self, store, tool_id: str, name: str, tool_input: dict) -> None:
        store.append("assistant", {
            "agent": "main",
            "role": "assistant",
            "content": [{"type": "tool_use", "id": tool_id, "name": name, "input": tool_input}],
        })

    def _write_result(self, store, tool_id: str, content: str, *, is_error: bool = False) -> None:
        store.append("tool_result", {
            "agent": "main",
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": tool_id, "content": content, "is_error": is_error}],
        })

    def _records(self, store):
        records, _dropped = store.read()
        return records

    def test_path_a_five_identical_ls_commands_are_stuck(self):
        """The OpenHands example: the same ls five times is caught at the fourth."""
        store = self._store()
        for index in range(5):
            self._write_assistant_tool(store, f"tu{index}", "Bash", {"command": "ls"})
            self._write_result(store, f"tu{index}", "README.md setup.py")
        verdict = detect(self._records(store))
        self.assertTrue(verdict.is_stuck)
        self.assertEqual(verdict.pattern, PATTERN_REPEAT_ACTION_OBSERVATION)
        self.assertEqual(verdict.evidence_pointer.count, 5)

    def test_path_a_three_identical_ls_commands_are_not_stuck(self):
        store = self._store()
        for index in range(3):
            self._write_assistant_tool(store, f"tu{index}", "Bash", {"command": "ls"})
            self._write_result(store, f"tu{index}", "README.md setup.py")
        self.assertFalse(detect(self._records(store)).is_stuck)

    def test_path_b_the_same_action_failing_three_times_is_stuck(self):
        store = self._store()
        for index in range(3):
            self._write_assistant_tool(store, f"tu{index}", "Bash", {"command": "pytest -q"})
            self._write_result(store, f"tu{index}", "ERROR: collection failed", is_error=True)
        verdict = detect(self._records(store))
        self.assertTrue(verdict.is_stuck)
        self.assertEqual(verdict.pattern, PATTERN_REPEAT_ACTION_ERROR)

    def test_path_c_normal_alternating_work_is_not_stuck(self):
        """Different actions, different observations, real progress."""
        store = self._store()
        steps = [
            ("Read", {"path": "a.py"}, "print('a')"),
            ("Read", {"path": "b.py"}, "print('b')"),
            ("Edit", {"path": "a.py"}, "print('a2')"),
            ("Read", {"path": "c.py"}, "print('c')"),
            ("Edit", {"path": "b.py"}, "print('b2')"),
            ("Read", {"path": "d.py"}, "print('d')"),
        ]
        for index, (name, tool_input, observation) in enumerate(steps):
            self._write_assistant_tool(store, f"tu{index}", name, tool_input)
            self._write_result(store, f"tu{index}", observation)
        verdict = detect(self._records(store))
        self.assertFalse(verdict.is_stuck)
        self.assertEqual(verdict.pattern, "")

    def test_path_d_a_monologue_is_stuck(self):
        store = self._store()
        for text in ("let me think", "still thinking", "almost there"):
            store.append("assistant", {
                "agent": "main",
                "role": "assistant",
                "content": [{"type": "text", "text": text}],
            })
        verdict = detect(self._records(store))
        self.assertTrue(verdict.is_stuck)
        self.assertEqual(verdict.pattern, PATTERN_MONOLOGUE)

    def test_path_e_an_alternating_ping_pong_is_stuck(self):
        store = self._store()
        for index in range(6):
            self._write_assistant_tool(store, f"a{index}", "Read", {"path": "a.py"})
            self._write_result(store, f"a{index}", "alpha")
            self._write_assistant_tool(store, f"b{index}", "Grep", {"pattern": "beta"})
            self._write_result(store, f"b{index}", "beta")
        verdict = detect(self._records(store))
        self.assertTrue(verdict.is_stuck)
        self.assertEqual(verdict.pattern, PATTERN_ALTERNATING)
        self.assertEqual(verdict.evidence_pointer.count, 6)

    def test_a_user_prompt_in_a_real_transcript_resets_the_window(self):
        store = self._store()
        for index in range(3):
            self._write_assistant_tool(store, f"a{index}", "Bash", {"command": "ls"})
            self._write_result(store, f"a{index}", "README.md")
        store.append("user_prompt", {
            "agent": "main",
            "role": "user",
            "content": [{"type": "text", "text": "now something else"}],
        })
        for index in range(3):
            self._write_assistant_tool(store, f"b{index}", "Bash", {"command": "ls"})
            self._write_result(store, f"b{index}", "README.md")
        self.assertFalse(detect(self._records(store)).is_stuck)
