"""Compaction boundary detection. The single most dangerous invariant here: cutting
in the wrong place leaves an orphaned ``tool_use`` and the API rejects the request.
"""
from __future__ import annotations

import unittest

import support  # noqa: F401
from support import RuntimeTestCase, text_turn, tool_turn

from compaction import (
    CompactionOutcome,
    compact,
    estimate_transcript_tokens,
    extractive_summary,
    is_safe_cut,
    latest_safe_cut,
    pending_tool_uses,
    rollover,
    safe_cuts,
    should_compact,
)
from providers.base import AssistantMessage, SystemMessage, TextBlock, ToolResultBlock, ToolUseBlock, UserMessage


def assistant_with_call(call_id: str, name: str = "Read") -> AssistantMessage:
    return AssistantMessage(content=(TextBlock(text="let me look"), ToolUseBlock(id=call_id, name=name, input={"path": "a"})))


def user_with_result(call_id: str, text: str = "result") -> UserMessage:
    return UserMessage(content=(ToolResultBlock(tool_use_id=call_id, content=text),))


class BoundaryTests(unittest.TestCase):
    def test_a_completed_exchange_is_a_safe_cut(self):
        transcript = [
            UserMessage.text_block("start"),
            assistant_with_call("t1"),
            user_with_result("t1"),
            UserMessage.text_block("next question"),
        ]
        self.assertTrue(is_safe_cut(transcript, 3))
        self.assertTrue(is_safe_cut(transcript, 0))
        self.assertTrue(is_safe_cut(transcript, len(transcript)))

    def test_cutting_after_an_unanswered_tool_use_is_unsafe(self):
        transcript = [UserMessage.text_block("start"), assistant_with_call("t1")]
        self.assertFalse(is_safe_cut(transcript, 2), "the tool_use would lose its tool_result")
        self.assertTrue(is_safe_cut(transcript, 1), "cutting before the assistant turn is legal")
        self.assertEqual(pending_tool_uses(transcript), ("t1",))

    def test_cutting_before_a_pending_tool_result_is_unsafe(self):
        transcript = [assistant_with_call("t1"), user_with_result("t1"), UserMessage.text_block("more")]
        # Cutting at 1 keeps a tool_result whose tool_use is in the summarized prefix.
        self.assertFalse(is_safe_cut(transcript, 1))
        self.assertTrue(is_safe_cut(transcript, 2))

    def test_parallel_tool_calls_are_only_safe_once_every_result_lands(self):
        unanswered = [
            UserMessage.text_block("go"),
            AssistantMessage(
                content=(ToolUseBlock(id="a", name="Read", input={}), ToolUseBlock(id="b", name="Read", input={}))
            ),
            UserMessage(content=(ToolResultBlock(tool_use_id="a", content="first"),)),
        ]
        self.assertFalse(is_safe_cut(unanswered, 2))
        self.assertFalse(is_safe_cut(unanswered, 3))
        answered = unanswered + [UserMessage(content=(ToolResultBlock(tool_use_id="b", content="second"),))]
        self.assertTrue(is_safe_cut(answered, 4))
        self.assertFalse(is_safe_cut(answered, 3), "one result still cannot cover two calls")

    def test_out_of_range_cuts_are_rejected(self):
        transcript = [UserMessage.text_block("only")]
        self.assertFalse(is_safe_cut(transcript, -1))
        self.assertFalse(is_safe_cut(transcript, 99))

    def test_latest_safe_cut_respects_both_bounds(self):
        transcript = [UserMessage.text_block("q"), assistant_with_call("t1"), user_with_result("t1"), UserMessage.text_block("q2")]
        self.assertEqual(latest_safe_cut(transcript), 4)
        self.assertEqual(latest_safe_cut(transcript, max_cut=2), 1)
        self.assertIsNone(latest_safe_cut(transcript, max_cut=2, min_cut=2))
        self.assertEqual(latest_safe_cut([UserMessage.text_block("q"), assistant_with_call("t1")], max_cut=1), 1)
        self.assertIsNone(latest_safe_cut([assistant_with_call("t1")], max_cut=1, min_cut=1))

    def test_safe_cuts_enumerates_only_legal_positions(self):
        transcript = [UserMessage.text_block("q"), assistant_with_call("t1"), user_with_result("t1")]
        self.assertEqual(safe_cuts(transcript), (0, 1, 3))

    def test_pending_tool_uses_tracks_pairing(self):
        transcript = [assistant_with_call("t1"), user_with_result("t1"), assistant_with_call("t2")]
        self.assertEqual(pending_tool_uses(transcript), ("t2",))


class CompactionOutcomeTests(unittest.TestCase):
    def build(self, pairs: int = 4) -> list:
        transcript = [UserMessage.text_block("original question")]
        for index in range(pairs):
            transcript.append(assistant_with_call(f"t{index}"))
            transcript.append(user_with_result(f"t{index}", f"output {index}"))
        return transcript

    def test_below_threshold_nothing_happens(self):
        transcript = self.build(1)
        outcome = compact(transcript, threshold_tokens=100_000)
        self.assertFalse(outcome.performed)
        self.assertEqual(outcome.transcript, tuple(transcript))
        self.assertIn("below the compaction threshold", outcome.reason)

    def test_compaction_keeps_the_tail_and_inserts_a_boundary(self):
        transcript = self.build(6)
        outcome = compact(transcript, force=True, keep_messages=2)
        self.assertTrue(outcome.performed, outcome.reason)
        self.assertGreater(outcome.dropped_messages, 0)
        self.assertIsInstance(outcome.transcript[0], SystemMessage)
        self.assertEqual(outcome.transcript[0].subtype, "compact_boundary")
        self.assertEqual(outcome.transcript[1:], tuple(transcript[-2:]))
        self.assertLess(outcome.tokens_after, outcome.tokens_before)
        self.assertIn("output 0", outcome.summary)

    def test_no_dangling_blocks_survive_compaction(self):
        for pairs in range(1, 8):
            for keep in range(1, 6):
                with self.subTest(pairs=pairs, keep=keep):
                    transcript = self.build(pairs)
                    outcome = compact(transcript, force=True, keep_messages=keep)
                    if not outcome.performed:
                        continue
                    # Compaction may only remove *completed* exchanges: whatever was
                    # still pending before the cut is still pending after it.
                    self.assertEqual(
                        pending_tool_uses(outcome.transcript), pending_tool_uses(transcript[outcome.cut :])
                    )
                    self.assertFalse(
                        any(
                            isinstance(message, UserMessage) and message.tool_results and not message.text
                            for message in outcome.transcript[1:2]
                        ),
                        "the kept tail must not begin with an orphaned tool_result",
                    )

    def test_a_transcript_whose_head_is_an_unresolved_exchange_refuses_to_compact(self):
        # The only legal cut here is index 1, which would leave the retained tail
        # starting with a tool_use whose result was summarized away.
        transcript = [assistant_with_call("t1"), user_with_result("t1")]
        outcome = compact(transcript, force=True, keep_messages=1)
        self.assertFalse(outcome.performed)
        self.assertIn("no safe compaction boundary", outcome.reason)
        self.assertEqual(outcome.transcript, tuple(transcript))

    def test_compaction_never_changes_the_pending_tool_use_set(self):
        for pairs, keep in ((1, 1), (2, 2), (4, 2), (6, 4)):
            with self.subTest(pairs=pairs, keep=keep):
                transcript = self.build(pairs)
                outcome = compact(transcript, force=True, keep_messages=keep)
                if not outcome.performed:
                    continue
                self.assertEqual(
                    pending_tool_uses(outcome.transcript),
                    pending_tool_uses(transcript[outcome.cut :]),
                )

    def test_a_transcript_shorter_than_the_retained_tail_is_left_alone(self):
        transcript = [UserMessage.text_block("q"), UserMessage.text_block("q2")]
        outcome = compact(transcript, force=True, keep_messages=4)
        self.assertFalse(outcome.performed)
        self.assertIn("nothing to summarise", outcome.reason)

    def test_a_zero_message_cut_is_never_reported_as_a_compaction(self):
        transcript = self.build(1)
        outcome = compact(transcript, force=True, keep_messages=len(transcript))
        self.assertFalse(outcome.performed)
        self.assertEqual(outcome.cut, -1)

    def test_a_custom_summarizer_is_used_and_honoured(self):
        transcript = self.build(6)
        outcome = compact(transcript, force=True, keep_messages=2, summarizer=lambda messages: "MODEL SUMMARY")
        self.assertEqual(outcome.summary, "MODEL SUMMARY")
        self.assertEqual(outcome.summary_source, "provider")
        self.assertEqual(outcome.transcript[0].content, "MODEL SUMMARY")

    def test_a_summarizer_that_returns_nothing_falls_back_instead_of_losing_context(self):
        transcript = self.build(6)
        outcome = compact(transcript, force=True, keep_messages=2, summarizer=lambda messages: "")
        self.assertIn("output 0", outcome.summary)
        self.assertEqual(outcome.summary_source, "extractive_fallback", "the label must name the summariser that actually ran")

    def test_host_instructions_reach_the_summary(self):
        transcript = self.build(6)
        outcome = compact(transcript, force=True, keep_messages=2, instructions="keep every path")
        self.assertIn("keep every path", outcome.summary)

    def test_rollover_replaces_the_safe_transcript_and_records_lineage(self):
        transcript = self.build(6)
        outcome = rollover(
            transcript,
            context_window_tokens=1800,
            max_output_tokens=200,
            window_index=3,
            session_id="session-1",
            reason="test overflow",
        )
        self.assertTrue(outcome.performed, outcome.reason)
        self.assertEqual(outcome.mode, "window_rollover")
        self.assertEqual(len(outcome.transcript), 1)
        self.assertEqual(outcome.boundary.data["window_id"], "session-1:window:3")
        self.assertEqual(outcome.boundary.data["sequence"], 3)
        self.assertEqual(outcome.boundary.data["lineage"]["previous_window_id"], "session-1:window:2")
        self.assertLessEqual(outcome.tokens_after + 200, 1800)
        self.assertEqual(pending_tool_uses(outcome.transcript), ())

    def test_rollover_never_cuts_a_pending_tool_exchange(self):
        transcript = [UserMessage.text_block("q"), assistant_with_call("pending")]
        outcome = rollover(
            transcript,
            context_window_tokens=1800,
            max_output_tokens=200,
            window_index=1,
            session_id="session-1",
        )
        self.assertFalse(outcome.performed)
        self.assertIn("mid tool exchange", outcome.reason)
        self.assertEqual(outcome.transcript, tuple(transcript))

    def test_extractive_summary_is_bounded_and_deterministic(self):
        transcript = self.build(10)
        first = extractive_summary(transcript)
        second = extractive_summary(transcript)
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), 4000)
        self.assertTrue(all(len(line) <= 260 for line in first.splitlines()))

    def test_should_compact_only_triggers_above_the_threshold(self):
        transcript = self.build(3)
        tokens = estimate_transcript_tokens(transcript)
        self.assertTrue(should_compact(transcript, tokens - 1))
        self.assertFalse(should_compact(transcript, tokens + 1))
        self.assertFalse(should_compact(transcript, None))
        self.assertFalse(should_compact(transcript, 0))

    def test_boundary_event_carries_the_audit_fields(self):
        transcript = self.build(6)
        outcome = compact(transcript, force=True, keep_messages=2)
        data = outcome.boundary.data
        self.assertEqual(sorted(data), ["cut", "dropped_messages", "kept_messages", "summary_source", "tokens_after", "tokens_before"])
        self.assertEqual(data["dropped_messages"], outcome.dropped_messages)


class CompactionAtRuntimeTests(RuntimeTestCase):
    def transcript_after(self, report):
        return report.transcript

    def test_context_preflight_rolls_into_a_new_window_before_generation(self):
        provider = self.provider([text_turn("done")])
        report = self.runtime(
            provider=provider,
            compaction_threshold_tokens=None,
            context_window_tokens=4000,
            max_output_tokens=100,
        ).run_collect("large context " * 3000)
        self.assertTrue(report.ok)
        self.assertEqual(report.context_windows, 2)
        self.assertEqual(len(report.window_rollovers), 1)
        boundary = report.window_rollovers[0]
        self.assertEqual(boundary["mode"], "window_rollover")
        self.assertEqual(boundary["sequence"], 1)
        self.assertEqual(len(provider.requests), 1, "preflight rollover must happen before the first provider call")
        self.assertEqual(report.compact_boundaries[0].data["lineage"]["session_id"], report.session_id)

    def test_rollover_after_tools_does_not_repeat_a_completed_call(self):
        workspace = self.workspace({"big.txt": "q" * 60_000 + "\n"})
        provider = self.provider(
            [
                tool_turn("Read", {"path": "big.txt"}, usage={"input_tokens": 20, "output_tokens": 10}),
                text_turn("done"),
            ]
        )
        report = self.runtime(
            provider=provider,
            workspace=workspace,
            compaction_threshold_tokens=None,
            context_window_tokens=4000,
            max_output_tokens=100,
        ).run_collect("read it")
        self.assertTrue(report.ok)
        self.assertEqual(len(report.tool_calls), 1)
        self.assertEqual(len(report.window_rollovers), 1)
        self.assertEqual(provider.cursor, 2)
        self.assertIn("tool_result", report.compact_boundaries[0].content)

    def test_the_loop_never_sends_a_dangling_tool_use_after_compacting(self):
        workspace = self.workspace({"big.txt": "q" * 60_000 + "\n"})
        turns = [tool_turn("Read", {"path": "big.txt"}, usage={"input_tokens": 900, "output_tokens": 200}) for _ in range(4)]
        turns.append(text_turn("done"))
        provider = self.provider(turns)
        report = self.drive(
            self.runtime(provider=provider, workspace=workspace, compaction_threshold_tokens=600, compaction_keep_messages=2)
        )
        self.assertTrue(report.compact_boundaries, "this scenario is built to force at least one compaction")
        for request in provider.requests:
            messages = request.messages
            uses = [block["id"] for message in messages for block in message["content"] if block["type"] == "tool_use"]
            results = [block["tool_use_id"] for message in messages for block in message["content"] if block["type"] == "tool_result"]
            self.assertEqual([call for call in uses if call not in results], [], "no request may carry an unanswered tool_use")
            self.assertEqual([result for result in results if result not in uses], [], "no request may carry an unmatched tool_result")
            roles = [message["role"] for message in messages]
            self.assertEqual(roles[0], "user")
            for position in range(1, len(roles)):
                self.assertNotEqual(roles[position], roles[position - 1], f"roles must alternate: {roles}")

    def test_compaction_never_outruns_the_most_recent_turn(self):
        workspace = self.workspace({"big.txt": "q" * 60_000 + "\n"})
        turns = [tool_turn("Read", {"path": "big.txt"}, usage={"input_tokens": 900, "output_tokens": 200}) for _ in range(4)]
        turns.append(text_turn("done"))
        provider = self.provider(turns)
        report = self.drive(self.runtime(provider=provider, workspace=workspace, compaction_threshold_tokens=600, compaction_keep_messages=2))
        for boundary in report.compact_boundaries:
            self.assertGreaterEqual(boundary.data["kept_messages"], 2)

    def test_compaction_is_skipped_and_reported_when_no_boundary_is_legal(self):
        provider = self.provider([tool_turn("Read", {"path": "x"}, usage={"input_tokens": 4000, "output_tokens": 100}) for _ in range(2)] + [text_turn("done")])
        runtime = self.runtime(provider=provider, compaction_threshold_tokens=600, compaction_keep_messages=50)
        report = runtime.run_collect("q" * 4000)
        self.assertEqual(report.compact_boundaries, ())
        self.assertTrue(any(not item["performed"] for item in report.compactions))


if __name__ == "__main__":
    unittest.main()
