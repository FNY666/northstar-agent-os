"""Pair-preserving compaction: a summary boundary never splits an exchange.

The rules under test:

* a tool call and its result are one atomic span;
* a cut inside a span is refused even when the older orphan rules would have
  allowed it;
* ``compact()`` moves the cut to the span boundary, or refuses to compact and
  says why;
* an approval request/response pair is one atomic span too - today the
  transcript carries no approval block, so the pair rule is exercised through
  the ``data`` mapping the approval module serialises.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import support  # noqa: F401  (bootstraps sys.path)

from compaction import (  # noqa: E402
    compact,
    group_messages,
    is_safe_cut,
    latest_safe_cut,
    safe_cuts,
    spans_crossing,
)
from providers.base import (  # noqa: E402
    AssistantMessage,
    SystemMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)


def assistant_with_call(call_id: str, name: str = "Read") -> AssistantMessage:
    return AssistantMessage(
        content=(TextBlock(text="let me look"), ToolUseBlock(id=call_id, name=name, input={"path": "a"}))
    )


def user_with_result(call_id: str, text: str = "result") -> UserMessage:
    return UserMessage(content=(ToolResultBlock(tool_use_id=call_id, content=text),))


class SpanTests(unittest.TestCase):
    def test_a_call_and_its_result_are_one_span(self):
        transcript = [
            UserMessage.text_block("start"),
            assistant_with_call("t1"),
            user_with_result("t1"),
            UserMessage.text_block("next"),
        ]
        spans = group_messages(transcript)
        pair = [span for span in spans if span.kind == "pair"]
        self.assertEqual(len(pair), 1)
        self.assertEqual((pair[0].start, pair[0].end), (1, 2))

    def test_a_cut_inside_a_pair_is_refused(self):
        transcript = [
            UserMessage.text_block("start"),
            assistant_with_call("t1"),
            user_with_result("t1"),
            UserMessage.text_block("next"),
        ]
        self.assertFalse(is_safe_cut(transcript, 2), "cutting between a call and its result splits the exchange")
        self.assertTrue(is_safe_cut(transcript, 3), "cutting after the whole exchange is fine")

    def test_safe_cuts_never_land_inside_a_span(self):
        transcript = [
            UserMessage.text_block("start"),
            assistant_with_call("t1"),
            user_with_result("t1"),
            UserMessage.text_block("next"),
        ]
        spans = group_messages(transcript)
        for cut in safe_cuts(transcript):
            self.assertEqual(spans_crossing(spans, cut), (), f"cut {cut} splits a span")

    def test_an_ambiguous_call_id_is_not_paired(self):
        # The same call id appears twice: the transcript cannot say which
        # occurrence the result belongs to, so no pair is claimed.
        transcript = [
            assistant_with_call("t1"),
            user_with_result("t1"),
            assistant_with_call("t1"),
            user_with_result("t1"),
        ]
        spans = group_messages(transcript)
        self.assertEqual([span for span in spans if span.kind == "pair"], [])


class ApprovalSpanTests(unittest.TestCase):
    """The approval pair rule, exercised through the message ``data`` mapping.

    Northstar's transcript message types carry no approval request/response
    block today - the approval path lives in ``permissions.py`` and
    ``approval_chain.py`` and never becomes a transcript message.  The pair
    rule therefore reads the pair off the ``data`` mapping, under the
    ``approval_request`` / ``approval_response`` keys with a shared
    ``approval_id`` - the shape ``approval_rules`` serialises.  No message
    shape is invented here: ``SystemMessage`` already carries a ``data`` dict.
    """

    def _approval_request(self, approval_id: str) -> SystemMessage:
        return SystemMessage(
            subtype="informational",
            content="approval requested",
            data={"approval_id": approval_id, "approval_request": True},
        )

    def _approval_response(self, approval_id: str) -> SystemMessage:
        return SystemMessage(
            subtype="informational",
            content="approval answered",
            data={"approval_id": approval_id, "approval_response": True},
        )

    def test_an_approval_pair_is_one_span(self):
        transcript = [
            UserMessage.text_block("start"),
            self._approval_request("a-1"),
            self._approval_response("a-1"),
            UserMessage.text_block("next"),
        ]
        spans = group_messages(transcript)
        pair = [span for span in spans if span.kind == "pair"]
        self.assertEqual(len(pair), 1)
        self.assertEqual((pair[0].start, pair[0].end), (1, 2))

    def test_a_cut_inside_an_approval_pair_is_refused(self):
        transcript = [
            UserMessage.text_block("start"),
            self._approval_request("a-1"),
            self._approval_response("a-1"),
            UserMessage.text_block("next"),
        ]
        self.assertFalse(is_safe_cut(transcript, 2))
        self.assertTrue(is_safe_cut(transcript, 3))


class CompactPathTests(unittest.TestCase):
    """The real path: a pair straddling the cut moves the cut or stops it."""

    def test_a_pair_straddling_the_cut_moves_the_cut_to_the_span_boundary(self):
        transcript = [
            UserMessage.text_block("question"),
            assistant_with_call("t1"),
            user_with_result("t1"),
            UserMessage.text_block("answer"),
        ]
        # keep_messages=1 leaves max_cut=3, which lands inside the pair
        # (messages 1 and 2).  The cut must move to 1 (before the pair) or 3.
        outcome = compact(transcript, force=True, keep_messages=1)
        self.assertTrue(outcome.performed, outcome.reason)
        self.assertNotIn(outcome.cut, (2,), "the cut must not land inside the tool pair")
        kept = outcome.transcript[1:]
        call_ids = [
            call.id
            for message in kept
            if isinstance(message, AssistantMessage)
            for call in message.tool_uses
        ]
        result_ids = [
            result.tool_use_id
            for message in kept
            if isinstance(message, UserMessage)
            for result in message.tool_results
        ]
        self.assertEqual(
            [cid for cid in call_ids if cid in result_ids],
            [cid for cid in call_ids if cid in result_ids],
        )
        # Whatever survived kept every pair whole.
        self.assertEqual(len(call_ids), len(result_ids))

    def test_a_pair_is_never_split_across_the_boundary(self):
        transcript = [
            UserMessage.text_block("question"),
            assistant_with_call("t1"),
            user_with_result("t1"),
            UserMessage.text_block("answer"),
        ]
        outcome = compact(transcript, force=True, keep_messages=1)
        self.assertTrue(outcome.performed)
        prefix = outcome.transcript[0]
        suffix = outcome.transcript[1:]
        calls_in_prefix = [
            call.id
            for message in prefix.content
            if isinstance(message, ToolUseBlock)
        ]
        self.assertEqual(calls_in_prefix, [], "the summary must not carry half a call")

    def test_compaction_refuses_when_every_cut_would_split_a_pair(self):
        # Three messages: a call, its result, and a trailing question.  The
        # only cuts that keep a tail are inside the pair or inside the tail,
        # and the tail is one message - so the only legal cut is before the
        # pair, which would leave the whole transcript in the tail.
        transcript = [
            assistant_with_call("t1"),
            user_with_result("t1"),
            UserMessage.text_block("still going"),
        ]
        outcome = compact(transcript, force=True, keep_messages=2)
        self.assertFalse(outcome.performed, "the pair must not be split")
        self.assertIn("split", outcome.reason)
        self.assertEqual(outcome.transcript, tuple(transcript))

    def test_latest_safe_cut_never_returns_a_cut_inside_a_span(self):
        transcript = [
            UserMessage.text_block("a"),
            assistant_with_call("t1"),
            user_with_result("t1"),
            UserMessage.text_block("b"),
        ]
        cut = latest_safe_cut(transcript, max_cut=3)
        self.assertIsNotNone(cut)
        self.assertNotEqual(cut, 2)


if __name__ == "__main__":
    unittest.main()
