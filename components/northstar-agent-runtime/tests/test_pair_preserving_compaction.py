"""Pair-preserving compaction: a summary boundary never splits an exchange.

The rules under test:

* a tool call and its result are one atomic span;
* a cut inside a span is refused - for a tool pair the older orphan rule
  already refuses it, for an approval pair the span rule is the only thing
  that refuses it;
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
    orphaned_tool_results,
    pending_tool_uses,
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

    def test_the_spans_are_contiguous_and_do_not_overlap(self):
        # A call and its result separated by other messages: the pair span is
        # the hull of the exchange, and the messages inside it travel with it
        # rather than forming spans that overlap it.
        transcript = [
            UserMessage.text_block("go"),
            assistant_with_call("t1"),
            UserMessage.text_block("between"),
            UserMessage.text_block("also between"),
            user_with_result("t1"),
        ]
        spans = group_messages(transcript)
        self.assertEqual([(span.start, span.end) for span in spans], [(0, 0), (1, 4)])
        # No message belongs to two spans.
        covered = [index for span in spans for index in range(span.start, span.end + 1)]
        self.assertEqual(len(covered), len(set(covered)), "spans overlap")

    def test_a_cut_inside_a_non_contiguous_pair_is_refused(self):
        transcript = [
            UserMessage.text_block("go"),
            assistant_with_call("t1"),
            UserMessage.text_block("between"),
            UserMessage.text_block("also between"),
            user_with_result("t1"),
        ]
        for cut in (2, 3, 4):
            with self.subTest(cut=cut):
                self.assertFalse(is_safe_cut(transcript, cut), "the pair must not be split")


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

    def test_an_ambiguous_approval_id_is_not_paired(self):
        # One request and TWO responses sharing an id: the transcript cannot
        # say which response answers the request, so no pair is claimed.
        transcript = [
            self._approval_request("a-1"),
            self._approval_response("a-1"),
            self._approval_response("a-1"),
        ]
        spans = group_messages(transcript)
        self.assertEqual([span for span in spans if span.kind == "pair"], [])
        # Two requests sharing an id pair with nothing either.
        transcript = [
            self._approval_request("a-1"),
            self._approval_request("a-1"),
            self._approval_response("a-1"),
        ]
        spans = group_messages(transcript)
        self.assertEqual([span for span in spans if span.kind == "pair"], [])


class SpanIsolationTests(unittest.TestCase):
    """Which rule actually refuses the cut.

    Honest result of reading the two rules side by side:

    * For a **tool** pair the span rule is *subsumed* by the older orphan
      rules.  Any cut that separates a ``tool_use`` from its ``tool_result``
      leaves the call unanswered in the prefix, so ``pending_tool_uses``
      already refuses it.  There is no transcript shape where the span rule
      binds alone for a tool pair - the tool span is a restatement, not an
      addition.
    * For an **approval** pair the span rule binds *alone*: the orphan rules
      know nothing about approvals, so both are empty and only the span rule
      refuses the cut.
    """

    def test_the_orphan_rules_already_refuse_a_tool_pair_split(self):
        # A parallel call: two tool_uses in one assistant turn, two results in
        # one user turn.  The pair is one span (1, 2), so the cut that would
        # split it is 2.
        transcript = [
            UserMessage.text_block("go"),
            AssistantMessage(
                content=(
                    ToolUseBlock(id="t1", name="Read", input={"path": "a"}),
                    ToolUseBlock(id="t2", name="Read", input={"path": "b"}),
                )
            ),
            UserMessage(
                content=(
                    ToolResultBlock(tool_use_id="t1", content="r1"),
                    ToolResultBlock(tool_use_id="t2", content="r2"),
                )
            ),
            UserMessage.text_block("done"),
        ]
        spans = group_messages(transcript)
        self.assertEqual([(s.start, s.end) for s in spans if s.kind == "pair"], [(1, 2)])
        # The older orphan rule is already enough: the prefix still holds two
        # unanswered calls.
        self.assertEqual(pending_tool_uses(transcript[:2]), ("t1", "t2"))
        self.assertFalse(is_safe_cut(transcript, 2), "the pair must not be split")
        self.assertTrue(is_safe_cut(transcript, 1), "cutting before the exchange is legal")
        self.assertTrue(is_safe_cut(transcript, 3), "cutting after the exchange is legal")

    def test_the_span_rule_binds_alone_for_an_approval_pair(self):
        # The same shape, but an approval request/response pair.  Neither
        # orphan rule has anything to say about approvals - both are empty at
        # the split cut - so the refusal is the span rule's alone.
        transcript = [
            UserMessage.text_block("go"),
            SystemMessage(
                subtype="informational",
                content="approval requested",
                data={"approval_id": "a-1", "approval_request": True},
            ),
            SystemMessage(
                subtype="informational",
                content="approval answered",
                data={"approval_id": "a-1", "approval_response": True},
            ),
            UserMessage.text_block("done"),
        ]
        self.assertEqual(pending_tool_uses(transcript[:2]), ())
        self.assertEqual(orphaned_tool_results(transcript[2:], answered_by=transcript[:2]), ())
        # The span rule refuses the cut that would split the approval pair.
        self.assertFalse(is_safe_cut(transcript, 2), "the approval pair must not be split")
        self.assertTrue(is_safe_cut(transcript, 1))
        self.assertTrue(is_safe_cut(transcript, 3))


class CompactPathTests(unittest.TestCase):
    """The real path: a pair straddling the cut moves the cut or stops it."""

    def test_a_pair_straddling_the_cut_moves_the_cut_to_the_span_boundary(self):
        # Three messages: a question, a call, and its result.  The retained
        # tail is one message, so the newest candidate cut is 2 - which lands
        # between the call and its result.  The cut must move down to 1, the
        # boundary before the pair.
        transcript = [
            UserMessage.text_block("question"),
            assistant_with_call("t1"),
            user_with_result("t1"),
        ]
        outcome = compact(transcript, force=True, keep_messages=1)
        self.assertTrue(outcome.performed, outcome.reason)
        self.assertEqual(
            outcome.cut,
            1,
            "the cut moved off the split position to the span boundary",
        )
        # One boundary summary plus the two kept messages.
        self.assertEqual(len(outcome.transcript), 3)

    def test_a_pair_is_never_split_across_the_boundary(self):
        transcript = [
            UserMessage.text_block("question"),
            assistant_with_call("t1"),
            user_with_result("t1"),
            UserMessage.text_block("answer"),
        ]
        outcome = compact(transcript, force=True, keep_messages=1)
        self.assertTrue(outcome.performed)
        # The summary carries no tool call at all: the whole exchange was
        # summarised, so neither half of the pair survives.
        self.assertEqual(outcome.summary.count("tool_use"), 0)
        # And the kept tail holds the call and its result together, or
        # neither.
        suffix = outcome.transcript[1:]
        call_ids = [
            call.id
            for message in suffix
            if isinstance(message, AssistantMessage)
            for call in message.tool_uses
        ]
        result_ids = [
            result.tool_use_id
            for message in suffix
            if isinstance(message, UserMessage)
            for result in message.tool_results
        ]
        self.assertEqual(len(call_ids), len(result_ids), "a pair was split across the boundary")

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

    def test_the_refusal_reason_names_the_tool_pair(self):
        # The refusal must say WHICH rule refused it: a tool pair reads as a
        # tool call, not as an approval.
        transcript = [
            assistant_with_call("t1"),
            user_with_result("t1"),
            UserMessage.text_block("still going"),
        ]
        outcome = compact(transcript, force=True, keep_messages=2)
        self.assertFalse(outcome.performed)
        self.assertIn("split a tool call from its result", outcome.reason)
        self.assertNotIn("approval", outcome.reason)

    def test_the_refusal_reason_names_the_approval_pair(self):
        # The same shape with an approval pair: the reason must not call it a
        # tool call, because no tool was involved.
        transcript = [
            SystemMessage(
                subtype="informational",
                content="approval requested",
                data={"approval_id": "a-1", "approval_request": True},
            ),
            SystemMessage(
                subtype="informational",
                content="approval answered",
                data={"approval_id": "a-1", "approval_response": True},
            ),
            UserMessage.text_block("still going"),
        ]
        outcome = compact(transcript, force=True, keep_messages=2)
        self.assertFalse(outcome.performed, "the approval pair must not be split")
        self.assertIn("split an approval request from its response", outcome.reason)
        self.assertNotIn("tool call", outcome.reason)
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
