"""Shutdown unwind: a killed turn resumes with synthesised interrupted results.

A run that is killed mid-turn leaves a transcript whose last assistant message
asks for tools that never answered. The provider rejects such a request, so the
resume had to fail at the API boundary with an opaque 400 - and nothing in the
transcript said whether the parent turn had finished or been cut short.

These tests pin the four properties the unwind pass promises:

* every call that never got a result gets one, marked interrupted and synthetic,
* a synthetic result is never counted as a success,
* a clean session resumes clean, with nothing synthesised,
* a store that refuses the resume raises, rather than continuing as if clean.
"""
from __future__ import annotations

import contextlib
import io
import sys
import unittest

import support  # noqa: F401
from support import RuntimeTestCase, text_turn, tool_turn

from providers.base import (
    AssistantMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)
from sessions import ResumeRefusedError, SessionIntegrityError, SessionStore
from shutdown_unwind import (
    INTERRUPTED_DENIAL_KIND,
    RESUME_CLEAN,
    RESUME_INTERRUPTED,
    classify,
    pending_tool_uses,
    require_resumable,
    successful_tool_results,
    synthetic_result_blocks,
    unwind,
)


def run_cli(*argv: str) -> tuple[int, str, str]:
    """Run the CLI in-process and capture its three outputs."""
    import cli

    out, err = io.StringIO(), io.StringIO()
    saved_stdin, sys.stdin = sys.stdin, io.StringIO("")
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
    finally:
        sys.stdin = saved_stdin
    return code, out.getvalue(), err.getvalue()


def assistant_with_call(call_id: str, name: str = "Read") -> AssistantMessage:
    return AssistantMessage(content=(ToolUseBlock(id=call_id, name=name, input={"path": "a"}),))


def user_with_result(call_id: str, content: str = "output") -> UserMessage:
    return UserMessage(content=(ToolResultBlock(tool_use_id=call_id, content=content),))


class PendingToolUseTests(unittest.TestCase):
    def test_a_call_with_no_result_is_pending(self):
        transcript = [assistant_with_call("t1"), user_with_result("t1")]
        self.assertEqual(pending_tool_uses(transcript), ())

    def test_a_call_that_never_answered_is_pending(self):
        transcript = [assistant_with_call("t1"), assistant_with_call("t2")]
        self.assertEqual(pending_tool_uses(transcript), (("t1", "Read"), ("t2", "Read")))

    def test_a_partially_answered_batch_leaves_only_the_unanswered_call_pending(self):
        transcript = [assistant_with_call("t1"), assistant_with_call("t2"), user_with_result("t1")]
        self.assertEqual(pending_tool_uses(transcript), (("t2", "Read"),))

    def test_a_call_with_no_id_is_not_pending(self):
        # A provider that omits the id gives the runtime nothing to pair with,
        # so there is nothing to synthesise against.
        transcript = [AssistantMessage(content=(ToolUseBlock(id="", name="Read"),))]
        self.assertEqual(pending_tool_uses(transcript), ())


class UnwindTests(unittest.TestCase):
    def test_a_killed_turn_gets_a_synthetic_interrupted_result(self):
        transcript = [assistant_with_call("t1"), assistant_with_call("t2")]
        unwound, outcome = unwind(transcript)
        self.assertEqual(outcome.classification, RESUME_INTERRUPTED)
        self.assertEqual(outcome.count, 2)
        blocks = synthetic_result_blocks(unwound)
        self.assertEqual([block.tool_use_id for block in blocks], ["t1", "t2"])
        for block in blocks:
            self.assertTrue(block.synthetic)
            self.assertTrue(block.is_error)
            self.assertEqual(block.tool_denial_kind, INTERRUPTED_DENIAL_KIND)

    def test_the_synthetic_result_says_the_call_did_not_run(self):
        unwound, _outcome = unwind([assistant_with_call("t1")])
        block = synthetic_result_blocks(unwound)[0]
        self.assertIn("did not run", block.text())

    def test_the_unwind_leaves_the_parent_history_unchanged(self):
        transcript = [assistant_with_call("t1")]
        unwound, _outcome = unwind(transcript)
        self.assertEqual(len(unwound), len(transcript) + 1)
        self.assertIs(unwound[0], transcript[0])

    def test_a_clean_session_unwinds_to_itself(self):
        transcript = [assistant_with_call("t1"), user_with_result("t1")]
        unwound, outcome = unwind(transcript)
        self.assertEqual(outcome.classification, RESUME_CLEAN)
        self.assertEqual(outcome.count, 0)
        self.assertEqual(len(unwound), len(transcript))
        self.assertEqual(synthetic_result_blocks(unwound), ())

    def test_classification_matches_the_unwind_outcome(self):
        self.assertEqual(classify([assistant_with_call("t1")]), RESUME_INTERRUPTED)
        self.assertEqual(classify([assistant_with_call("t1"), user_with_result("t1")]), RESUME_CLEAN)

    def test_a_synthetic_result_is_never_counted_as_a_success(self):
        unwound, _outcome = unwind([assistant_with_call("t1")])
        self.assertEqual(successful_tool_results(unwound), ())

    def test_a_real_result_still_counts_as_a_success_alongside_a_synthetic_one(self):
        transcript = [assistant_with_call("t1"), assistant_with_call("t2"), user_with_result("t1")]
        unwound, _outcome = unwind(transcript)
        successes = successful_tool_results(unwound)
        self.assertEqual([block.tool_use_id for block in successes], ["t1"])

    def test_require_resumable_refuses_a_history_with_an_unanswered_call(self):
        with self.assertRaises(ResumeRefusedError):
            require_resumable([assistant_with_call("t1")])

    def test_require_resumable_accepts_a_complete_history(self):
        require_resumable([assistant_with_call("t1"), user_with_result("t1")])


class ResumeRefusalTests(unittest.TestCase):
    def test_resume_refused_error_is_a_session_integrity_error(self):
        # A caller that already catches the integrity error must keep catching
        # this one; it is the same fact with a sharper name.
        self.assertTrue(issubclass(ResumeRefusedError, SessionIntegrityError))

class StoreUnwindTests(RuntimeTestCase):
    def killed_session(self, session_id: str = "ns-killed") -> SessionStore:
        """A session whose last turn asked for a tool that never answered."""
        store = SessionStore(self.workspace(), session_id=session_id)
        store.append("session_start", {"agent": "main"})
        store.append(
            "assistant",
            {
                "agent": "main",
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {"path": "a"}}],
                "model": "m",
                "usage": {},
            },
        )
        return store

    def test_a_killed_session_resumes_with_a_synthetic_result(self):
        store = self.killed_session()
        transcript, outcome = store.resume_transcript(require_integrity=True)
        self.assertEqual(outcome.classification, RESUME_INTERRUPTED)
        blocks = synthetic_result_blocks(transcript)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].tool_use_id, "t1")
        self.assertTrue(blocks[0].synthetic)
        self.assertEqual(blocks[0].tool_denial_kind, INTERRUPTED_DENIAL_KIND)

    def test_a_clean_session_resumes_clean_with_nothing_synthesised(self):
        store = SessionStore(self.workspace(), session_id="ns-clean")
        store.append("session_start", {"agent": "main"})
        store.append(
            "assistant",
            {
                "agent": "main",
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {"path": "a"}}],
                "model": "m",
                "usage": {},
            },
        )
        store.append(
            "tool_result",
            {
                "agent": "main",
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "output", "is_error": False}],
            },
        )
        transcript, outcome = store.resume_transcript(require_integrity=True)
        self.assertEqual(outcome.classification, RESUME_CLEAN)
        self.assertEqual(outcome.count, 0)
        self.assertEqual(synthetic_result_blocks(transcript), ())

    def test_the_synthetic_marker_survives_the_transcript_round_trip(self):
        store = self.killed_session()
        transcript, _outcome = store.resume_transcript(require_integrity=True)
        blocks = synthetic_result_blocks(transcript)
        self.assertTrue(blocks[0].synthetic)
        self.assertEqual(blocks[0].tool_denial_kind, INTERRUPTED_DENIAL_KIND)

    def test_a_store_that_refuses_the_transcript_raises_resume_refused(self):
        store = self.killed_session()
        # A redacted transcript cannot be resumed, and the refusal has its own
        # name rather than a generic integrity failure.
        store.append("informational", {"agent": "main", "content": "x", "content_redacted": True})
        with self.assertRaises(ResumeRefusedError):
            store.resume_transcript(require_integrity=True)


class EndToEndResumeTests(RuntimeTestCase):
    """The unwind pass as a resumed run actually experiences it."""

    def killed_store(self, session_id: str = "ns-e2e-killed") -> SessionStore:
        store = SessionStore(self.workspace(), session_id=session_id)
        store.append("session_start", {"agent": "main"})
        store.append(
            "assistant",
            {
                "agent": "main",
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {"path": "a.txt"}}],
                "model": "m",
                "usage": {},
            },
        )
        return store

    def test_a_resumed_killed_session_sends_the_synthetic_result_to_the_provider(self):
        store = self.killed_store()
        transcript, outcome = store.resume_transcript(require_integrity=True)
        self.assertEqual(outcome.classification, RESUME_INTERRUPTED)
        provider = self.provider([text_turn("done")])
        runtime = self.runtime(provider=provider, workspace=self.workspace(), sessions=store)
        report = runtime.run_collect("continue", resume=transcript)
        self.assertTrue(report.ok)
        # The provider sees a legal request: every tool_use it reads back has a
        # matching tool_result.
        sent = provider.requests[0].messages
        asked = [
            block["id"]
            for message in sent
            for block in message["content"]
            if isinstance(block, dict) and block.get("type") == "tool_use"
        ]
        answered = [
            block["tool_use_id"]
            for message in sent
            for block in message["content"]
            if isinstance(block, dict) and block.get("type") == "tool_result"
        ]
        self.assertTrue(asked)
        self.assertEqual(sorted(answered), sorted(asked))

    def test_a_synthetic_result_is_never_a_tool_call_in_the_report(self):
        store = self.killed_store()
        transcript, _outcome = store.resume_transcript(require_integrity=True)
        provider = self.provider([text_turn("done")])
        runtime = self.runtime(provider=provider, workspace=self.workspace(), sessions=store)
        report = runtime.run_collect("continue", resume=transcript)
        # The call never ran, so it is not a call: the report must not claim it.
        self.assertEqual(report.tool_calls, ())

    def test_a_synthetic_result_never_counts_as_a_success(self):
        store = self.killed_store()
        transcript, _outcome = store.resume_transcript(require_integrity=True)
        provider = self.provider([text_turn("done")])
        runtime = self.runtime(provider=provider, workspace=self.workspace(), sessions=store)
        report = runtime.run_collect("continue", resume=transcript)
        self.assertEqual(successful_tool_results(report.transcript), ())

    def test_the_run_records_the_interrupted_classification_in_its_init_record(self):
        store = self.killed_store()
        transcript, _outcome = store.resume_transcript(require_integrity=True)
        provider = self.provider([text_turn("done")])
        runtime = self.runtime(provider=provider, workspace=self.workspace(), sessions=store)
        runtime.run_collect("continue", resume=transcript)
        records, _ = store.read(store.session_id)
        init_records = [record for record in records if record.get("type") == "session_start"]
        self.assertTrue(init_records)
        data = init_records[-1].get("data") or {}
        unwind_data = data.get("resume_unwind") or {}
        self.assertEqual(unwind_data.get("classification"), RESUME_INTERRUPTED)
        self.assertEqual(unwind_data.get("synthesised_count"), 1)

    def test_the_synthetic_result_is_written_into_the_transcript(self):
        store = self.killed_store()
        transcript, _outcome = store.resume_transcript(require_integrity=True)
        provider = self.provider([text_turn("done")])
        runtime = self.runtime(provider=provider, workspace=self.workspace(), sessions=store)
        runtime.run_collect("continue", resume=transcript)
        records, _ = store.read(store.session_id)
        synthetic = [
            block
            for record in records
            if record.get("type") == "tool_result"
            for block in record.get("content") or []
            if isinstance(block, dict) and block.get("synthetic")
        ]
        self.assertEqual(len(synthetic), 1)
        self.assertEqual(synthetic[0]["tool_denial_kind"], INTERRUPTED_DENIAL_KIND)

    def test_a_clean_session_resumes_clean_and_the_run_says_so(self):
        store = SessionStore(self.workspace(), session_id="ns-e2e-clean")
        store.append("session_start", {"agent": "main"})
        store.append(
            "assistant",
            {
                "agent": "main",
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {"path": "a.txt"}}],
                "model": "m",
                "usage": {},
            },
        )
        store.append(
            "tool_result",
            {
                "agent": "main",
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "output", "is_error": False}],
            },
        )
        transcript, outcome = store.resume_transcript(require_integrity=True)
        self.assertEqual(outcome.classification, RESUME_CLEAN)
        provider = self.provider([text_turn("done")])
        runtime = self.runtime(provider=provider, workspace=self.workspace(), sessions=store)
        runtime.run_collect("continue", resume=transcript)
        records, _ = store.read(store.session_id)
        init_records = [record for record in records if record.get("type") == "session_start"]
        data = init_records[-1].get("data") or {}
        unwind_data = data.get("resume_unwind") or {}
        self.assertEqual(unwind_data.get("classification"), RESUME_CLEAN)
        self.assertEqual(unwind_data.get("synthesised_count"), 0)

    def test_a_store_that_refuses_raises_and_the_run_does_not_continue(self):
        store = self.killed_store()
        store.append("informational", {"agent": "main", "content": "x", "content_redacted": True})
        with self.assertRaises(ResumeRefusedError):
            store.resume_transcript(require_integrity=True)


class CliResumeTests(RuntimeTestCase):
    """The unwind as the CLI experiences it: a killed session, resumed."""

    def test_resuming_a_killed_session_succeeds_and_records_the_unwind(self):
        root = self.workspace()
        session_dir = self.temp_dir()
        # A session that was killed mid-turn: the assistant asked for a tool and
        # the process died before the tool answered.
        store = SessionStore(session_dir, session_id="ns-cli-killed")
        store.append("session_start", {"agent": "main"})
        store.append(
            "assistant",
            {
                "agent": "main",
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {"path": "a.txt"}}],
                "model": "m",
                "usage": {},
            },
        )
        code, out, err = run_cli(
            "run", "--workspace", str(root), "--prompt", "continue", "--scripted-text", "resumed",
            "--session-dir", str(session_dir), "--resume", "ns-cli-killed", "--quiet",
        )
        self.assertEqual(code, 0, err)
        self.assertNotIn("Traceback", err)
        records, _ = store.read("ns-cli-killed")
        synthetic = [
            block
            for record in records
            if record.get("type") == "tool_result"
            for block in record.get("content") or []
            if isinstance(block, dict) and block.get("synthetic")
        ]
        self.assertEqual(len(synthetic), 1)
        self.assertEqual(synthetic[0]["tool_denial_kind"], INTERRUPTED_DENIAL_KIND)

    def test_a_store_that_refuses_the_resume_is_refused_out_loud(self):
        root = self.workspace()
        session_dir = self.temp_dir()
        store = SessionStore(session_dir, session_id="ns-cli-refused")
        store.append("session_start", {"agent": "main"})
        store.append("informational", {"agent": "main", "content": "x", "content_redacted": True})
        code, _out, err = run_cli(
            "run", "--workspace", str(root), "--prompt", "continue", "--scripted-text", "resumed",
            "--session-dir", str(session_dir), "--resume", "ns-cli-refused", "--quiet",
        )
        self.assertNotEqual(code, 0, "a refused resume must not exit as a successful run")
        self.assertIn("resume refused", err)


class ReplayCountingTests(RuntimeTestCase):
    """The replay view must not read a synthetic result as a tool failure."""

    def test_a_synthetic_result_is_counted_as_interrupted_not_as_a_tool_error(self):
        from session_replay import build_replay

        session_dir = self.temp_dir()
        store = SessionStore(session_dir, session_id="ns-replay")
        store.append("session_start", {"agent": "main"})
        store.append(
            "assistant",
            {
                "agent": "main",
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {"path": "a"}}],
                "model": "m",
                "usage": {},
            },
        )
        store.append(
            "tool_result",
            {
                "agent": "main",
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "t1",
                        "content": "[interrupted] this call did not run.",
                        "is_error": True,
                        "synthetic": True,
                        "tool_denial_kind": INTERRUPTED_DENIAL_KIND,
                    }
                ],
            },
        )
        records, _ = store.read("ns-replay")
        report = build_replay(records, session_id="ns-replay")
        self.assertEqual(report.counts["interrupted_tools"], 1)
        self.assertEqual(report.counts["tool_errors"], 0, "an interrupted call is not a tool failure")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
