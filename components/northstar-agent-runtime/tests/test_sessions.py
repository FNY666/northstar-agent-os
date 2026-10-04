"""Session transcripts: append-only JSONL, fsync per write, tail-truncation
recovery, and a session id even when nothing is persisted.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import support  # noqa: F401
from support import RuntimeTestCase, text_turn, tool_turn

import sessions
from providers.base import AssistantMessage, ResultMessage, SystemMessage, UserMessage
from sessions import (
    RECORD_TYPES,
    SessionIntegrityError,
    SessionStore,
    _open_regular_nofollow,
    load_jsonl,
    new_session_id,
    resolve_session_id,
    session_spend,
    summarise,
    transcript_from_records,
)


class SessionSpendTests(unittest.TestCase):
    def test_session_spend_counts_trailing_assistant_usage_without_result(self):
        records = [
            {"type": "assistant", "model": "claude-sonnet-4-5", "usage": {"input_tokens": 100_000}},
        ]
        cost, usage = session_spend(records)
        self.assertEqual(cost, 0.3)
        self.assertEqual(usage.input_tokens, 100_000)

    def test_session_spend_prices_each_interrupted_model_segment_separately(self):
        records = [
            {"type": "assistant", "model": "claude-haiku-4-5", "usage": {"input_tokens": 100_000}},
            {"type": "assistant", "model": "claude-sonnet-4-5", "usage": {"input_tokens": 100_000}},
        ]
        cost, _usage = session_spend(records)
        self.assertEqual(cost, 0.38)

    def test_session_spend_does_not_double_count_completed_run_usage(self):
        records = [
            {"type": "assistant", "model": "claude-sonnet-4-5", "usage": {"input_tokens": 100_000}},
            {"type": "result", "total_cost_usd": 0.3},
            {"type": "assistant", "model": "claude-sonnet-4-5", "usage": {"input_tokens": 50_000}},
        ]
        cost, _usage = session_spend(records)
        self.assertEqual(cost, 0.45)

    def test_session_spend_aggregates_results_and_assistant_usage_only(self):
        records = [
            {"type": "session_start", "data": {"total_cost_usd": 999}},
            {"type": "assistant", "usage": {"input_tokens": 10, "output_tokens": 2}},
            {"type": "result", "total_cost_usd": 0.3},
            {"type": "assistant", "usage": {"input_tokens": 4, "cache_read_input_tokens": 3}},
            {"type": "result", "total_cost_usd": 0.2},
            {"type": "session_end", "total_cost_usd": 123},
        ]
        cost, usage = session_spend(records)
        self.assertEqual(cost, 0.5)
        self.assertEqual(usage.input_tokens, 14)
        self.assertEqual(usage.output_tokens, 2)
        self.assertEqual(usage.cache_read_input_tokens, 3)


class SessionIdTests(unittest.TestCase):
    def test_path_traversal_and_absolute_ids_are_refused(self):
        for value in ("../secret", "/tmp/secret", "a/b", r"a\\b", ".."):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    SessionStore("/tmp/sessions", session_id=value)

    def test_safe_legacy_id_is_accepted(self):
        self.assertEqual(SessionStore(None, session_id="ns-given").session_id, "ns-given")

    def test_read_refuses_path_traversal_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="safe")
            with self.assertRaises(ValueError):
                store.read("../outside")

    def test_ids_are_unique_sortable_and_prefixed(self):
        first, second = new_session_id(now=1_000_000), new_session_id(now=2_000_000)
        self.assertTrue(first.startswith("ns-1970"))
        self.assertNotEqual(first, second)
        self.assertLess(first, second)

    def test_a_generated_id_is_unique_per_call(self):
        self.assertNotEqual(resolve_session_id(None, None), resolve_session_id(None, None))
        self.assertTrue(resolve_session_id(None, None).startswith("ns-"))

    def test_an_explicit_id_is_respected(self):
        self.assertEqual(resolve_session_id("ns-given", None), "ns-given")
        self.assertEqual(resolve_session_id(None, SessionStore(None, session_id="ns-store")), "ns-store")

    def test_unknown_record_types_are_refused(self):
        store = SessionStore(None)
        with self.assertRaises(ValueError):
            store.append("raw_prompt_bytes", {})
        # 13 since the fourteenth batch: "checkpoint" (checkpoints.py) joins: "postconditions" is the independent
        # "postconditions" (the end-of-run verdict) and "checkpoint" (a resumable
        # turn boundary), each with its own record type rather than hiding inside
        # "informational". Add a type here only with a test for it.
        self.assertEqual(len(RECORD_TYPES), 13)


class WriteTests(RuntimeTestCase):
    def test_a_nonblocking_fifo_open_does_not_hang_before_regular_file_check(self):
        if not all(hasattr(os, name) for name in ("mkfifo", "O_NOFOLLOW", "O_NONBLOCK")):
            self.skipTest("requires POSIX FIFO and safe-open flags")
        fifo = self.workspace() / "ns-fifo.jsonl"
        os.mkfifo(fifo)
        # A missing O_NONBLOCK must fail within the child timeout, not hang the suite.
        probe = (
            "import errno, os, sys\n"
            "from pathlib import Path\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import sessions\n"
            "try:\n"
            "    fd = sessions._open_regular_nofollow(Path(sys.argv[2]), int(sys.argv[3]))\n"
            "except sessions.SessionIntegrityError:\n"
            "    print('rejected-nonregular')\n"
            "except OSError as error:\n"
            "    assert error.errno == errno.ENXIO, error\n"
            "    print('rejected-no-reader')\n"
            "else:\n"
            "    os.close(fd)\n"
            "    raise AssertionError('FIFO was accepted')\n"
        )
        for flags in (os.O_RDONLY, os.O_WRONLY | os.O_APPEND | os.O_CREAT):
            with self.subTest(flags=flags):
                process = subprocess.Popen(
                    [sys.executable, "-I", "-c", probe, str(Path(sessions.__file__).parent), str(fifo), str(flags)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    # iSH may defer a signal during FIFO open; supply a peer to unblock it.
                    peer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
                    try:
                        process.communicate(timeout=5)
                    finally:
                        os.close(peer)
                    self.fail("FIFO safe open timed out; O_NONBLOCK must prevent blocking")
                self.assertEqual(process.returncode, 0, stderr)
                self.assertIn("rejected-", stdout)

    def test_open_regular_restores_append_flag_after_nonblocking_open(self):
        import fcntl

        path = self.workspace() / "ns-append-flag.jsonl"
        path.write_bytes(b"seed\n")
        real_open = os.open

        def open_without_append(target, flags, mode=0o600):
            # Model the observed host behavior on every POSIX CI host.
            return real_open(target, flags & ~os.O_APPEND, mode)

        with patch.object(sessions.os, "open", side_effect=open_without_append):
            fd = _open_regular_nofollow(path, os.O_WRONLY | os.O_APPEND)
        try:
            actual = fcntl.fcntl(fd, fcntl.F_GETFL)
            self.assertTrue(actual & os.O_APPEND, "safe open must restore append semantics")
            os.lseek(fd, 0, os.SEEK_SET)
            self.assertEqual(os.write(fd, b"tail\n"), 5)
        finally:
            os.close(fd)
        self.assertEqual(path.read_bytes(), b"seed\ntail\n")

    def test_append_keeps_all_variable_length_jsonl_records(self):
        store = SessionStore(self.workspace(), session_id="ns-append-integrity")
        store.append("session_start", {"data": {"short": True}})
        store.append("tool_result", {"content": [{"type": "tool_result", "content": "x" * 180, "is_error": False}]})
        store.append("denial", {"tool": "Write", "reason": "r" * 130})
        records, dropped = store.read()
        self.assertEqual(dropped, 0)
        self.assertEqual([record["type"] for record in records], ["session_start", "tool_result", "denial"])
        self.assertEqual(records[1]["content"][0]["content"], "x" * 180)

    def test_every_append_is_one_line_and_fsynced(self):
        calls: list[int] = []
        root = self.workspace()
        store = SessionStore(root, session_id="ns-t", fsync=lambda fd: calls.append(fd))
        store.append("session_start", {"model": "m"})
        store.append("user_prompt", {"content": []})
        self.assertEqual(len(calls), 2, "each write must be durable before the loop continues")
        lines = store.path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        records = [json.loads(line) for line in lines]
        self.assertEqual([record["index"] for record in records], [0, 1])
        self.assertEqual({record["session_id"] for record in records}, {"ns-t"})
        self.assertEqual(records[0]["type"], "session_start")
        self.assertTrue(records[0]["ts"].endswith("Z"))

    def test_durable_false_skips_the_fsync_for_benchmarks(self):
        calls: list[int] = []
        store = SessionStore(self.workspace(), session_id="ns-t", fsync=lambda fd: calls.append(fd), durable=False)
        store.append("session_start", {})
        self.assertEqual(calls, [])

    def test_the_file_is_append_only_across_independent_writers(self):
        root = self.workspace()
        first = SessionStore(root, session_id="ns-shared")
        second = SessionStore(root, session_id="ns-shared")
        first.append("session_start", {"writer": "a"})
        second.append("user_prompt", {"writer": "b"})
        records, dropped = load_jsonl(first.path)
        self.assertEqual(dropped, 0)
        self.assertEqual([record["index"] for record in records], [0, 0])
        self.assertEqual([record["type"] for record in records], ["session_start", "user_prompt"])

    def test_transcript_files_are_owner_readable_only(self):
        root = self.workspace()
        store = SessionStore(root, session_id="ns-perm")
        store.append("session_start", {})
        mode = stat.S_IMODE(os.stat(store.path).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(root).st_mode), 0o700)

    def test_append_refuses_a_transcript_symlink(self):
        root = self.workspace()
        outside = root.parent / "outside.jsonl"
        outside.write_text("do not append here\n", encoding="utf-8")
        (root / "ns-link.jsonl").symlink_to(outside)
        store = SessionStore(root, session_id="ns-link")
        with self.assertRaises(SessionIntegrityError):
            store.append("informational", {"content": "must stay inside"})
        self.assertEqual(outside.read_text(encoding="utf-8"), "do not append here\n")

    def test_read_refuses_a_transcript_symlink(self):
        root = self.workspace()
        outside = root.parent / "outside.jsonl"
        outside.write_text('{"index":0,"type":"session_start"}\n', encoding="utf-8")
        link = root / "ns-link.jsonl"
        link.symlink_to(outside)
        with self.assertRaises(SessionIntegrityError):
            load_jsonl(link)

    def test_oversized_records_stay_parseable(self):
        store = SessionStore(self.workspace(), session_id="ns-big", max_record_chars=300)
        store.append("informational", {"content": "q" * 5000})
        records, dropped = load_jsonl(store.path)
        self.assertEqual(dropped, 0)
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0].get("truncated"))

    def test_unicode_is_not_escaped_away(self):
        store = SessionStore(self.workspace(), session_id="ns-cjk")
        store.append("user_prompt", {"content": [{"type": "text", "text": "测试" * 50}]})
        line = store.path.read_text(encoding="utf-8").splitlines()[0]
        self.assertIn("测试", line, "raw UTF-8 keeps transcripts greppable")
        self.assertNotIn("\\u", line)


class RecoveryTests(RuntimeTestCase):
    def write_lines(self, root: Path, lines: list[str], name: str = "ns-r.jsonl") -> Path:
        path = root / name
        path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
        return path

    def test_a_truncated_last_line_is_skipped_not_fatal(self):
        root = self.workspace()
        store = SessionStore(root, session_id="ns-r")
        store.append("session_start", {"a": 1})
        store.append("user_prompt", {"b": 2})
        with open(store.path, "a", encoding="utf-8") as handle:
            handle.write('{"index": 2, "type": "assistant", "content": [{"ty')  # torn write, no newline
        records, dropped = store.read()
        self.assertEqual([record["type"] for record in records], ["session_start", "user_prompt"])
        self.assertEqual(dropped, 1)

    def test_a_missing_final_newline_is_not_corruption(self):
        root = self.workspace()
        path = self.write_lines(root, [json.dumps({"index": 0, "type": "session_start"})])
        path.write_text(path.read_text().rstrip("\n"), encoding="utf-8")
        records, dropped = load_jsonl(path)
        self.assertEqual((len(records), dropped), (1, 0))

    def test_damage_in_the_middle_is_reported_not_silently_dropped(self):
        root = self.workspace()
        path = self.write_lines(root, [json.dumps({"index": 0}), "not json at all", json.dumps({"index": 1})])
        with self.assertRaises(SessionIntegrityError):
            load_jsonl(path)
        records, dropped = load_jsonl(path, strict=False)
        self.assertEqual(len(records), 2)
        self.assertEqual(dropped, 1)

    def test_missing_files_read_as_empty(self):
        store = SessionStore(self.workspace(), session_id="ns-absent")
        self.assertEqual(store.read(), ([], 0))
        self.assertEqual(store.transcript(), [])
        self.assertEqual(store.list_sessions(), ())

    def test_a_run_survives_reading_back_its_own_transcript(self):
        root = self.workspace()
        store = SessionStore(root, session_id="ns-round")
        store.append("user_prompt", {"role": "user", "content": [{"type": "text", "text": "hello"}]})
        store.append(
            "assistant",
            {"role": "assistant", "content": [{"type": "text", "text": "hi"}], "model": "m", "usage": {"input_tokens": 3, "output_tokens": 5}},
        )
        store.append(
            "compact_boundary",
            {"subtype": "compact_boundary", "content": "summary text", "data": {"cut": 1}},
        )
        transcript = store.transcript()
        self.assertEqual([type(item).__name__ for item in transcript], ["UserMessage", "AssistantMessage", "SystemMessage"])
        self.assertEqual(transcript[1].usage.output_tokens, 5)
        self.assertEqual(transcript[2].subtype, "compact_boundary")
        self.assertEqual(transcript[2].data["cut"], 1)


class RuntimeSessionTests(RuntimeTestCase):
    def test_a_run_without_a_store_still_reports_a_session_id(self):
        # Logs on the host side need something to correlate to, even when the
        # runtime is configured to persist nothing.
        provider = self.provider([text_turn("done")])
        runtime = self.runtime(provider=provider)
        report = self.drive(runtime, "go")
        self.assertFalse(runtime.durable)
        self.assertTrue(report.result.session_id.startswith("ns-"))
        self.assertEqual(report.result.session_id, runtime.session_id)

    def test_a_full_run_writes_a_readable_transcript_and_result(self):
        workspace = self.workspace({"a.txt": "content\n"})
        store = SessionStore(self.workspace(), session_id="ns-run")
        provider = self.provider(
            [
                tool_turn("Read", {"path": "a.txt"}, usage={"input_tokens": 42, "output_tokens": 7}),
                text_turn("done", usage={"input_tokens": 8, "output_tokens": 3}),
            ]
        )
        runtime = self.runtime(provider=provider, workspace=workspace, sessions=store)
        report = self.drive(runtime, "read")
        records, dropped = store.read()
        self.assertEqual(dropped, 0)
        types = [record["type"] for record in records]
        self.assertEqual(types.count("result"), 1)
        self.assertEqual(types[0], "session_start")
        self.assertEqual(types[-1], "session_end")
        self.assertIn("user_prompt", types)
        self.assertIn("assistant", types)
        self.assertIn("tool_result", types)
        result_record = records[types.index("result")]
        self.assertEqual(result_record["subtype"], "success")
        self.assertEqual(result_record["total_usage"]["input_tokens"], 50)
        self.assertEqual(result_record["total_usage"]["output_tokens"], 10)
        self.assertEqual(result_record["num_turns"], 2)

    def test_prompts_and_tool_output_are_persisted_but_never_in_the_trace(self):
        workspace = self.workspace({"a.txt": "TOP-SECRET-CONTENT\n"})
        store = SessionStore(self.workspace())
        provider = self.provider([tool_turn("Read", {"path": "a.txt"}), text_turn("done")])
        self.drive(self.runtime(provider=provider, workspace=workspace, sessions=store), "read the secret file TOP-SECRET-PROMPT")
        body = store.path.read_text(encoding="utf-8")
        self.assertIn("TOP-SECRET-PROMPT", body, "the transcript is the audit trail")
        self.assertIn("TOP-SECRET-CONTENT", body)
        for record in self.tracer.records():
            self.assertNotIn("TOP-SECRET", json.dumps(record.attributes))

    def test_redacted_mode_keeps_the_audit_trail_without_output_bodies(self):
        workspace = self.workspace({"a.txt": "SENSITIVE-BODY\n"})
        store = SessionStore(self.workspace())
        provider = self.provider([tool_turn("Read", {"path": "a.txt"}), text_turn("done")])
        runtime = self.runtime(provider=provider, workspace=workspace, sessions=store, record_tool_output_in_session=False)
        self.drive(runtime, "read")
        body = store.path.read_text(encoding="utf-8")
        self.assertNotIn("SENSITIVE-BODY", body)
        self.assertIn("omitted by configuration", body)
        self.assertIn("Read", body)

    def test_redacted_mode_drops_error_tool_output_bodies(self):
        from providers.base import ToolResultBlock
        secret = "ERROR-SECRET-BODY"
        store = SessionStore(self.workspace())
        runtime = self.runtime(workspace=self.workspace(), sessions=store, record_tool_output_in_session=False)
        runtime._record_tool_message(UserMessage(content=(ToolResultBlock(tool_use_id="t1", content=secret, is_error=True),)))
        body = store.path.read_text(encoding="utf-8")
        self.assertNotIn(secret, body)

    def test_session_stats_summarise_a_run(self):
        store = SessionStore(self.workspace(), session_id="ns-stats")
        store.append("session_start", {})
        store.append("assistant", {"role": "assistant", "content": []})
        store.append("result", {"subtype": "success", "total_cost_usd": 0.25})
        records, _ = store.read()
        summary = summarise(records)
        self.assertEqual(summary["assistant_turns"], 1)
        self.assertEqual(summary["subtype"], "success")
        self.assertAlmostEqual(summary["total_cost_usd"], 0.25)

    def test_a_resumed_session_continues_from_its_transcript(self):
        store = SessionStore(self.workspace(), session_id="ns-resume")
        store.append("user_prompt", {"role": "user", "content": [{"type": "text", "text": "earlier question"}]})
        store.append("assistant", {"role": "assistant", "content": [{"type": "text", "text": "earlier answer"}], "model": "m", "usage": {}})
        provider = self.provider([text_turn("later answer")])
        runtime = self.runtime(provider=provider, sessions=store)
        report = runtime.continue_session("follow-up question")
        self.assertTrue(report.ok)
        sent = json.dumps(provider.requests[0].messages, ensure_ascii=False)
        self.assertIn("earlier question", sent)
        self.assertIn("earlier answer", sent)
        self.assertIn("follow-up question", sent)
        self.assertGreaterEqual(len([event for event in report.events if isinstance(event, AssistantMessage)]), 1)
        self.assertGreaterEqual(len(report.transcript), 3)

    def test_list_sessions_finds_persisted_ids(self):
        root = self.workspace()
        SessionStore(root, session_id="ns-one").append("session_start", {})
        SessionStore(root, session_id="ns-two").append("session_start", {})
        store = SessionStore(root, session_id="ns-one")
        self.assertEqual(store.list_sessions(), ("ns-one", "ns-two"))

    def test_transcript_round_trip_of_tool_result_blocks(self):
        root = self.workspace()
        store = SessionStore(root, session_id="ns-blocks")
        store.append(
            "tool_result",
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "output", "is_error": True}],
            },
        )
        transcript = store.transcript()
        self.assertEqual(len(transcript), 1)
        block = transcript[0].tool_results[0]
        self.assertEqual((block.tool_use_id, block.is_error, block.text()), ("t1", True, "output"))


class WriteTimeChainTests(unittest.TestCase):
    """AU4: the transcript is sealed at write time, not just at export."""

    def workspace(self):
        import tempfile
        from pathlib import Path

        return Path(tempfile.mkdtemp())

    def test_records_are_chained_at_write(self):
        from audit_chain import verify_lines

        root = self.workspace()
        store = SessionStore(root, session_id="ns-chain")
        store.append("session_start", {"content": "a"})
        store.append("assistant", {"content": "b"})
        lines = store.path.read_text(encoding="utf-8").strip().split("\n")
        result = verify_lines(lines)
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.chained, 2)

    def test_tampering_breaks_the_chain(self):
        import json

        from audit_chain import verify_lines

        root = self.workspace()
        store = SessionStore(root, session_id="ns-tamper")
        store.append("session_start", {"content": "a"})
        store.append("assistant", {"content": "b"})
        lines = store.path.read_text(encoding="utf-8").strip().split("\n")
        rec = json.loads(lines[1])
        rec["content"] = "EVIL"
        lines[1] = json.dumps(rec)
        result = verify_lines(lines)
        self.assertFalse(result.ok)

    def test_chain_resumes_across_reopens(self):
        from audit_chain import verify_lines

        root = self.workspace()
        store = SessionStore(root, session_id="ns-resume")
        store.append("session_start", {"content": "a"})
        # Reopen: the new writer picks up the existing chain head.
        store2 = SessionStore(root, session_id="ns-resume")
        store2.append("assistant", {"content": "b"})
        lines = store.path.read_text(encoding="utf-8").strip().split("\n")
        result = verify_lines(lines)
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.chained, 2)

    def test_chain_can_be_disabled(self):
        root = self.workspace()
        store = SessionStore(root, session_id="ns-nochain", chain=False)
        store.append("session_start", {"content": "a"})
        line = store.path.read_text(encoding="utf-8").strip()
        self.assertNotIn("chain_hash", line)


if __name__ == "__main__":
    unittest.main()
