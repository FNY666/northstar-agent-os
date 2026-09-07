"""Session transcripts: append-only JSONL, fsync per write, tail-truncation
recovery, and a session id even when nothing is persisted.
"""
from __future__ import annotations

import json
import os
import stat
import unittest
from pathlib import Path

import support  # noqa: F401
from support import RuntimeTestCase, text_turn, tool_turn

import sessions
from providers.base import AssistantMessage, ResultMessage, SystemMessage, UserMessage
from sessions import (
    RECORD_TYPES,
    SessionIntegrityError,
    SessionStore,
    load_jsonl,
    new_session_id,
    resolve_session_id,
    summarise,
    transcript_from_records,
)


class SessionIdTests(unittest.TestCase):
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
        self.assertEqual(len(RECORD_TYPES), 12)


class WriteTests(RuntimeTestCase):
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

    def test_a_new_writer_resumes_the_next_index_from_an_existing_transcript(self):
        root = self.workspace()
        first = SessionStore(root, session_id="ns-resume-index")
        first.append("session_start", {})
        second = SessionStore(root, session_id="ns-resume-index")
        second.append("informational", {"message": "continued"})
        records, _ = load_jsonl(first.path)
        self.assertEqual([record["index"] for record in records], [0, 1])

    def test_transcript_files_are_owner_readable_only(self):
        root = self.workspace()
        store = SessionStore(root, session_id="ns-perm")
        store.append("session_start", {})
        mode = stat.S_IMODE(os.stat(store.path).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(root).st_mode), 0o700)

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
        records, _ = store.read()
        self.assertEqual([record["index"] for record in records], list(range(len(records))))

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


if __name__ == "__main__":
    unittest.main()
