"""Replaying a transcript as frames, and verifying the fork points it recorded.

The promise under test is narrow and load-bearing: **a boundary this listing calls
``verified`` is one ``run --resume-from`` will accept, and one it calls
``digest-mismatch`` is one a resume refuses.** Both commands have to reach that verdict
through the same recomputation, or a preview that disagreed with the real resume would be
worse than no preview at all. The folding itself is asserted as a pure function, because
"what did this run do, turn by turn" is only useful if it is deterministic enough to diff.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

import support  # noqa: F401  (bootstraps sys.path)
from support import RuntimeTestCase

from checkpoints import CHECKPOINT_TYPE, build as build_checkpoint, digest_transcript
from session_replay import (
    DIGEST_MISMATCH,
    MALFORMED,
    PREFIX_SHORT,
    VERIFIED,
    budget_headroom,
    build_replay,
    checkpoint_reports,
    describe_checkpoint,
    fork_preview,
    lineage_of,
    load_replay,
)
from sessions import SessionStore


def record(index: int, kind: str, **fields) -> dict:
    return {"index": index, "ts": f"2026-09-09T00:00:0{index}.000Z", "session_id": "s", "type": kind, **fields}


def start(index: int = 0, **data) -> dict:
    payload = {
        "provider": "scripted",
        "model": "claude-sonnet-4-5",
        "permission_mode": "default",
        "limits": {"max_turns": 25, "max_budget_usd": None, "max_tool_calls": 50},
        "checkpoint_turns": 0,
    }
    payload.update(data)
    return record(index, "session_start", agent="main", content="runtime ready", subtype="init", data=payload)


def prompt(index: int, text: str) -> dict:
    return record(index, "user_prompt", role="user", content=[{"type": "text", "text": text}])


def assistant(index: int, *, text: str = "", tool: dict | None = None, usage: dict | None = None) -> dict:
    content: list[dict] = []
    if text:
        content.append({"type": "text", "text": text})
    if tool:
        content.append({"type": "tool_use", "id": tool.get("id", "t1"), "name": tool["name"], "input": tool["input"]})
    return record(index, "assistant", agent="main", role="assistant", model="m", stop_reason="tool_use" if tool else "end_turn", content=content, usage=usage or {"input_tokens": 10, "output_tokens": 2})


def tool_result(index: int, *, text: str, is_error: bool = False) -> dict:
    return record(index, "tool_result", role="user", content=[{"type": "tool_result", "content": text, "is_error": is_error}])


def result(index: int, *, subtype: str = "success", turns: int = 1, cost: float = 0.0, denials: int = 0) -> dict:
    return record(
        index,
        "result",
        subtype=subtype,
        num_turns=turns,
        total_cost_usd=cost,
        duration_ms=5,
        errors=[],
        is_error=subtype != "success",
        permission_denials=[{} for _ in range(denials)],
        total_usage={"input_tokens": 10, "output_tokens": 2},
    )


class FrameTests(unittest.TestCase):
    def test_a_short_run_becomes_start_prompt_turn_result(self):
        records = [
            start(),
            prompt(1, "read a.txt"),
            assistant(2, tool={"name": "Read", "input": {"path": "a.txt"}, "id": "t1"}),
            tool_result(3, text="content"),
            assistant(4, text="done"),
            result(5, turns=2),
            record(6, "session_end", subtype="success"),
        ]
        replay = build_replay(records, session_id="s")
        self.assertEqual([frame.kind for frame in replay.frames], ["start", "prompt", "turn", "turn", "result"])
        self.assertTrue(replay.sealed)
        self.assertEqual(replay.counts["turns"], 2)
        self.assertEqual(replay.counts["tool_calls"], 1)
        self.assertEqual(replay.frames[2].records, (2, 3), "the tool result belongs to the turn that asked for it")

    def test_the_frame_labels_say_what_happened_rather_than_recording_everything(self):
        records = [start(), prompt(1, "do it"), assistant(2, text="thinking out loud, at some length"), result(3), record(4, "session_end", subtype="success")]
        replay = build_replay(records, session_id="s")
        self.assertIn("turn 1: thinking out loud", replay.frames[2].label)
        rendered = replay.render()
        self.assertIn("start", rendered)
        self.assertIn("result=success", rendered)
        self.assertIn("sealed=yes", rendered)

    def test_a_tool_error_and_a_denial_are_counted_on_the_turn(self):
        records = [
            start(),
            prompt(1, "write it"),
            assistant(2, tool={"name": "Write", "input": {"path": "x"}, "id": "t1"}),
            record(3, "denial", agent="main", data={"tool": "Write", "reason": "permission mode"}),
            tool_result(4, text="refused", is_error=True),
            result(5, subtype="error_during_execution", denials=1),
        ]
        replay = build_replay(records, session_id="s")
        turn = replay.frames[2]
        self.assertEqual(turn.tool_errors, 1)
        self.assertEqual(turn.denials, 1, "a denial rides on the turn it interrupted rather than becoming a frame")
        self.assertTrue(replay.verified, "a transcript with no checkpoints has nothing to distrust")

    def test_a_run_that_never_wrote_a_result_is_visible_as_one(self):
        records = [start(), prompt(1, "go"), assistant(2, text="half an answer")]
        replay = build_replay(records, session_id="s")
        self.assertEqual(replay.result, {})
        self.assertIn("result=(no result)", replay.summary())
        self.assertIn("sealed=NO", replay.summary())

    def test_compaction_gets_its_own_frame(self):
        records = [start(), prompt(1, "go"), record(2, "compact_boundary", content="compact_before_turn", data={"dropped": 3}), assistant(3, text="ok"), result(4)]
        replay = build_replay(records, session_id="s")
        self.assertEqual([frame.kind for frame in replay.frames], ["start", "prompt", "compaction", "turn", "result"])

    def test_unknown_record_types_are_noted_rather_than_dropped(self):
        records = [start(), record(1, "brand_new_type", interesting=True), assistant(2, text="ok"), result(3)]
        replay = build_replay(records, session_id="s")
        noted = [frame for frame in replay.frames if frame.kind == "note"]
        self.assertEqual(len(noted), 1)
        self.assertIn("brand_new_type", noted[0].label)
        self.assertNotIn("session_id", noted[0].label, "the frame is about what is new, not the envelope")

    def test_subagent_records_are_labelled_with_the_agent_that_wrote_them(self):
        records = [start(), prompt(1, "go"), assistant(2, text="child says hi"), result(3)]
        records[2]["agent"] = "explorer"
        replay = build_replay(records, session_id="s")
        self.assertIn("[explorer]", replay.render())

    def test_long_previews_are_bounded(self):
        records = [start(), prompt(1, "y" * 900), assistant(2, text="ok"), result(3)]
        line = build_replay(records).frames[1].line()
        self.assertLess(len(line), 300)
        self.assertTrue(line.endswith("..."))

    def test_token_usage_is_taken_from_the_assistant_record_not_invented(self):
        records = [start(), prompt(1, "go"), assistant(2, text="ok", usage={"input_tokens": 41, "output_tokens": 7}), result(3)]
        turn = build_replay(records).frames[2]
        self.assertEqual((turn.input_tokens, turn.output_tokens), (41, 7))
        self.assertIn("tok 41+7", turn.line())

    def test_cost_is_only_claimed_where_the_transcript_states_it(self):
        records = [start(), prompt(1, "go"), assistant(2, text="ok"), result(3, cost=0.25)]
        replay = build_replay(records)
        self.assertIsNone(replay.frames[2].cost_usd, "no record prices a single turn")
        self.assertEqual(replay.frames[3].cost_usd, 0.25)

    def test_the_json_shape_is_stable_and_self_describing(self):
        records = [start(), prompt(1, "go"), assistant(2, text="ok"), result(3)]
        payload = json.loads(build_replay(records, session_id="s").to_json())
        self.assertEqual(payload["version"], "northstar.replay.v1")
        self.assertEqual(sorted(payload), ["checkpoints", "counts", "frames", "inherited_messages", "lineage", "result", "sealed", "session_id", "truncated_at", "verified", "version"])

    def test_inherited_messages_ignores_file_only_records(self):
        records = [start(), prompt(1, "go"), assistant(2, text="ok"), result(3)]
        replay = build_replay(records)
        self.assertEqual(
            replay.inherited_messages, 2, "only the records that *are* transcript messages count: prompt + assistant"
        )


class CheckpointVerificationTests(unittest.TestCase):
    """Verification, on records built by hand so each failure mode can be provoked.

    The digest a checkpoint carries is computed over the *rebuilt* prefix here. Real
    writer/reader agreement - the thing that makes "verified" mean "a resume will accept
    this" - is pinned against actual transcripts in :class:`RealRunTests`, where a fork is
    both listed here and then really performed.
    """

    def setUp(self) -> None:
        from checkpoints import digest_transcript
        from sessions import transcript_from_records

        self.records = [
            start(),
            prompt(1, "read a.txt"),
            assistant(2, tool={"name": "Read", "input": {"path": "a.txt"}, "id": "t1"}),
            tool_result(3, text="content"),
        ]
        prefix = transcript_from_records(self.records[1:])
        self.digest = digest_transcript(prefix)
        self.records.append(
            record(
                4,
                CHECKPOINT_TYPE,
                session_id="s",
                transcript_len=len(prefix),
                transcript_digest=self.digest,
                turns=1,
                tool_calls=1,
                cost_usd=0.25,
                denials=0,
                usage={"input_tokens": 10, "output_tokens": 2},
                model="m",
                provider="scripted",
                permission_mode="default",
                boundary="after_tools",
            )
        )

    def test_a_boundary_the_file_still_agrees_with_verifies(self):
        reports = checkpoint_reports(self.records)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].status, VERIFIED)
        self.assertNotIn("!", reports[0].line())
        self.assertEqual(reports[0].boundary, "after_tools")

    def test_editing_one_message_in_the_prefix_breaks_the_boundary(self):
        tampered = [dict(item) for item in self.records]
        tampered[1]["content"][0]["text"] = "read a.txt (rewritten by someone else)"
        report = describe_checkpoint(tampered[4], tampered)
        self.assertEqual(report.status, DIGEST_MISMATCH)
        self.assertIn("a resume would refuse it", report.detail)

    def test_a_transcript_shorter_than_its_own_boundary_is_its_own_status(self):
        report = describe_checkpoint(self.records[4], self.records[:2])
        self.assertEqual(report.status, PREFIX_SHORT)
        self.assertIn("shorter than its own checkpoint", report.detail)

    def test_a_recognised_checkpoint_missing_counters_is_malformed_not_guessed(self):
        broken = dict(self.records[4])
        del broken["turns"]
        del broken["cost_usd"]
        report = describe_checkpoint(broken, self.records)
        self.assertEqual(report.status, MALFORMED)
        self.assertIn("turns", report.detail)

    def test_verification_reports_only_checkpoint_records(self):
        self.assertEqual(checkpoint_reports([start(), prompt(1, "go")]), ())

    def test_the_report_carries_the_counters_a_resume_would_inherit(self):
        report = checkpoint_reports(self.records)[0]
        self.assertEqual((report.turn, report.tool_calls, report.transcript_len), (1, 1, 3))
        self.assertEqual(report.digest_prefix, self.digest[:12])
        self.assertEqual(report.cost_usd, 0.25)
        self.assertEqual(report.as_dict()["status"], VERIFIED)

    def test_a_checkpoint_frame_carries_its_report_into_the_replay(self):
        replay = build_replay(self.records, session_id="s")
        frames = [frame for frame in replay.frames if frame.kind == "checkpoint"]
        self.assertEqual(len(frames), 1)
        self.assertTrue(frames[0].checkpoint.verified)
        self.assertIn("boundary after_tools", frames[0].label)
        self.assertIn("all verified", replay.summary())

    def test_an_unverified_checkpoint_shows_its_reason_in_the_render(self):
        tampered = [dict(item) for item in self.records]
        tampered[1]["content"][0]["text"] = "rewritten"
        rendered = build_replay(tampered, session_id="s").render()
        self.assertIn("UNVERIFIED", rendered)
        self.assertIn("digests to", rendered)

class LineageTests(unittest.TestCase):
    def test_a_fork_names_the_parent_and_the_boundary_it_came_from(self):
        origin = {"parent_session": "p", "checkpoint_record": 4, "turns_inherited": 2, "tool_calls_inherited": 3, "cost_usd_inherited": 0.5}
        records = [start(0, resumed_from=origin)]
        lineage = lineage_of(records)
        self.assertEqual(lineage["parent_session"], "p")
        self.assertEqual((lineage["turns_inherited"], lineage["tool_calls_inherited"]), (2, 3))

    def test_a_run_that_started_itself_has_no_lineage(self):
        self.assertEqual(lineage_of([start()]), {})

    def test_the_rendered_replay_shows_the_inheritance(self):
        origin = {"parent_session": "p", "checkpoint_record": 4, "turns_inherited": 2, "tool_calls_inherited": 3, "cost_usd_inherited": 0.5}
        records = [
            start(0, resumed_from=origin),
            prompt(1, "go"),
            assistant(2, text="ok"),
            result(3, cost=0.75),
        ]
        rendered = build_replay(records, session_id="child").render()
        self.assertIn("forked from session p record #4", rendered)
        self.assertIn("inherits 2 turn(s), 3 call(s), $0.500000", rendered)


class BudgetHeadroomTests(unittest.TestCase):
    def report(self, cost: float):
        from session_replay import CheckpointReport

        return CheckpointReport(record_index=4, status=VERIFIED, cost_usd=cost)

    def test_no_ceiling_means_there_is_nothing_to_check(self):
        remaining, note = budget_headroom([start()], self.report(0.1))
        self.assertIsNone(remaining)
        self.assertEqual(note, "")

    def test_a_ceiling_leaves_room_is_stated_as_room(self):
        records = [start(0, limits={"max_budget_usd": 5.0})]
        remaining, note = budget_headroom(records, self.report(4.25))
        self.assertAlmostEqual(remaining, 0.75)
        self.assertIn("may still use $0.750000", note)

    def test_a_spent_ceiling_is_announced_as_a_refusal(self):
        records = [start(0, limits={"max_budget_usd": 5.0})]
        _remaining, note = budget_headroom(records, self.report(5.0))
        self.assertIn("would be refused", note)


class RealRunTests(RuntimeTestCase):
    """The two commands against transcripts a real run wrote."""

    def invoke(self, *argv: str) -> tuple[int, str, str]:
        import contextlib
        import io

        from cli import main

        out, err = io.StringIO(), io.StringIO()
        saved, sys.stdin = sys.stdin, io.StringIO("")
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(list(argv))
        finally:
            sys.stdin = saved
        return code, out.getvalue(), err.getvalue()

    def recorded_run(self, *, budget: str | None = "1") -> tuple[Path, str]:
        root = self.workspace({"a.txt": "content\n"})
        sessions = Path(self.temp_dir()) / "sessions"
        script = Path(self.temp_dir()) / "script.json"
        script.write_text(json.dumps([{"tool": {"name": "Read", "input": {"path": "a.txt"}, "id": "t1"}}, {"text": "read it"}]), encoding="utf-8")
        argv = ["run", "--workspace", str(root), "--session-dir", str(sessions), "--script", str(script), "--checkpoint-turns", "1", "--prompt", "read a.txt"]
        if budget:
            argv += ["--max-budget-usd", budget]
        code, _out, err = self.invoke(*argv)
        self.assertEqual(code, 0, err)
        session = next(path.name[: -len(".jsonl")] for path in sessions.glob("*.jsonl"))
        return sessions, session

    def test_the_listing_and_a_real_resume_agree_on_the_same_boundary(self):
        # The promise in one test: this module says "verified", and the command that would
        # spend money agrees by resuming from it.
        sessions, session = self.recorded_run()
        code, out, _ = self.invoke("sessions", "checkpoints", "--session-dir", str(sessions), "--session", session)
        self.assertEqual(code, 0)
        self.assertEqual(out.count("[verified]"), 2)
        code, _out, err = self.invoke(
            "run", "--workspace", str(self.workspace({"a.txt": "content\n"})), "--session-dir", str(sessions),
            "--resume-from", session, "--resume-record", "6", "--prompt", "continue", "--scripted-text", "ok",
        )
        self.assertEqual(code, 0, err)

    def test_a_run_that_recorded_checkpoints_lists_them_as_verified(self):
        sessions, session = self.recorded_run()
        code, out, err = self.invoke("sessions", "checkpoints", "--session-dir", str(sessions), "--session", session)
        self.assertEqual(code, 0, err)
        self.assertIn("[verified]", out)
        self.assertIn("may still use $1.000000", out)

    def test_the_listing_defaults_to_every_transcript_in_the_directory(self):
        sessions, _ = self.recorded_run()
        code, out, _ = self.invoke("sessions", "checkpoints", "--session-dir", str(sessions))
        self.assertEqual(code, 0)
        self.assertEqual(out.count("[verified]"), 2, "one run at two turn boundaries")

    def test_an_edited_transcript_fails_the_listing_and_a_resume(self):
        sessions, session = self.recorded_run()
        path = sessions / f"{session}.jsonl"
        lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        for item in lines:
            if item.get("type") == "user_prompt":
                item["content"][0]["text"] = "read a.txt, or whatever"
        path.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in lines), encoding="utf-8")

        code, out, _ = self.invoke("sessions", "checkpoints", "--session-dir", str(sessions), "--session", session)
        self.assertEqual(code, 1, "a boundary the file no longer matches has to be loud, not silent")
        self.assertIn("digest-mismatch", out)

        # The same verdict, from the command that would have spent a run finding it out.
        code, _out, err = self.invoke(
            "run", "--workspace", str(self.workspace()), "--session-dir", str(sessions), "--resume-from", session,
            "--resume-record", "4", "--prompt", "continue", "--scripted-text", "x",
        )
        self.assertNotEqual(code, 0)
        self.assertIn("resume refused", err)
        self.assertIn("does not match the checkpoint digest", err)

    def test_replay_renders_the_whole_run_and_the_cut_shows_only_the_inheritance(self):
        sessions, session = self.recorded_run()
        code, whole, _ = self.invoke("sessions", "replay", "--session-dir", str(sessions), session)
        self.assertEqual(code, 0)
        self.assertIn("prompt: read a.txt", whole)
        self.assertIn("turn 1:", whole)
        self.assertIn("result=success", whole)
        self.assertNotIn("cut at record", whole)

        code, cut, _ = self.invoke("sessions", "replay", "--session-dir", str(sessions), session, "--from-checkpoint", "4")
        self.assertEqual(code, 0)
        self.assertIn("cut at record #4", cut)
        self.assertIn("3 message(s) inherited", cut)
        self.assertNotIn("turn 2", cut, "the second turn happened after the boundary")

    def test_a_child_replay_names_the_parent_and_the_boundary(self):
        sessions, parent = self.recorded_run()
        code, _out, err = self.invoke(
            "run", "--workspace", str(self.workspace({"a.txt": "content\n"})), "--session-dir", str(sessions),
            "--resume-from", parent, "--resume-record", "4", "--prompt", "continue", "--scripted-text", "thanks for the context",
        )
        self.assertEqual(code, 0, err)
        child = next(
            path.name[: -len(".jsonl")] for path in sessions.glob("*.jsonl") if path.name != f"{parent}.jsonl"
        )
        code, out, _ = self.invoke("sessions", "replay", "--session-dir", str(sessions), child)
        self.assertEqual(code, 0)
        self.assertIn(f"forked from session {parent} record #4", out)

    def test_replay_json_is_the_same_report_a_machine_can_read(self):
        sessions, session = self.recorded_run()
        code, out, _ = self.invoke("sessions", "replay", "--session-dir", str(sessions), session, "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(payload["verified"])
        self.assertEqual(payload["counts"]["turns"], 2)
        self.assertEqual([frame["kind"] for frame in payload["frames"]][:2], ["start", "prompt"])

    def test_checkpoints_json_is_one_object_per_transcript(self):
        sessions, session = self.recorded_run()
        code, out, _ = self.invoke("sessions", "checkpoints", "--session-dir", str(sessions), "--session", session, "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["session_id"], session)
        self.assertTrue(payload["verified"])
        self.assertEqual(len(payload["checkpoints"]), 2)

    def test_an_unknown_session_or_record_is_reported_rather_than_guessed(self):
        sessions, session = self.recorded_run()
        code, _out, err = self.invoke("sessions", "replay", "--session-dir", str(sessions), "no-such-session")
        self.assertEqual(code, 1)
        self.assertIn("no transcript", err)
        code, _out, err = self.invoke("sessions", "replay", "--session-dir", str(sessions), session, "--from-checkpoint", "99")
        self.assertEqual(code, 64, "asking for a boundary that does not exist is a bad command, not a bad transcript")
        self.assertIn("no checkpoint at record #99", err)

    def test_a_run_without_checkpoints_says_so_and_still_replays(self):
        sessions = Path(self.temp_dir()) / "sessions"
        root = self.workspace({"a.txt": "content\n"})
        code, _out, err = self.invoke(
            "run", "--workspace", str(root), "--session-dir", str(sessions), "--prompt", "hi", "--scripted-text", "hello",
        )
        self.assertEqual(code, 0, err)
        session = next(path.name[: -len(".jsonl")] for path in sessions.glob("*.jsonl"))
        code, out, _ = self.invoke("sessions", "checkpoints", "--session-dir", str(sessions))
        self.assertEqual(code, 0)
        self.assertIn("no checkpoints", out)
        code, out, _ = self.invoke("sessions", "replay", "--session-dir", str(sessions), session)
        self.assertEqual(code, 0)
        self.assertIn("no checkpoints", out)

    def test_the_reader_helpers_return_the_objects_the_commands_print(self):
        from sessions import load_jsonl

        sessions, session = self.recorded_run()
        replay, error = load_replay(sessions, session)
        self.assertEqual(error, "")
        self.assertTrue(replay.verified)
        self.assertEqual(len(replay.checkpoints), 2)

        records, _dropped = load_jsonl(sessions / f"{session}.jsonl")
        cut, report, error = fork_preview(records, record_index=4, session_id=session)
        self.assertEqual(error, "")
        self.assertEqual(report.status, VERIFIED)
        self.assertEqual(cut.truncated_at, 5, "the cut is just past the boundary record itself")
        self.assertEqual(cut.inherited_messages, 3)

        _replay, _report, error = fork_preview(records, record_index=99)
        self.assertIn("no checkpoint at record #99", error)

    def test_show_and_list_still_work_after_the_two_new_actions(self):
        sessions, session = self.recorded_run()
        code, out, _ = self.invoke("sessions", "list", "--session-dir", str(sessions))
        self.assertEqual(code, 0)
        self.assertIn(session, out)
        code, out, _ = self.invoke("sessions", "show", "--session-dir", str(sessions), session)
        self.assertEqual(code, 0)
        self.assertIn("checkpoint", out)


class TranscriptFixtureTests(unittest.TestCase):
    """The record the writer emits is the record the replay reads - no private fast path."""

    def test_a_stored_checkpoint_record_is_replayable(self):
        import tempfile

        from support import text_turn  # noqa: F401  (keeps the support import honest in this file)

        root = Path(tempfile.mkdtemp(prefix="nsar-replaystore-"))
        store = SessionStore(root, session_id="s")
        store.append("user_prompt", {"role": "user", "content": [{"type": "text", "text": "go"}]})
        store.append(
            CHECKPOINT_TYPE,
            {
                "session_id": "s",
                "transcript_len": 0,
                "transcript_digest": digest_transcript([]),
                "turns": 1,
                "tool_calls": 0,
                "cost_usd": 0.0,
                "usage": {},
                "model": "m",
                "provider": "scripted",
                "permission_mode": "default",
                "denials": 0,
                "boundary": "after_tools",
            },
        )
        records, dropped = store.read("s")
        self.assertEqual(dropped, 0)
        self.assertEqual([item["type"] for item in records], ["user_prompt", CHECKPOINT_TYPE])
        self.assertEqual([item["index"] for item in records], [0, 1], "the reader numbers records by line")
        reports = checkpoint_reports(records)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].status, VERIFIED, "a boundary before any message still digests: the cut follows transcript_len, not the line count")

        lying = dict(records[1])
        lying["transcript_len"] = 1
        lying["index"] = 2
        store.append(CHECKPOINT_TYPE, {key: value for key, value in lying.items() if key not in ("index", "ts", "type", "session_id", "agent")})
        records, _dropped = store.read("s")
        mismatched = checkpoint_reports(records)[1]
        self.assertEqual(mismatched.status, DIGEST_MISMATCH, "claiming one message where the digest covers none is exactly the edit this check exists to catch")


if __name__ == "__main__":
    unittest.main()
