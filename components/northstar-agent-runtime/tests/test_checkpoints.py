"""Turn-boundary checkpoints: resumable, verifiable, and unable to launder a budget.

The properties this file exists to pin down:

- a checkpoint is written only at a *complete* turn boundary, and only when asked;
- resuming rebuilds exactly the prefix the checkpoint described, verified by digest;
- **a resumed run inherits the consumed counters** - turns, tool calls and cost - so
  resuming cannot hand out a fresh budget (this was the real bug: ceilings were
  per-run and resume started a new run);
- a fork never touches the parent file;
- a tampered or mismatched transcript is refused, not continued.
"""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

import support  # noqa: F401  (bootstraps sys.path)
from support import RuntimeTestCase, tool_turn

from checkpoints import (
    CHECKPOINT_TYPE,
    CheckpointError,
    build,
    digest_transcript,
    from_record,
    prepare_resume,
    select,
)
from providers.base import AssistantMessage, TextBlock, UserMessage
from sessions import SessionStore


def _checkpoint_dict(**overrides) -> dict:
    base = {
        "type": CHECKPOINT_TYPE,
        "index": 4,
        "session_id": "s-1",
        "transcript_len": 2,
        "transcript_digest": "0" * 64,
        "turns": 2,
        "tool_calls": 1,
        "cost_usd": 0.5,
        "usage": {"input_tokens": 10, "output_tokens": 3},
        "model": "scripted",
        "provider": "scripted",
        "permission_mode": "default",
        "denials": 0,
    }
    base.update(overrides)
    return base


class CheckpointRecordTests(unittest.TestCase):
    def test_the_digest_is_stable_and_canonical(self):
        messages = [UserMessage.text_block("go"), AssistantMessage(content=(TextBlock(text="done"),), model="m")]
        first = digest_transcript(messages)
        self.assertEqual(first, digest_transcript(list(messages)))
        self.assertEqual(len(first), 64)
        changed = [UserMessage.text_block("go"), AssistantMessage(content=(TextBlock(text="DONE"),), model="m")]
        self.assertNotEqual(first, digest_transcript(changed))

    def test_build_records_length_and_digest(self):
        messages = [UserMessage.text_block("go")]
        payload = build(
            session_id="s-1",
            record_index=0,
            transcript=messages,
            turns=1,
            tool_calls=0,
            cost_usd=0.125,
            usage=object(),
            model="m",
            provider="scripted",
            permission_mode="default",
        )
        self.assertEqual(payload["transcript_len"], 1)
        self.assertEqual(payload["transcript_digest"], digest_transcript(messages))
        self.assertEqual(payload["cost_usd"], 0.125)
        self.assertEqual(json.loads(json.dumps(payload))["turns"], 1)

    def test_non_checkpoint_records_are_skipped_not_fatal(self):
        self.assertIsNone(from_record({"type": "assistant", "index": 1}))
        self.assertIsNone(select([{"type": "assistant"}, {"type": "session_start"}]))

    def test_a_recognised_but_broken_checkpoint_raises(self):
        # Silently restoring partial counters is how the budget leak comes back.
        with self.assertRaises(CheckpointError) as caught:
            from_record(_checkpoint_dict(cost_usd=None))
        self.assertIn("cost_usd", str(caught.exception))

    def test_select_takes_the_latest_unless_named(self):
        records = [_checkpoint_dict(index=2, turns=1), _checkpoint_dict(index=9, turns=4)]
        self.assertEqual(select(records).turns, 4)
        self.assertEqual(select(records, record_index=2).turns, 1)
        with self.assertRaises(CheckpointError) as caught:
            select(records, record_index=7)
        self.assertIn("#2, #9", str(caught.exception), "the error must say what was available")


class PrepareResumeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.messages = [
            UserMessage.text_block("go"),
            AssistantMessage(content=(TextBlock(text="one"),), model="m"),
            UserMessage.text_block("again"),
            AssistantMessage(content=(TextBlock(text="two"),), model="m"),
        ]
        self.payload = build(
            session_id="s-1",
            record_index=3,
            transcript=self.messages[:2],
            turns=1,
            tool_calls=0,
            cost_usd=0.0,
            usage=object(),
            model="m",
            provider="scripted",
            permission_mode="default",
        )
        self.checkpoint = from_record({"type": CHECKPOINT_TYPE, "index": 3, "session_id": "s-1", **self.payload})

    def test_the_prefix_is_cut_at_the_boundary(self):
        self.assertEqual(len(prepare_resume(self.checkpoint, self.messages)), 2)

    def test_a_different_history_is_refused(self):
        tampered = [self.messages[0], AssistantMessage(content=(TextBlock(text="rewritten"),), model="m"), *self.messages[2:]]
        with self.assertRaises(CheckpointError) as caught:
            prepare_resume(self.checkpoint, tampered)
        self.assertIn("does not match the checkpoint digest", str(caught.exception))

    def test_a_shorter_transcript_is_refused(self):
        with self.assertRaises(CheckpointError):
            prepare_resume(self.checkpoint, self.messages[:1])

    def test_a_checkpoint_from_another_session_is_refused(self):
        with self.assertRaises(CheckpointError) as caught:
            prepare_resume(self.checkpoint, self.messages, expected_session_id="s-2")
        self.assertIn("not 's-2'", str(caught.exception))

    def test_the_label_is_readable_in_an_error_or_log(self):
        self.assertIn("2 messages", self.checkpoint.label)


class LoopCheckpointTests(RuntimeTestCase):
    def _scripted(self, turns):
        from providers.scripted import ScriptedProvider

        return ScriptedProvider(turns, model="claude-sonnet-4-5")

    def _records(self, store: SessionStore) -> list[dict]:
        return store.read(store.session_id)[0]

    def test_no_checkpoint_records_by_default(self):
        store = self.session_store()
        self.drive(self.runtime([{"text": "done"}], sessions=store))
        self.assertEqual([record for record in self._records(store) if record.get("type") == CHECKPOINT_TYPE], [])

    def test_one_record_per_boundary_at_the_requested_cadence(self):
        root = self.workspace({"a.txt": "x"})
        store = self.session_store()
        self.drive(
            self.runtime(
                [tool_turn("Read", {"path": "a.txt"}), tool_turn("Read", {"path": "a.txt"}), {"text": "done"}],
                workspace=root,
                sessions=store,
                checkpoint_turns=1,
            ),
        )
        boundaries = [record for record in self._records(store) if record.get("type") == CHECKPOINT_TYPE]
        self.assertEqual([record["turns"] for record in boundaries], [1, 2, 3], "every boundary, including the last text turn")
        self.assertEqual([record["boundary"] for record in boundaries], ["after_tools", "after_tools", "after_text"])
        lengths = [record["transcript_len"] for record in boundaries]
        self.assertEqual(lengths, sorted(set(lengths)), "lengths grow monotonically and never repeat")
        replayed = store.transcript(store.session_id)
        for record in boundaries:
            checkpoint = from_record(record)
            # The record must describe a prefix that still verifies, which is the
            # only property a fork actually depends on.
            self.assertEqual(len(prepare_resume(checkpoint, replayed)), checkpoint.transcript_len)

    def test_cadence_skips_boundaries(self):
        root = self.workspace({"a.txt": "x"})
        store = self.session_store()
        self.drive(
            self.runtime(
                [tool_turn("Read", {"path": "a.txt"}), tool_turn("Read", {"path": "a.txt"}), tool_turn("Read", {"path": "a.txt"}), {"text": "x"}],
                workspace=root,
                sessions=store,
                checkpoint_turns=2,
            )
        )
        # cadence 2 with four turns: the two tool boundaries land on turns 2 and 4,
        # and turn 1 / turn 3 are deliberately skipped.
        self.assertEqual([r["turns"] for r in self._records(store) if r.get("type") == CHECKPOINT_TYPE], [2, 4])

    def test_a_resumed_run_inherits_the_counters(self):
        root = self.workspace()
        store = self.session_store()
        first = self.runtime(
            [tool_turn("Read", {"path": "a.txt"}), {"text": "done"}],
            workspace=root,
            sessions=store,
            checkpoint_turns=1,
        )
        self.drive(first)
        records, _ = store.read(store.session_id)
        checkpoint = select(records)
        self.assertIsNotNone(checkpoint)

        # Same ceilings, resumed: the parent already used 1 turn, so a run capped at
        # 1 turn has nothing left - the ceiling binds the lineage, not the process.
        replayed = store.transcript(store.session_id)
        resumed = self.runtime(
            [{"text": "should never be asked"}],
            workspace=root,
            resume_from=checkpoint,
            max_turns=checkpoint.turns,
        )
        report = resumed.run_collect("go", resume=replayed)
        self.assertEqual(report.subtype, "error_max_turns")
        self.assertEqual(report.result.num_turns, checkpoint.turns)
        init = next(event for event in report.events if getattr(event, "subtype", "") == "init")
        self.assertEqual(init.data["resumed_from"]["turns_inherited"], checkpoint.turns)
        self.assertEqual(init.data["resumed_from"]["checkpoint_record"], checkpoint.record_index)

    def test_resuming_without_carrying_the_cost_is_refused(self):
        root = self.workspace()
        store = self.session_store()
        provider = self._scripted([{"text": "expensive answer", "usage": {"input_tokens": 2_000_000}}])
        first = self.runtime(provider=provider, workspace=root, sessions=store, checkpoint_turns=1)
        self.drive(first)
        records, _ = store.read(store.session_id)
        checkpoint = select(records)
        self.assertGreater(checkpoint.cost_usd, 0, "the fixture must actually have spent money")

        # The default runtime builds a fresh Budget at zero - precisely the mistake
        # this guard exists to catch.
        with self.assertRaises(Exception) as caught:
            resumed = self.runtime(
                [{"text": "more"}],
                workspace=root,
                sessions=store,
                resume_from=checkpoint,
                max_turns=3,
            )
            resumed.run_collect("go", resume=store.transcript(store.session_id))
        self.assertIn("carrying the parent's spend", str(caught.exception))

    def test_a_fork_records_the_parent_and_leaves_it_alone(self):
        root = self.workspace()
        store = self.session_store()
        self.drive(self.runtime([{"text": "done"}], workspace=root, sessions=store, checkpoint_turns=1))
        parent_path = store.path
        before = parent_path.read_bytes()
        records, _ = store.read(store.session_id)
        checkpoint = select(records)
        child = self.session_store()
        replayed = store.transcript(store.session_id)
        child_runtime = self.runtime(
            [{"text": "continued"}],
            workspace=root,
            sessions=child,
            resume_from=checkpoint,
            parent_session=store.session_id,
            max_turns=5,
            budget=__import__("budget").Budget(max_budget_usd=None, total_cost_usd=checkpoint.cost_usd),
        )
        child_runtime.run_collect("go", resume=replayed)
        self.assertEqual(parent_path.read_bytes(), before, "a fork must not write to the parent transcript")
        self.assertNotEqual(child.session_id, store.session_id)
        child_records, _ = child.read(child.session_id)
        init = next(record for record in child_records if record.get("type") == "session_start")
        self.assertEqual(init["data"]["resumed_from"]["parent_session"], store.session_id)
        self.assertTrue(init["data"]["resumed_from"]["forked"])
        self.assertEqual(init["data"]["resumed_from"]["transcript_digest"], checkpoint.transcript_digest[:12])

    def test_a_fork_from_a_tampered_parent_is_refused(self):
        root = self.workspace()
        store = self.session_store()
        self.drive(self.runtime([tool_turn("Read", {"path": "a.txt"}), {"text": "done"}], workspace=root, sessions=store, checkpoint_turns=1))
        records, _ = store.read(store.session_id)
        checkpoint = select(records)
        lines = store.path.read_text(encoding="utf-8").splitlines()
        # Rewrite one assistant message body inside the checkpointed prefix: the
        # digest is the only thing that can notice.
        for position, line in enumerate(lines):
            record = json.loads(line)
            if record.get("type") == "assistant":
                record["content"] = [{"type": "text", "text": "edited after the fact"}]
                lines[position] = json.dumps(record)
                break
        store.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        replayed = store.transcript(store.session_id)
        # Reopen the *same* store directory: a second store pointed at a different
        # directory would read a different (empty) history and prove nothing.
        tampered = SessionStore(store.directory, session_id=store.session_id)
        replayed = tampered.transcript(store.session_id)
        with self.assertRaises(Exception) as caught:
            tampered_runtime = self.runtime(
                [{"text": "x"}],
                workspace=root,
                resume_from=select(tampered.read(store.session_id)[0]),
                max_turns=5,
            )
            tampered_runtime.run_collect("again", resume=tampered.transcript(store.session_id))
        self.assertIn("does not match the checkpoint digest", str(caught.exception))


class CliCheckpointTests(RuntimeTestCase):
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

    def _script(self, body: list[dict]) -> Path:
        path = Path(self.temp_dir()) / "script.json"
        path.write_text(json.dumps({"turns": body}), encoding="utf-8")
        return path

    def test_checkpoint_then_fork_end_to_end(self):
        root = self.workspace({"a.txt": "content"})
        sessions = Path(self.temp_dir()) / "sessions"
        script = self._script([{"tool": {"name": "Read", "input": {"path": "a.txt"}}}, {"text": "read it"}])
        code, out, err = self.invoke(
            "run",
            "--workspace",
            str(root),
            "--session-dir",
            str(sessions),
            "--script",
            str(script),
            "--checkpoint-turns",
            "1",
            "--prompt",
            "read a.txt",
        )
        self.assertEqual(code, 0, err)
        parent = next(path.name[: -len(".jsonl")] for path in sessions.glob("*.jsonl"))
        parent_bytes = (sessions / f"{parent}.jsonl").read_bytes()

        code, out, err = self.invoke(
            "run",
            "--workspace",
            str(root),
            "--session-dir",
            str(sessions),
            "--script",
            str(self._script([{"text": "thanks for the context"}])),
            "--resume-from",
            parent,
            "--prompt",
            "continue",
        )
        self.assertEqual(code, 0, err)
        children = [path for path in sessions.glob("*.jsonl") if path.name != f"{parent}.jsonl"]
        self.assertEqual(len(children), 1, "the fork wrote a new file")
        self.assertEqual((sessions / f"{parent}.jsonl").read_bytes(), parent_bytes, "the parent is untouched")
        child_records = [json.loads(line) for line in children[0].read_text(encoding="utf-8").splitlines()]
        start = next(record for record in child_records if record["type"] == "session_start")
        self.assertEqual(start["data"]["resumed_from"]["parent_session"], parent)
        self.assertEqual(start["data"]["resumed_from"]["transcript_len"], 4)

    def test_resuming_a_run_with_no_checkpoints_says_why(self):
        root = self.workspace()
        sessions = Path(self.temp_dir()) / "sessions"
        sessions.mkdir()
        (sessions / "empty.jsonl").write_text("", encoding="utf-8")
        code, _, err = self.invoke("run", "--workspace", str(root), "--session-dir", str(sessions), "--resume-from", "empty", "--prompt", "x", "--scripted-text", "y")
        self.assertEqual(code, 64)
        self.assertIn("no checkpoints", err)
        self.assertIn("--checkpoint-turns", err)

    def test_a_cadence_that_could_never_fire_is_refused(self):
        code, _, err = self.invoke("run", "--workspace", ".", "--max-turns", "2", "--checkpoint-turns", "5", "--prompt", "x", "--scripted-text", "y")
        self.assertEqual(code, 64)
        self.assertIn("no checkpoint could ever be written", err)

    def test_the_two_resume_flags_are_mutually_exclusive(self):
        code, _, err = self.invoke("run", "--workspace", ".", "--resume", "a", "--resume-from", "b", "--prompt", "x", "--scripted-text", "y")
        self.assertEqual(code, 64)
        self.assertIn("choose one", err)

    def test_resume_record_needs_resume_from(self):
        code, _, err = self.invoke("run", "--workspace", ".", "--resume-record", "3", "--prompt", "x", "--scripted-text", "y")
        self.assertEqual(code, 64)
        self.assertIn("--resume-record only means something", err)

    def test_a_resumed_run_cannot_spend_a_second_budget(self):
        """The point of the whole feature: ceilings bind the lineage, not the process."""
        root = self.workspace()
        sessions = Path(self.temp_dir()) / "sessions"
        script = self._script([{"text": "costly", "usage": {"input_tokens": 2_000_000}}])
        code, out, _ = self.invoke(
            "run",
            "--workspace",
            str(root),
            "--session-dir",
            str(sessions),
            "--script",
            str(script),
            "--checkpoint-turns",
            "1",
            "--max-budget-usd",
            "100",
            "--prompt",
            "go",
        )
        self.assertEqual(code, 0)
        parent = next(path.name[: -len(".jsonl")] for path in sessions.glob("*.jsonl"))
        parent_records = [json.loads(line) for line in (sessions / f"{parent}.jsonl").read_text(encoding="utf-8").splitlines()]
        spent = next(record["cost_usd"] for record in parent_records if record["type"] == CHECKPOINT_TYPE)
        self.assertGreater(spent, 1, "the fixture spent more than the resumed cap")

        code, out, err = self.invoke(
            "run",
            "--workspace",
            str(root),
            "--session-dir",
            str(sessions),
            "--script",
            str(self._script([{"text": "one more thing"}])),
            "--resume-from",
            parent,
            "--max-budget-usd",
            "1",
            "--prompt",
            "continue",
        )
        self.assertEqual(code, 4, "error_max_budget_usd: the parent's spend carried over")
        self.assertIn("error_max_budget_usd", out)
        self.assertNotIn("one more thing", out)


class SdkParityTests(RuntimeTestCase):
    """The same guarantees through the embedding API, because that is how hosts use it."""

    def _options(self, **kwargs):
        from sdk import RunOptions

        return RunOptions(scripted_turns=[{"text": "costly", "usage": {"input_tokens": 2_000_000}}], **kwargs)

    def test_a_forked_run_cannot_spend_a_second_budget(self):
        from sdk import run

        root = self.workspace()
        sessions = Path(self.temp_dir()) / "sessions"
        first = run(self._options(prompt="go", workspace=str(root), session_dir=str(sessions), checkpoint_turns=1, max_budget_usd=100))
        self.assertEqual(first.subtype, "success")
        forked = run(
            self._options(
                prompt="continue",
                workspace=str(root),
                session_dir=str(sessions),
                resume_from=first.session_id,
                max_budget_usd=1,
            )
        )
        self.assertEqual(forked.subtype, "error_max_budget_usd", "the parent's spend carried over")
        self.assertEqual(sorted(path.name for path in sessions.glob("*.jsonl")), sorted([f"{first.session_id}.jsonl", f"{forked.session_id}.jsonl"]))
        self.assertNotEqual(forked.session_id, first.session_id)

    def test_resume_from_needs_a_session_dir(self):
        from sdk import RunOptions, run

        with self.assertRaises(ValueError) as caught:
            run(RunOptions(prompt="x", resume_from="s-1", scripted_turns=[{"text": "y"}]))
        self.assertIn("session_dir", str(caught.exception))

    def test_a_session_without_checkpoints_says_what_to_add(self):
        from sdk import RunOptions, run

        root = self.workspace()
        sessions = Path(self.temp_dir()) / "sessions"
        plain = run(RunOptions(prompt="go", workspace=str(root), session_dir=str(sessions), scripted_turns=[{"text": "hi"}]))
        with self.assertRaises(ValueError) as caught:
            run(RunOptions(prompt="x", workspace=str(root), session_dir=str(sessions), resume_from=plain.session_id, scripted_turns=[{"text": "y"}]))
        self.assertIn("checkpoint_turns", str(caught.exception))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
