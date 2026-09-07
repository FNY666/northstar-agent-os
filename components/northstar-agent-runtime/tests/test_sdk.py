"""The Python API (sdk.py): embed one governed run, no subprocess."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import sdk
from events import EXIT_CODES, event_to_dict
from sdk import RunOptions, RunReport, run, stream_run


DEMO_WORKSPACE = "examples/demo/workspace"
READ_TURNS = [
    {"tools": [{"name": "Read", "input": {"path": "notes.txt"}}]},
    {"text": "Read done."},
]
WRITE_TURNS = [
    {"tools": [{"name": "Write", "input": {"path": "out.txt", "content": "hello"}}]},
    {"text": "Wrote out.txt."},
]


class RunReportTests(unittest.TestCase):
    def test_successful_run_reports_structure_and_events(self):
        report = run(RunOptions(prompt="Read notes.txt.", workspace=DEMO_WORKSPACE, scripted_turns=READ_TURNS))
        self.assertIsInstance(report, RunReport)
        self.assertEqual(report.subtype, "success")
        self.assertFalse(report.is_error)
        self.assertEqual(report.exit_code, 0)
        self.assertEqual(report.num_turns, 2)
        self.assertEqual(report.tool_calls, 1)
        self.assertEqual(report.total_cost_usd, 0.0)
        self.assertFalse(report.errors)
        self.assertFalse(report.permission_denials)
        self.assertTrue(report.session_id.startswith("ns-"))
        self.assertEqual([event["type"] for event in report.events], ["system", "assistant", "user", "assistant", "result"])
        self.assertEqual(report.result_event["type"], "result")
        self.assertEqual(report.result_event["subtype"], "success")

    def test_result_event_shape_matches_the_public_event_schema(self):
        report = run(RunOptions(prompt="Read notes.txt.", workspace=DEMO_WORKSPACE, scripted_turns=READ_TURNS))
        result = report.result_event
        for key in ("type", "subtype", "is_error", "num_turns", "duration_ms",
                    "total_cost_usd", "total_usage", "session_id", "errors", "permission_denials"):
            self.assertIn(key, result)
        self.assertEqual(EXIT_CODES["success"], 0)
        # The CLI --json stream is produced by the same event_to_dict source.
        self.assertEqual(result["type"], "result")

    def test_default_scripted_reply_runs_without_turns(self):
        report = run(RunOptions(prompt="Say hi."))
        self.assertEqual(report.subtype, "success")
        self.assertEqual(report.num_turns, 1)

    def test_custom_provider_instance_is_accepted(self):
        from providers.scripted import ScriptedProvider

        provider = ScriptedProvider([{"text": "custom provider reply"}], model="scripted")
        report = run(RunOptions(prompt="Hi", provider=provider))
        self.assertEqual(report.subtype, "success")
        self.assertIn("custom provider reply", str(report.events))


class PermissionGatingTests(unittest.TestCase):
    def test_mutating_tool_is_denied_under_default_mode_with_halt(self):
        report = run(RunOptions(
            prompt="Write a file.",
            workspace=DEMO_WORKSPACE,
            scripted_turns=WRITE_TURNS,
            halt_on_denial=True,
        ))
        self.assertEqual(report.subtype, "error_permission_denied")
        self.assertTrue(report.is_error)
        self.assertEqual(report.exit_code, 5)
        self.assertEqual(len(report.permission_denials), 1)
        self.assertEqual(report.permission_denials[0]["tool"], "Write")

    def test_allow_tool_lets_a_mutating_call_through(self):
        with tempfile.TemporaryDirectory() as directory:
            report = run(RunOptions(
                prompt="Write a file.",
                workspace=directory,
                scripted_turns=WRITE_TURNS,
                allowed_tools=["Write"],
            ))
        self.assertEqual(report.subtype, "success")
        self.assertEqual(report.tool_calls, 1)
        self.assertFalse(report.permission_denials)

    def test_read_only_denies_even_an_allowed_write(self):
        with tempfile.TemporaryDirectory() as directory:
            report = run(RunOptions(
                prompt="Write a file.",
                workspace=directory,
                scripted_turns=WRITE_TURNS,
                allowed_tools=["Write"],
                read_only=True,
            ))
        self.assertTrue(report.is_error or report.permission_denials)
        if not report.is_error:  # without halt the loop may continue and finish
            self.assertEqual([d["tool"] for d in report.permission_denials], ["Write"])

    def test_denial_without_halt_is_recorded_and_the_run_continues(self):
        report = run(RunOptions(
            prompt="Write then finish.",
            workspace=DEMO_WORKSPACE,
            scripted_turns=WRITE_TURNS,  # only one tool call, then text
        ))
        self.assertEqual(report.subtype, "success")
        self.assertEqual([d["tool"] for d in report.permission_denials], ["Write"])


class SessionTests(unittest.TestCase):
    def test_session_dir_persists_the_transcript(self):
        with tempfile.TemporaryDirectory() as directory:
            report = run(RunOptions(
                prompt="Read notes.txt.",
                workspace=DEMO_WORKSPACE,
                scripted_turns=READ_TURNS,
                session_dir=directory,
            ))
            path = Path(directory) / f"{report.session_id}.jsonl"
            self.assertTrue(path.is_file())
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(records[0]["type"], "session_start")
            self.assertEqual(records[-1]["type"], "session_end")

    def test_resume_continues_a_persisted_session(self):
        with tempfile.TemporaryDirectory() as directory:
            first = run(RunOptions(
                prompt="Read notes.txt.",
                workspace=DEMO_WORKSPACE,
                scripted_turns=READ_TURNS,
                session_dir=directory,
            ))
            second = run(RunOptions(
                prompt="One more turn.",
                workspace=DEMO_WORKSPACE,
                scripted_turns=[{"text": "continued"}],
                session_dir=directory,
            ), resume=first.session_id)
        self.assertEqual(second.subtype, "success")
        # The resumed run carries the same session id and adds its own turns.
        self.assertEqual(second.session_id, first.session_id)


class StreamTests(unittest.TestCase):
    def test_stream_run_yields_plain_dict_events_and_a_result_tail(self):
        events = list(stream_run(RunOptions(
            prompt="Read notes.txt.",
            workspace=DEMO_WORKSPACE,
            scripted_turns=READ_TURNS,
        )))
        self.assertEqual([event["type"] for event in events], ["system", "assistant", "user", "assistant", "result"])
        self.assertEqual(events[-1]["subtype"], "success")

    def test_stream_events_are_json_serialisable(self):
        for event in stream_run(RunOptions(prompt="Hi", scripted_turns=[{"text": "yo"}])):
            json.dumps(event)  # must not raise


class ValidationTests(unittest.TestCase):
    def test_empty_prompt_is_rejected(self):
        with self.assertRaises(ValueError):
            run(RunOptions(prompt="   "))

    def test_unknown_provider_name_is_rejected(self):
        with self.assertRaises(ValueError):
            run(RunOptions(prompt="Hi", provider="gemini"))


if __name__ == "__main__":
    unittest.main()
