import json
import unittest

from hooks import HookRegistry
from loop import (
    AssistantMessage,
    ResultMessage,
    RunConfig,
    SystemMessage,
    UserMessage,
)
from providers.scripted import ScriptedProvider

from helpers import make_runtime, make_workspace, results_of


class EventContractTests(unittest.TestCase):
    def test_init_is_first_event(self):
        runtime, _ = make_runtime(["done"])
        report = runtime.run("hello")
        self.assertIsInstance(report.events[0], SystemMessage)
        self.assertEqual(report.events[0].subtype, "init")

    def test_exactly_one_result_message_and_it_is_last(self):
        runtime, _ = make_runtime(["done"])
        report = runtime.run("hello")
        results = results_of(report)
        self.assertEqual(len(results), 1)
        self.assertIs(report.events[-1], results[0])

    def test_init_carries_model_session_tools_and_mode(self):
        runtime, _ = make_runtime(["done"], permission_mode="acceptEdits")
        report = runtime.run("hello")
        init = report.events[0].data
        self.assertEqual(init["model"], "claude-sonnet-4-5")
        self.assertEqual(init["session_id"], report.session_id)
        self.assertIn("Read", init["tools"])
        self.assertIn("Write", init["tools"])
        self.assertEqual(init["permission_mode"], "acceptEdits")

    def test_session_id_exists_without_session_store(self):
        # Invariant: even with no session store, every event carries the same non-empty session id.
        runtime, _ = make_runtime([
            {"text": "reading", "tools": [{"name": "Read", "input": {"path": "nope.txt"}}]},
            "finished",
        ])
        report = runtime.run("hello")
        self.assertNotEqual(report.session_id, "")
        for event in report.events:
            self.assertEqual(event.session_id, report.session_id)

    def test_user_message_carries_the_prompt(self):
        runtime, _ = make_runtime(["done"])
        report = runtime.run("the prompt text")
        user_events = [e for e in report.events if isinstance(e, UserMessage)]
        self.assertEqual(len(user_events), 1)
        self.assertEqual(user_events[0].text, "the prompt text")

    def test_assistant_message_carries_tool_uses(self):
        runtime, _ = make_runtime([
            {"text": "reading", "tools": [{"name": "Read", "input": {"path": "x"}}]},
            "done",
        ])
        report = runtime.run("go")
        assistant_events = [e for e in report.events if isinstance(e, AssistantMessage)]
        self.assertEqual(len(assistant_events), 2)
        self.assertEqual(assistant_events[0].text, "reading")
        self.assertEqual(assistant_events[0].tool_uses[0]["name"], "Read")
        self.assertEqual(assistant_events[0].tool_uses[0]["input"], {"path": "x"})
        self.assertEqual(assistant_events[1].tool_uses, [])

    def test_all_events_are_json_serializable(self):
        runtime, _ = make_runtime([
            {"text": "reading", "tools": [{"name": "Read", "input": {"path": "nope.txt"}}]},
            "done",
        ])
        report = runtime.run("go")
        for event in report.events:
            text = json.dumps(event.to_dict(), ensure_ascii=False)
            self.assertIn('"type"', text)

    def test_result_message_reports_turns_tools_cost_usage(self):
        runtime, _ = make_runtime([
            {"text": "writing", "tools": [{"name": "Write", "input": {"path": "a.txt", "content": "x"}}]},
            "done",
        ], permission_mode="bypassPermissions")
        report = runtime.run("go")
        result = report.result
        self.assertEqual(result.subtype, "success")
        self.assertEqual(result.num_turns, 2)
        self.assertEqual(result.num_tool_calls, 1)
        self.assertGreater(result.total_cost_usd, 0.0)
        self.assertEqual(result.usage["output_tokens"], 10)
        self.assertFalse(result.pricing_estimated)

    def test_known_model_not_estimated_unknown_model_is(self):
        runtime, _ = make_runtime(["done"], model="claude-sonnet-4-5")
        self.assertFalse(runtime.run("go").result.pricing_estimated)
        runtime2, _ = make_runtime(["done"], model="some-future-model")
        self.assertTrue(runtime2.run("go").result.pricing_estimated)

    def test_invalid_subtypes_rejected_at_construction(self):
        with self.assertRaises(ValueError):
            SystemMessage("bogus", {})
        with self.assertRaises(ValueError):
            ResultMessage(subtype="maybe", summary="x")

    def test_empty_prompt_is_an_event_not_an_exception(self):
        runtime, _ = make_runtime(["done"])
        report = runtime.run("   ")
        self.assertEqual(report.result.subtype, "error_during_execution")
        self.assertEqual(len(results_of(report)), 1)
        self.assertNotEqual(report.session_id, "")


class SessionStoreWiringTests(unittest.TestCase):
    def test_events_are_recorded_to_session_file(self):
        import sessions as sessions_module

        workspace = make_workspace()
        session_file = workspace / "session.jsonl"
        runtime, _ = make_runtime(["done"], session_path=session_file)
        report = runtime.run("hello")
        records = sessions_module.load_records(session_file)
        self.assertGreaterEqual(len(records), 2)
        for record in records:
            self.assertEqual(record["session_id"], report.session_id)
            self.assertIn("run_id", record)
            self.assertEqual(record["event"]["session_id"], report.session_id)

    def test_result_record_is_last_in_file(self):
        import sessions as sessions_module

        workspace = make_workspace()
        session_file = workspace / "session.jsonl"
        runtime, _ = make_runtime(["done"], session_path=session_file)
        runtime.run("hello")
        records = sessions_module.load_records(session_file)
        self.assertEqual(records[-1]["event"]["type"], "result")


if __name__ == "__main__":
    unittest.main()
