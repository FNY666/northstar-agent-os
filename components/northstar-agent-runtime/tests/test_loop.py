"""Loop mechanics: the init event, dispatch ordering, coercion, ceilings, and
what the provider is actually shown.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import support  # noqa: F401
from support import RuntimeTestCase, text_turn, tool_turn

from loop import AgentRuntime, RuntimeConfig, RuntimeConfigurationError, run_agent, task_tool_spec
from providers.base import AssistantMessage, ResultMessage, SystemMessage, ToolResultBlock, UserMessage
from providers.scripted import ScriptedProvider
from tools import ToolRegistry, ToolResult, ToolSpec


class InitEventTests(RuntimeTestCase):
    def test_the_init_event_describes_the_governed_run(self):
        workspace = self.workspace({"a": "1"})
        provider = self.provider([text_turn("done")])
        runtime = self.runtime(provider=provider, workspace=workspace, max_turns=4, permission_mode="plan")
        report = self.drive(runtime, "hello")
        init = report.events[0]
        self.assertIsInstance(init, SystemMessage)
        self.assertEqual(init.subtype, "init")
        data = init.data
        self.assertEqual(data["model"], "claude-sonnet-4-5")
        self.assertEqual(data["permission_mode"], "plan")
        self.assertEqual(data["limits"]["max_turns"], 4)
        self.assertIn("Read", data["tools"])
        self.assertIn("Task", data["tools"])
        self.assertEqual(data["subagents"], ["evaluator", "explorer", "general", "planner"])
        self.assertEqual(data["sidecar"], False)
        self.assertEqual(data["session_id"], runtime.session_id)
        self.assertEqual(sorted(data["hooks"].values()), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    def test_the_init_event_is_persisted_but_never_sent_to_the_model(self):
        store = self.session_store()
        provider = self.provider([text_turn("done")])
        runtime = self.runtime(provider=provider, sessions=store)
        self.drive(runtime, "prompt text")
        self.assertEqual(provider.requests[0].messages[0]["content"][0]["text"], "prompt text")
        records, _dropped = store.read()
        self.assertEqual(records[0]["type"], "session_start")
        self.assertEqual(records[0]["data"]["model"], "claude-sonnet-4-5")

    def test_describe_exposes_the_policy_surface(self):
        runtime = self.runtime(turns=[])
        described = runtime.describe()
        self.assertEqual(described["provider"], "scripted")
        self.assertEqual(described["session_store"], "none")
        names = {item["name"] for item in described["tools"]}
        self.assertTrue({"Read", "Write", "Task"} <= names)
        self.assertNotIn("CodexReadOnly", names, "the sidecar tool exists only when a socket was provided")
        self.assertEqual([item["name"] for item in described["agents"]][0], "evaluator")


class DispatchTests(RuntimeTestCase):
    def test_parallel_calls_all_receive_results_in_order(self):
        workspace = self.workspace({"a.txt": "A", "b.txt": "B"})
        provider = self.provider(
            [{"tools": [{"name": "Read", "input": {"path": "a.txt"}}, {"name": "Read", "input": {"path": "b.txt"}}, {"name": "Read", "input": {"path": "missing"}}]}, text_turn("done")]
        )
        report = self.drive(self.runtime(provider=provider, workspace=workspace))
        results = report.transcript[2].tool_results
        self.assertEqual(len(results), 3)
        self.assertEqual([result.is_error for result in results], [False, False, True])
        self.assertEqual(results[0].text(), "A")
        self.assertEqual(results[1].text(), "B")
        ids = [call.id for call in report.transcript[1].tool_uses]
        self.assertEqual(ids, [result.tool_use_id for result in results])

    def test_an_unknown_tool_is_answered_with_the_real_tool_list(self):
        provider = self.provider([tool_turn("DeleteTheInternet", {}), text_turn("recovering")])
        report = self.drive(self.runtime(provider=provider))
        refusal = report.transcript[2].tool_results[0]
        self.assertTrue(refusal.is_error)
        self.assertIn("unknown tool 'DeleteTheInternet'", refusal.text())
        self.assertIn("Read", refusal.text(), "the model needs to know what it may call instead")
        self.assertEqual(self.assertExactlyOneResult(report).subtype, "success")

    def test_handler_return_shapes_are_all_coerced(self):
        registry = ToolRegistry()

        def build(name, value):
            return ToolSpec(name=name, description="", input_schema={}, handler=lambda payload, ctx: value, kind="read", is_mutating=False)

        for index, value in enumerate(("plain text", {"structured": 1}, ["a", "b"], None, 42, False)):
            registry.register(build(f"T{index}", value))
        provider = self.provider([{"tools": [{"name": f"T{index}", "input": {}} for index in range(6)]}, text_turn("done")])
        report = self.drive(self.runtime(provider=provider, tools=registry, max_turns=8))
        blocks = report.transcript[2].tool_results
        self.assertEqual(blocks[0].text(), "plain text")
        self.assertIn('"structured": 1', blocks[1].text())
        self.assertIn("a", blocks[2].text())
        self.assertEqual(blocks[3].text(), "T3 returned no result")
        self.assertEqual(blocks[4].text(), "42")
        self.assertEqual(blocks[5].text(), "T5 returned False")
        self.assertEqual(self.assertExactlyOneResult(report).subtype, "success")

    def test_oversized_output_is_capped_before_it_enters_the_transcript(self):
        registry = ToolRegistry()
        registry.register(
            ToolSpec(
                name="Spew",
                description="returns far too much",
                input_schema={},
                handler=lambda payload, ctx: ToolResult(content="w" * 500_000),
                kind="read",
                is_mutating=False,
            )
        )
        provider = self.provider([tool_turn("Spew", {}), text_turn("done")])
        report = self.drive(self.runtime(provider=provider, tools=registry))
        block = report.transcript[2].tool_results[0]
        self.assertLess(len(block.text()), 301_000)
        self.assertIn("truncated", block.text())
        self.assertEqual(report.tool_calls[0].result_chars, 500_000, "the report keeps the true size")

    def test_a_handler_that_loses_its_mind_is_reported_not_propagated(self):
        registry = ToolRegistry()

        def handler(payload: dict, ctx) -> ToolResult:
            raise ZeroDivisionError("deep inside")

        registry.register(ToolSpec(name="Crashy", description="", input_schema={}, handler=handler, kind="read", is_mutating=False))
        provider = self.provider([tool_turn("Crashy", {}), text_turn("recovered")])
        report = self.drive(self.runtime(provider=provider, tools=registry))
        self.assertIn("ZeroDivisionError", report.transcript[2].tool_results[0].text())
        self.assertEqual(self.assertExactlyOneResult(report).subtype, "success")

    def test_the_model_is_shown_the_system_prompt_and_tool_schemas(self):
        provider = self.provider([text_turn("done")])
        runtime = self.runtime(provider=provider)
        self.drive(runtime, "go")
        request = provider.requests[0]
        self.assertIn("governed runtime", request.system)
        self.assertIn("report it instead of working around it", request.system)
        self.assertEqual(request.model, "claude-sonnet-4-5")
        names = [tool["name"] for tool in request.tools]
        self.assertIn("Read", names)
        self.assertIn("Task", names)
        schema = next(tool for tool in request.tools if tool["name"] == "Read")["input_schema"]
        self.assertEqual(schema["required"], ["path"])
        self.assertEqual(request.turn_index, 1)
        self.assertEqual(request.depth, 0)

    def test_a_request_snapshot_never_includes_prompt_text(self):
        provider = self.provider([text_turn("done")])
        self.drive(self.runtime(provider=provider), "confidential instructions")
        snapshot = provider.requests[0].snapshot()
        self.assertNotIn("confidential", json.dumps(snapshot))
        self.assertEqual(snapshot["message_count"], 1)

    def test_turn_numbering_matches_generation_count(self):
        provider = self.provider([tool_turn("Read", {"path": "x"}), tool_turn("LS", {"path": "."}), text_turn("done")])
        report = self.drive(self.runtime(provider=provider))
        self.assertEqual([request.turn_index for request in provider.requests], [1, 2, 3])
        self.assertEqual(self.assertExactlyOneResult(report).num_turns, 3)


class TerminalEventConsistencyTests(RuntimeTestCase):
    def test_result_persistence_failure_still_releases_the_session_lease(self):
        store = self.session_store()
        runtime = self.runtime(provider=self.provider([text_turn("done")]), sessions=store)
        with patch.object(store, "record_result", side_effect=OSError("injected result persistence failure")):
            with self.assertRaises(OSError) as raised:
                runtime.run_collect("go")
        self.assertEqual(str(raised.exception), "injected result persistence failure")
        self.assertIsNone(runtime._session_lease)
        lease = None
        try:
            from session_lease import SessionLease, lease_path_for
            lease = SessionLease(lease_path_for(store.directory, store.session_id), owner_id="close-failure-test")
            lease.acquire()
        finally:
            if lease is not None:
                lease.release()
        self.assertIn("result persistence failure", " ".join(runtime.last_report.errors))

    def test_session_end_failure_still_releases_the_session_lease(self):
        store = self.session_store()
        runtime = self.runtime(provider=self.provider([text_turn("done")]), sessions=store)
        original_fire = runtime._fire
        def fail_only_session_end(state, event, payload):
            if event == "SessionEnd":
                raise OSError("injected session-end failure")
            return original_fire(state, event, payload)
        with patch.object(runtime, "_fire", side_effect=fail_only_session_end):
            with self.assertRaises(OSError) as raised:
                runtime.run_collect("go")
        self.assertEqual(str(raised.exception), "injected session-end failure")
        self.assertIsNone(runtime._session_lease)
        self.assertIn("session-end failure", " ".join(runtime.last_report.errors))

    def test_lease_release_failure_preserves_the_first_error_without_retry(self):
        store = self.session_store()
        runtime = self.runtime(provider=self.provider([text_turn("done")]), sessions=store)
        leases = []
        original_release = runtime._release_session
        def release_then_fail():
            leases.append(runtime._session_lease)
            original_release()
            raise OSError("injected release failure")
        with patch.object(runtime, "_release_session", side_effect=release_then_fail):
            with self.assertRaises(OSError) as raised:
                runtime.run_collect("go")
        self.assertEqual(str(raised.exception), "injected release failure")
        self.assertIsNone(runtime._session_lease)
        lease = leases[0]
        self.assertIsNotNone(lease)
        self.assertFalse(lease.status().locked)
        from session_lease import SessionLease, lease_path_for
        reacquired = SessionLease(lease_path_for(store.directory, store.session_id), owner_id="release-reacquire-check")
        reacquired.acquire()
        reacquired.release()
        self.assertIn("lease_release", " ".join(runtime.last_report.errors))

    def test_release_exception_keeps_still_held_lease_reference(self):
        store = self.session_store()
        runtime = self.runtime(provider=self.provider([text_turn("done")]), sessions=store)
        original_release = runtime._release_session
        lease_box = []
        def fail_without_releasing():
            lease_box.append(runtime._session_lease)
            raise OSError("injected low-level release failure")
        with patch.object(runtime, "_release_session", side_effect=fail_without_releasing) as mocked_release:
            with self.assertRaisesRegex(OSError, "low-level release failure"):
                runtime.run_collect("go")
        self.assertEqual(mocked_release.call_count, 1)
        lease = lease_box[0]
        self.assertIs(runtime._session_lease, lease)
        self.assertTrue(lease.status().locked)
        self.assertIn("lease_release", " ".join(runtime.last_report.errors))
        original_release()

    def test_keyboard_interrupt_during_result_write_still_attempts_release(self):
        store = self.session_store()
        runtime = self.runtime(provider=self.provider([text_turn("done")]), sessions=store)
        original_release = runtime._release_session
        released = []
        def observed_release():
            released.append(True)
            return original_release()
        with patch.object(store, "record_result", side_effect=KeyboardInterrupt("interrupt close")), patch.object(
            runtime, "_release_session", side_effect=observed_release
        ):
            with self.assertRaises(KeyboardInterrupt):
                runtime.run_collect("go")
        self.assertEqual(released, [True])
        self.assertIsNone(runtime._session_lease)
        from session_lease import SessionLease, lease_path_for
        lease = SessionLease(lease_path_for(store.directory, store.session_id), owner_id="interrupt-reacquire")
        lease.acquire()
        lease.release()

    def test_result_and_session_end_failures_keep_first_error_identity_and_both_diagnostics(self):
        store = self.session_store()
        runtime = self.runtime(provider=self.provider([text_turn("done")]), sessions=store)
        first = OSError("first result write failure")
        original_fire = runtime._fire
        def fail_session_end(state, event, payload):
            if event == "SessionEnd":
                raise OSError("second SessionEnd failure")
            return original_fire(state, event, payload)
        with patch.object(store, "record_result", side_effect=first), patch.object(
            runtime, "_fire", side_effect=fail_session_end
        ):
            with self.assertRaises(OSError) as raised:
                runtime.run_collect("go")
        self.assertIs(raised.exception, first)
        self.assertTrue(any("SessionEnd" in note for note in getattr(first, "__notes__", ())))
        diagnostics = " ".join(runtime.last_report.errors)
        self.assertIn("result", diagnostics)
        self.assertIn("SessionEnd", diagnostics)
        self.assertIsNone(runtime._session_lease)

    def test_refused_session_preserves_real_busy_owner_and_never_writes(self):
        from session_lease import SessionLease, lease_path_for
        store = self.session_store()
        holder = SessionLease(lease_path_for(store.directory, store.session_id), owner_id="real-busy-owner")
        holder.acquire()
        try:
            runtime = self.runtime(provider=self.provider([text_turn("done")]), sessions=store)
            report = runtime.run_collect("go")
            self.assertEqual("error_session_busy", report.result.subtype)
            self.assertEqual("real-busy-owner", holder.status().owner_id)
            records, dropped = store.read()
            self.assertEqual(0, dropped)
            self.assertEqual(0, sum(record["type"] == "result" for record in records))
            self.assertEqual(0, sum(record["type"] == "session_end" for record in records))
        finally:
            holder.release()

    def test_refused_session_result_failure_does_not_write_another_session(self):
        from session_lease import SessionBusyError
        store = self.session_store()
        runtime = self.runtime(provider=self.provider([text_turn("done")]), sessions=store)
        with patch.object(runtime, "_claim_session", return_value="owned by another process"):
            report = runtime.run_collect("go")
        self.assertEqual("error_session_busy", report.result.subtype)
        records, dropped = store.read()
        self.assertEqual(0, dropped)
        self.assertEqual(0, sum(record["type"] == "result" for record in records))
        self.assertEqual(0, sum(record["type"] == "session_end" for record in records))

    def test_successful_close_releases_lease_and_writes_one_terminal_result(self):
        store = self.session_store()
        runtime = self.runtime(provider=self.provider([text_turn("done")]), sessions=store)
        self.assertIsNone(runtime._session_lease)
        report = runtime.run_collect("go")
        self.assertIsNone(runtime._session_lease)
        self.assertEqual("success", self.assertExactlyOneResult(report).subtype)
        records, dropped = store.read()
        self.assertEqual(0, dropped)
        self.assertEqual(1, sum(record["type"] == "result" for record in records))
        self.assertEqual(1, sum(record["type"] == "session_end" for record in records))

    def test_snapshot_exception_terminal_is_present_in_collected_report_and_store(self):
        from postconditions import PostCondition, PostConditionError
        store = self.session_store()
        provider = self.provider([text_turn("never requested")])
        runtime = self.runtime(provider=provider, sessions=store,
            postconditions=[PostCondition(kind="unchanged", path="artifact.txt")])
        with patch.object(runtime.postconditions, "snapshot", side_effect=PostConditionError("injected snapshot failure")):
            report = runtime.run_collect("go")
        result = self.assertExactlyOneResult(report)
        self.assertIs(result, report.result)
        self.assertEqual(result.subtype, "error_during_execution")
        self.assertIn("injected snapshot failure", " ".join(result.errors))
        self.assertEqual(provider.requests, [])
        self.assertEqual(runtime.last_report.events, report.events)
        records, dropped = store.read()
        self.assertEqual(dropped, 0)
        self.assertEqual([r["type"] for r in records], ["result", "session_end"])
        self.assertEqual(records[0]["subtype"], result.subtype)

    def test_exception_after_init_keeps_stream_and_internal_event_list_identical(self):
        runtime = self.runtime([text_turn("never requested")])
        with patch.object(runtime, "_open_session", side_effect=RuntimeError("after init failure")):
            streamed = tuple(runtime.run("go"))
        self.assertEqual(streamed, runtime.last_report.events)
        results = [e for e in streamed if isinstance(e, ResultMessage)]
        self.assertEqual(len(results), 1)
        self.assertIsInstance(streamed[0], SystemMessage)
        self.assertEqual(results[0].subtype, "error_during_execution")

    def test_unyielded_existing_result_is_recorded_without_creating_another(self):
        runtime = self.runtime([])
        def finish_without_yield(prompt, state, span):
            runtime._finish(state, "success")
            return iter(())
        with patch.object(runtime, "_events", side_effect=finish_without_yield):
            report = runtime.run_collect("go")
        result = self.assertExactlyOneResult(report)
        self.assertIs(result, report.result)
        self.assertEqual(result.subtype, "success")

    def test_normal_finish_is_not_duplicated(self):
        runtime = self.runtime([text_turn("done")])
        streamed = tuple(runtime.run("go"))
        self.assertEqual(streamed, runtime.last_report.events)
        self.assertExactlyOneResult(runtime.last_report)


class CeilingAndFlowTests(RuntimeTestCase):
    def test_max_turns_stops_a_model_that_will_not_finish(self):
        provider = self.provider([tool_turn("Read", {"path": "x"}) for _ in range(6)], on_exhausted="repeat_last")
        report = self.drive(self.runtime(provider=provider, max_turns=3, max_tool_calls=None))
        result = self.assertExactlyOneResult(report)
        self.assertEqual(result.subtype, "error_max_turns")
        self.assertEqual(result.num_turns, 3)
        self.assertEqual(len(provider.requests), 3)

    def test_halting_on_denial_still_answers_every_call(self):
        provider = self.provider(
            [{"tools": [{"name": "Write", "input": {"path": "a", "content": "1"}}, {"name": "Write", "input": {"path": "b", "content": "2"}}]}]
        )
        report = self.drive(self.runtime(provider=provider, halt_on_denial=True))
        result = self.assertExactlyOneResult(report)
        self.assertEqual(result.subtype, "error_permission_denied")
        blocks = report.transcript[2].tool_results
        self.assertEqual(len(blocks), 2)
        self.assertIn("not executed", blocks[1].text())

    def test_a_reused_runtime_keeps_one_cost_meter_for_the_whole_session(self):
        # Deliberate: a long-lived runtime cannot be worn down by repeated runs,
        # because the meter is shared. Hosts that want a per-request budget build a
        # runtime per request (see the component README).
        provider = self.provider([text_turn(f"answer {index}", usage={"input_tokens": 1_000_000}) for index in range(3)])
        runtime = self.runtime(provider=provider, max_budget_usd=5.0)
        first = self.drive(runtime, "one")
        self.assertAlmostEqual(first.result.total_cost_usd, 3.0)
        second = self.drive(runtime, "two")
        self.assertAlmostEqual(second.result.total_cost_usd, 6.0, msg="cost accumulates across runs on one instance")
        self.assertEqual(second.result.subtype, "success")
        third = self.drive(runtime, "three")
        self.assertEqual(self.assertExactlyOneResult(third).subtype, "error_max_budget_usd")
        self.assertEqual(provider.cursor, 2, "the run that would have breached the ceiling never asked the model")

    def test_a_fresh_runtime_starts_a_fresh_budget(self):
        provider = self.provider([text_turn("answer", usage={"input_tokens": 1_000_000})])
        report = self.drive(self.runtime(provider=provider, max_budget_usd=5.0))
        self.assertEqual(report.result.subtype, "success")
        self.assertAlmostEqual(report.result.total_cost_usd, 3.0)

    def test_provider_returning_nonsense_is_an_execution_error(self):
        class Broken:
            name = "broken"

            def generate(self, request):
                return {"text": "not a Generation"}

        report = self.drive(self.runtime(provider=Broken()))
        result = self.assertExactlyOneResult(report)
        self.assertEqual(result.subtype, "error_during_execution")
        self.assertIn("Generation", result.errors[0])

    def test_run_agent_wrapper_builds_the_runtime(self):
        provider = self.provider([text_turn("hello back")])
        report = run_agent("greet me", provider=provider, config=RuntimeConfig(workspace=str(self.workspace())))
        self.assertEqual(report.subtype, "success")
        self.assertEqual(report.final_text, "hello back")

    def test_a_runtime_needs_a_provider(self):
        with self.assertRaises(RuntimeConfigurationError):
            AgentRuntime(provider=None)

    def test_tool_call_reports_are_collected(self):
        workspace = self.workspace({"a.txt": "x"})
        provider = self.provider([tool_turn("Read", {"path": "a.txt"}), tool_turn("Read", {"path": "nope"}), text_turn("done")])
        report = self.drive(self.runtime(provider=provider, workspace=workspace))
        rows = report.tool_calls
        self.assertEqual([row.name for row in rows], ["Read", "Read"])
        self.assertEqual([row.is_error for row in rows], [False, True])
        self.assertEqual([row.turn_index for row in rows], [1, 2])
        self.assertEqual(rows[0].permission_source, "mode")
        self.assertGreaterEqual(rows[0].duration_ms, 0)
        self.assertEqual(rows[0].result_chars, 1)

    def test_task_tool_is_never_executed_through_its_placeholder_handler(self):
        spec = task_tool_spec()
        self.assertTrue(spec.is_delegation)
        self.assertFalse(spec.is_mutating)
        from tools import ToolContext

        result = spec.handler({}, ToolContext())
        self.assertTrue(result.is_error)
        self.assertIn("dispatch is broken", result.text())


class PersistenceTests(RuntimeTestCase):
    def test_a_run_records_every_turn_type(self):
        store = self.session_store()
        provider = self.provider([tool_turn("Read", {"path": "x"}), text_turn("done")])
        self.drive(self.runtime(provider=provider, sessions=store))
        records, dropped = store.read()
        self.assertEqual(dropped, 0)
        types = [record["type"] for record in records]
        self.assertEqual(types, ["session_start", "user_prompt", "assistant", "tool_result", "assistant", "result", "session_end"])

    def test_denials_are_written_as_their_own_record(self):
        store = self.session_store()
        provider = self.provider([tool_turn("Write", {"path": "x", "content": "1"}), text_turn("ok")])
        self.drive(self.runtime(provider=provider, sessions=store))
        records, _ = store.read()
        denials = [record for record in records if record["type"] == "denial"]
        self.assertEqual(len(denials), 1)
        self.assertEqual(denials[0]["tool"], "Write")
        self.assertEqual(denials[0]["source"], "mode")


if __name__ == "__main__":
    unittest.main()
