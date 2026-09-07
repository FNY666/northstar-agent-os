"""Loop mechanics: the init event, dispatch ordering, coercion, ceilings, and
what the provider is actually shown.
"""
from __future__ import annotations

import json
import unittest

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

    def test_mutating_tools_write_a_pre_and_post_workspace_receipt(self):
        workspace = self.workspace()
        store = self.session_store()
        provider = self.provider([tool_turn("Write", {"path": "x.txt", "content": "created"}), text_turn("ok")])
        self.drive(
            self.runtime(
                provider=provider,
                workspace=workspace,
                sessions=store,
                permission_mode="acceptEdits",
            )
        )
        records, _ = store.read()
        receipts = [record for record in records if record["type"] == "workspace_change"]
        self.assertEqual(len(receipts), 1)
        receipt = receipts[0]
        self.assertEqual(receipt["paths"], ["x.txt"])
        self.assertFalse(receipt["before"][0]["exists"])
        self.assertTrue(receipt["after"][0]["exists"])
        self.assertEqual(receipt["after"][0]["kind"], "file")
        self.assertTrue(receipt["changed"])
        self.assertFalse(receipt["is_error"])

    def test_denials_are_written_as_their_own_record(self):
        store = self.session_store()
        provider = self.provider([tool_turn("Write", {"path": "x", "content": "1"}), text_turn("ok")])
        self.drive(self.runtime(provider=provider, sessions=store))
        records, _ = store.read()
        denials = [record for record in records if record["type"] == "denial"]
        self.assertEqual(len(denials), 1)
        self.assertEqual(denials[0]["tool"], "Write")
        self.assertEqual(denials[0]["source"], "mode")

    def test_declared_custom_impact_keys_are_included_in_workspace_receipts(self):
        workspace = self.workspace()
        store = self.session_store()
        registry = ToolRegistry()

        def write_artifact(payload, ctx):
            ctx.resolve(payload["output_path"], for_write=True).write_text("artifact", encoding="utf-8")
            return ToolResult.ok("written")

        registry.register(
            ToolSpec(
                name="WriteArtifact",
                description="write using a non-standard path key",
                input_schema={},
                handler=write_artifact,
                kind="edit",
                affected_input_keys=("output_path",),
            )
        )
        provider = self.provider([tool_turn("WriteArtifact", {"output_path": "artifact.txt"}), text_turn("ok")])
        self.drive(
            self.runtime(
                provider=provider,
                workspace=workspace,
                sessions=store,
                tools=registry,
                permission_mode="acceptEdits",
            )
        )
        records, _ = store.read()
        receipt = next(record for record in records if record["type"] == "workspace_change")
        self.assertEqual(receipt["paths"], ["artifact.txt"])
        self.assertEqual(receipt["impact_source"], "declared")
        self.assertEqual(receipt["impact_input_keys"], ["output_path"])
        self.assertFalse(receipt["before"][0]["exists"])
        self.assertTrue(receipt["after"][0]["exists"])


if __name__ == "__main__":
    unittest.main()
