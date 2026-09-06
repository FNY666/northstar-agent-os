"""The ten lifecycle hooks: coverage, terminal deny, and fail-safe errors.
"""
from __future__ import annotations

import unittest

import support  # noqa: F401
from support import RuntimeTestCase, text_turn, tool_turn

from hooks import (
    BLOCK_EVENTS,
    HOOK_EVENTS,
    VETO_EVENTS,
    HookInput,
    HookRegistry,
    HookResult,
    coerce_result,
)
from providers.base import AssistantMessage, SystemMessage, UserMessage


def recorder(log: list[str], verdict=None):
    def hook(payload: HookInput):
        log.append(payload.event)
        return verdict

    return hook


class HookShapeTests(unittest.TestCase):
    def test_exactly_the_ten_documented_events_exist(self):
        self.assertEqual(len(HOOK_EVENTS), 10)
        self.assertEqual(
            HOOK_EVENTS,
            (
                "PreToolUse",
                "PostToolUse",
                "PostToolUseFailure",
                "UserPromptSubmit",
                "Stop",
                "SubagentStart",
                "SubagentStop",
                "PreCompact",
                "SessionStart",
                "SessionEnd",
            ),
        )

    def test_registry_rejects_an_unknown_event_name(self):
        registry = HookRegistry()
        with self.assertRaises(ValueError):
            registry.register("PostCoT", lambda payload: None)

    def test_registration_accepts_the_decorator_form_and_counts(self):
        registry = HookRegistry()

        @registry.register("PreToolUse", name="guard")
        def guard(payload: HookInput):
            return None

        self.assertEqual(registry.counts()["PreToolUse"], 1)
        self.assertEqual(registry.total(), 1)
        self.assertEqual(registry.events_with_hooks, ("PreToolUse",))
        self.assertTrue(callable(guard))

    def test_non_callable_hook_is_refused(self):
        with self.assertRaises(TypeError):
            HookRegistry().register("Stop", "not callable")

    def test_return_values_are_normalised(self):
        self.assertEqual(coerce_result(None).decision, "noop")
        self.assertEqual(coerce_result(True).decision, "allow")
        self.assertEqual(coerce_result(False).decision, "deny")
        self.assertEqual(coerce_result({"decision": "deny", "reason": "no"}).reason, "no")
        self.assertEqual(coerce_result({"reason": "not yet"}).decision, "block")
        self.assertEqual(coerce_result(HookResult.inject("ctx")).additional_context, "ctx")

    def test_modify_input_requires_a_dict(self):
        with self.assertRaises(TypeError):
            HookResult.modify_input(["not", "a", "dict"])

    def test_only_documented_events_can_veto(self):
        self.assertEqual(VETO_EVENTS, ("PreToolUse", "UserPromptSubmit", "SessionStart", "PreCompact", "SubagentStart"))
        self.assertEqual(BLOCK_EVENTS, ("Stop", "SubagentStop"))


class DenyIsTerminalTests(RuntimeTestCase):
    def test_a_deny_stops_the_chain_and_cannot_be_overturned(self):
        calls: list[str] = []
        registry = HookRegistry()
        registry.register("PreToolUse", lambda payload: calls.append("deny") or HookResult.deny("not today"), name="denier")
        registry.register("PreToolUse", lambda payload: calls.append("allow") or HookResult.allow(), name="overturner")
        outcome = registry.fire("PreToolUse", HookInput(event="PreToolUse", tool_name="Write"))
        self.assertTrue(outcome.denied)
        self.assertEqual(calls, ["deny"], "hooks after a deny must not run")
        self.assertEqual(outcome.skipped, ["overturner"])
        self.assertEqual(outcome.deny_reason, "not today")

    def test_a_deny_from_a_later_hook_still_wins_over_an_earlier_allow(self):
        registry = HookRegistry()
        registry.register("PreToolUse", lambda payload: HookResult.allow(), name="first")
        registry.register("PreToolUse", lambda payload: HookResult.deny("blocked"), name="second")
        outcome = registry.fire("PreToolUse", HookInput(event="PreToolUse", tool_name="Write"))
        self.assertTrue(outcome.denied)
        self.assertEqual(outcome.denied_by, "second")
        self.assertEqual(outcome.fired, ["first", "second"])

    def test_deny_on_an_observation_only_event_is_recorded_as_ignored(self):
        registry = HookRegistry()
        registry.register("PostToolUse", lambda payload: HookResult.deny("too late"), name="late")
        outcome = registry.fire("PostToolUse", HookInput(event="PostToolUse", tool_name="Read"))
        self.assertFalse(outcome.denied)
        self.assertTrue(any("not applicable" in note for note in outcome.ignored))

    def test_a_crashing_veto_hook_fails_closed(self):
        registry = HookRegistry()

        def explode(payload: HookInput):
            raise RuntimeError("policy service down")

        registry.register("PreToolUse", explode, name="explodes")
        registry.register("PreToolUse", lambda payload: HookResult.allow(), name="never")
        outcome = registry.fire("PreToolUse", HookInput(event="PreToolUse", tool_name="Write"))
        self.assertTrue(outcome.denied, "an unreadable verdict must never be a green light")
        self.assertIn("fail", outcome.deny_reason)
        self.assertEqual(outcome.errors[0].split(":")[0], "explodes")

    def test_a_crashing_observation_hook_only_logs(self):
        registry = HookRegistry()

        def explode(payload: HookInput):
            raise RuntimeError("telemetry broke")

        registry.register("PostToolUse", explode, name="explodes")
        outcome = registry.fire("PostToolUse", HookInput(event="PostToolUse"))
        self.assertFalse(outcome.denied)
        self.assertEqual(len(outcome.errors), 1)


class ToolHookRuntimeTests(RuntimeTestCase):
    def test_pre_tool_use_can_rewrite_the_input_the_gate_and_handler_see(self):
        workspace = self.workspace()
        seen: list[dict] = []

        registry = HookRegistry()
        registry.register(
            "PreToolUse",
            lambda payload: seen.append(dict(payload.tool_input))
            or HookResult.modify_input({"path": "safe.txt", "content": "rewritten by hook"}, reason="path normalised"),
            name="normaliser",
        )
        provider = self.provider([tool_turn("Write", {"path": "unsafe.txt", "content": "original"})])
        report = self.drive(self.runtime(provider=provider, workspace=workspace, hooks=registry, allowed_tools=("Write",)))
        self.assertEqual((workspace / "safe.txt").read_text(), "rewritten by hook")
        self.assertFalse((workspace / "unsafe.txt").exists())
        self.assertEqual(seen, [{"path": "unsafe.txt", "content": "original"}])
        self.assertTrue(report.tool_calls[0].input_rewritten)

    def test_pre_tool_use_deny_means_the_handler_never_runs(self):
        workspace = self.workspace()
        registry = HookRegistry()
        registry.register("PreToolUse", lambda payload: HookResult.deny("freezes until Monday"), name="freeze")
        provider = self.provider([tool_turn("Write", {"path": "x.txt", "content": "y"}), text_turn("ok")])
        report = self.drive(self.runtime(provider=provider, workspace=workspace, hooks=registry, permission_mode="bypassPermissions"))
        self.assertFalse((workspace / "x.txt").exists())
        self.assertIn("freezes until Monday", report.transcript[2].tool_results[0].text())
        self.assertEqual(report.denials[0].source, "hook:freeze")

    def test_a_hook_deny_is_visible_in_the_trace_as_a_refused_tool(self):
        registry = HookRegistry()
        registry.register("PreToolUse", lambda payload: HookResult.deny("no"), name="freeze")
        provider = self.provider([tool_turn("Write", {"path": "x.txt", "content": "y"}), text_turn("ok")])
        self.drive(self.runtime(provider=provider, hooks=registry))
        span = self.tracer.find("tool:Write")
        self.assertIsNotNone(span)
        self.assertTrue(span.attributes["tool.denied"])
        self.assertEqual(span.attributes["permission.source"], "hook:freeze")

    def test_post_tool_use_and_failure_are_split_by_outcome(self):
        workspace = self.workspace({"present.txt": "data"})
        events: list[tuple[str, str, bool]] = []
        registry = HookRegistry()
        registry.register("PostToolUse", lambda payload: events.append(("PostToolUse", payload.tool_name, payload.tool_is_error)) or None, name="ok")
        registry.register(
            "PostToolUseFailure",
            lambda payload: events.append(("PostToolUseFailure", payload.tool_name, payload.tool_is_error)) or None,
            name="bad",
        )
        provider = self.provider(
            [tool_turn("Read", {"path": "present.txt"}), tool_turn("Read", {"path": "absent.txt"}), text_turn("done")]
        )
        self.drive(self.runtime(provider=provider, workspace=workspace, hooks=registry))
        self.assertEqual(events, [("PostToolUse", "Read", False), ("PostToolUseFailure", "Read", True)])

    def test_a_failing_tool_handler_reports_failure_with_its_error_class(self):
        from tools import ToolRegistry, ToolResult, ToolSpec

        registry_tools = ToolRegistry()

        def boom(payload: dict, ctx) -> ToolResult:
            raise KeyError("missing")

        # Classified read-only so the permission gate lets it reach its handler.
        registry_tools.register(
            ToolSpec(name="Boom", description="explodes", input_schema={}, handler=boom, kind="read", is_mutating=False)
        )
        failures: list[str] = []
        hooks = HookRegistry()
        hooks.register("PostToolUseFailure", lambda payload: failures.append(payload.error) or None, name="watch")
        provider = self.provider([tool_turn("Boom", {}), text_turn("recovered")])
        report = self.drive(self.runtime(provider=provider, tools=registry_tools, hooks=hooks))
        self.assertEqual(len(failures), 1)
        self.assertIn("KeyError", failures[0])
        self.assertEqual(self.assertExactlyOneResult(report).subtype, "success", "a tool failure is recoverable by design")
        self.assertEqual(self.tracer.find("tool:Boom").attributes["tool.error_class"], "KeyError")

    def test_tool_filter_only_fires_for_the_named_tool(self):
        hits: list[str] = []
        registry = HookRegistry()
        registry.register("PreToolUse", lambda payload: hits.append(payload.tool_name) or None, name="write-only", tool="Write")
        provider = self.provider([tool_turn("Read", {"path": "a"}), tool_turn("Write", {"path": "b", "content": "c"}), text_turn("done")])
        self.drive(self.runtime(provider=provider, hooks=registry))
        self.assertEqual(hits, ["Write"])


class PromptAndStopHookTests(RuntimeTestCase):
    def test_user_prompt_submit_can_inject_context(self):
        registry = HookRegistry()
        registry.register("UserPromptSubmit", lambda payload: HookResult.inject("today is a code freeze"), name="injector")
        provider = self.provider([text_turn("acknowledged")])
        report = self.drive(self.runtime(provider=provider, hooks=registry))
        informational = [event for event in report.events if isinstance(event, SystemMessage) and event.subtype == "informational"]
        self.assertEqual([event.content for event in informational], ["today is a code freeze"])
        # The injected note and the prompt share one user turn: same-role events
        # merge so the API never sees two consecutive user messages.
        first = provider.requests[0].messages[0]
        self.assertEqual([message["role"] for message in provider.requests[0].messages], ["user"])
        texts = [block["text"] for block in first["content"]]
        self.assertTrue(any("today is a code freeze" in text for text in texts))
        self.assertTrue(any(text.strip() == "go" for text in texts), "the real prompt must still be there")

    def test_user_prompt_submit_rejection_ends_the_run_before_the_model_is_called(self):
        registry = HookRegistry()
        registry.register("UserPromptSubmit", lambda payload: HookResult.deny("prompt matches a banned pattern"), name="gate")
        provider = self.provider([text_turn("never")])
        report = self.drive(self.runtime(provider=provider, hooks=registry))
        result = self.assertExactlyOneResult(report)
        self.assertEqual(result.subtype, "error_permission_denied")
        self.assertEqual(provider.requests, [], "a refused prompt must never reach the model")
        self.assertEqual(result.permission_denials[0]["kind"], "prompt")

    def test_session_start_deny_refuses_the_whole_run(self):
        registry = HookRegistry()
        registry.register("SessionStart", lambda payload: HookResult.deny("maintenance window"), name="maintenance")
        provider = self.provider([text_turn("never")])
        report = self.drive(self.runtime(provider=provider, hooks=registry))
        self.assertEqual(self.assertExactlyOneResult(report).subtype, "error_permission_denied")
        self.assertEqual(provider.requests, [])

    def test_stop_hook_can_refuse_to_stop_and_feed_a_reason_back(self):
        registry = HookRegistry()
        blocks = {"count": 0}

        def stop(payload: HookInput):
            blocks["count"] += 1
            if blocks["count"] == 1:
                return HookResult.block("you did not run the tests")
            return None

        registry.register("Stop", stop, name="reviewer")
        provider = self.provider([text_turn("all done"), text_turn("ran the tests, all green")])
        report = self.drive(self.runtime(provider=provider, hooks=registry))
        result = self.assertExactlyOneResult(report)
        self.assertEqual(result.subtype, "success")
        self.assertEqual(result.num_turns, 2)
        meta = [message for message in report.transcript if isinstance(message, UserMessage) and message.is_meta]
        self.assertEqual([message.text for message in meta], ["you did not run the tests"])
        self.assertEqual(len(report.events_of(AssistantMessage)), 2)

    def test_a_stop_hook_that_always_blocks_terminates_on_the_turn_ceiling(self):
        registry = HookRegistry()
        registry.register("Stop", lambda payload: HookResult.block("again"), name="stubborn")
        provider = self.provider([text_turn("done") for _ in range(5)], on_exhausted="stop")
        report = self.drive(self.runtime(provider=provider, hooks=registry, max_turns=3))
        self.assertEqual(self.assertExactlyOneResult(report).subtype, "error_max_turns")
        self.assertEqual(report.result.stop_reason, "error_max_turns")

    def test_session_end_fires_once_even_on_a_provider_failure(self):
        from providers.base import ProviderError

        ends: list[str] = []
        registry = HookRegistry()
        registry.register("SessionEnd", lambda payload: ends.append(payload.data["subtype"]) or None, name="watch")
        provider = self.provider([{"raises": ProviderError("boom")}])
        report = self.drive(self.runtime(provider=provider, hooks=registry))
        self.assertEqual(ends, ["error_during_execution"])
        self.assertEqual(self.assertExactlyOneResult(report).subtype, "error_during_execution")


class FullCoverageTests(RuntimeTestCase):
    def test_a_single_run_exercises_every_hook(self):
        workspace = self.workspace({"a.txt": "alpha\n" * 2000})
        fired: list[str] = []
        registry = HookRegistry()
        for event in HOOK_EVENTS:
            registry.register(event, recorder(fired), name=f"watch-{event}")
        from agents import AgentRegistry, explorer_agent

        # The subagent runs on its own script, so the parent and child turn
        # counts are independently pinned - a provider swap is part of the spec.
        parent = self.provider(
            [
                tool_turn("Task", {"agent": "explorer", "prompt": "read a.txt"}, usage={"input_tokens": 50, "output_tokens": 5}),
                tool_turn("Read", {"path": "missing.txt"}, usage={"input_tokens": 60, "output_tokens": 5}),
                tool_turn("Read", {"path": "a.txt"}, usage={"input_tokens": 60, "output_tokens": 5}),
                text_turn("done"),
            ]
        )
        child = self.provider([tool_turn("Read", {"path": "a.txt"}), text_turn("alpha confirmed")])
        runtime = self.runtime(
            provider=parent,
            providers={"explorer_script": child},
            workspace=workspace,
            hooks=registry,
            compaction_threshold_tokens=600,
            agents=AgentRegistry([explorer_agent().override(provider="explorer_script")]),
        )
        report = self.drive(runtime, "delegate then finish")
        self.assertEqual(self.assertExactlyOneResult(report).subtype, "success")
        for event in HOOK_EVENTS:
            with self.subTest(event=event):
                self.assertIn(event, fired)

    def test_pre_compact_hook_can_veto_compaction(self):
        workspace = self.workspace({"big.txt": "y" * 40_000 + "\n"})
        registry = HookRegistry()
        registry.register("PreCompact", lambda payload: HookResult.deny("the audit needs the full transcript"), name="archivist")
        turns = [tool_turn("Read", {"path": "big.txt"}, usage={"input_tokens": 900, "output_tokens": 200}) for _ in range(3)]
        turns.append(text_turn("done"))
        provider = self.provider(turns)
        report = self.drive(self.runtime(provider=provider, workspace=workspace, hooks=registry, compaction_threshold_tokens=600))
        self.assertEqual(report.compact_boundaries, (), "a vetoed compaction must not rewrite the transcript")
        self.assertIn("audit needs the full transcript", str(report.hook_fires))
        # The refusal itself is recorded so an operator can see compaction was asked for.
        self.assertTrue(any(not item["performed"] and "refused by the archivist" in item["reason"] for item in report.compactions))

    def test_pre_compact_hook_can_supply_instructions(self):
        workspace = self.workspace({"big.txt": "z" * 40_000 + "\n"})
        registry = HookRegistry()
        registry.register("PreCompact", lambda payload: HookResult.inject("keep every file path verbatim"), name="instruct")
        turns = [tool_turn("Read", {"path": "big.txt"}, usage={"input_tokens": 900, "output_tokens": 200}) for _ in range(3)]
        turns.append(text_turn("done"))
        provider = self.provider(turns)
        report = self.drive(self.runtime(provider=provider, workspace=workspace, hooks=registry, compaction_threshold_tokens=600))
        self.assertTrue(report.compact_boundaries)
        self.assertIn("keep every file path verbatim", report.compact_boundaries[0].content)

    def test_subagent_start_hook_can_veto_the_delegation(self):
        registry = HookRegistry()
        registry.register("SubagentStart", lambda payload: HookResult.deny("no subagents during a release"), name="freeze")
        provider = self.provider([tool_turn("Task", {"agent": "explorer", "prompt": "look"}), text_turn("fine")])
        report = self.drive(self.runtime(provider=provider, hooks=registry))
        self.assertEqual(report.subagents, (), "a vetoed delegation must not create a subagent")
        self.assertIn("no subagents during a release", provider.sent_tool_results()[0]["content"])
        self.assertEqual(report.denials[0].source, "hook:freeze")

    def test_subagent_stop_hook_can_withhold_acceptance(self):
        registry = HookRegistry()
        registry.register("SubagentStop", lambda payload: HookResult.block("the subagent cited no evidence"), name="reviewer")
        parent = self.provider([tool_turn("Task", {"agent": "explorer", "prompt": "look"}), text_turn("noted")])
        child = self.provider([text_turn("I think it is fine")])
        from agents import AgentRegistry, explorer_agent

        runtime = self.runtime(
            provider=parent,
            providers={"explorer_script": child},
            hooks=registry,
            agents=AgentRegistry([explorer_agent().override(provider="explorer_script")]),
        )
        report = self.drive(runtime, "delegate")
        self.assertTrue(report.subagents[0].tool_calls == 0)
        refusal = parent.sent_tool_results()[0]["content"]
        self.assertIn("SubagentStop hook", refusal)
        self.assertIn("cited no evidence", refusal)
        self.assertTrue(parent.sent_tool_results()[0]["is_error"], "an unaccepted subagent result is an error the parent must handle")

    def test_hook_firings_are_reported_for_inspection(self):
        registry = HookRegistry()
        registry.register("SessionStart", lambda payload: None, name="watch")
        report = self.drive(self.runtime(turns=[text_turn("done")], hooks=registry))
        events = [item["event"] for item in report.hook_fires]
        self.assertIn("SessionStart", events)
        self.assertIn("Stop", events)
        self.assertIn("SessionEnd", events)


if __name__ == "__main__":
    unittest.main()
