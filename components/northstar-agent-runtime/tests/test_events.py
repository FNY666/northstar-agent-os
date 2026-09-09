"""Event vocabulary: the four message types, their closed subtypes, and the
"exactly one ResultMessage per run" guarantee.
"""
from __future__ import annotations

import typing
import unittest

import support  # noqa: F401  (installs the sys.path shim)
from support import RuntimeTestCase, text_turn, tool_turn

from events import EXIT_CODES  # the terminal convention lives with the event feed
from providers.base import (
    RESULT_SUBTYPES,
    SYSTEM_SUBTYPES,
    AssistantMessage,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    Usage,
    UserMessage,
    transcript_to_api,
)


class EventTypeTests(unittest.TestCase):
    def test_system_message_accepts_the_documented_subtypes(self):
        for subtype in ("init", "compact_boundary", "informational", "postconditions", "governance_drift"):
            self.assertEqual(SystemMessage(subtype=subtype, content="x").subtype, subtype)
        # ``governance_drift`` is the fifth: a run that caught its own policy tree moving has
        # to say so in a frame a consumer can key on, not in prose inside ``informational``.
        self.assertEqual(
            SYSTEM_SUBTYPES,
            ("init", "compact_boundary", "informational", "postconditions", "governance_drift"),
        )

    def test_system_message_rejects_an_unknown_subtype(self):
        with self.assertRaises(ValueError):
            SystemMessage(subtype="debug", content="x")

    def test_result_message_accepts_every_documented_subtype(self):
        self.assertEqual(
            RESULT_SUBTYPES,
            (
                "success",
                "error_max_turns",
                "error_max_tool_calls",
                "error_max_budget_usd",
                "error_during_execution",
                "error_permission_denied",
                "error_postconditions_failed",
                "error_session_busy",
                # 8, and paired with the ``governance_drift`` system frame above: a sandbox
                # that cannot bind read-only must still stop a run that edited its own policy.
                "error_governance_drift",
            ),
        )
        # Pinned against the exit-code table as well: a subtype with no code is a result
        # the shell cannot read, and a code with no subtype is a number that lies.
        self.assertEqual(set(RESULT_SUBTYPES), set(EXIT_CODES))
        for subtype in RESULT_SUBTYPES:
            message = ResultMessage(subtype=subtype)
            self.assertEqual(message.is_error, subtype != "success")

    def test_result_message_rejects_an_invented_subtype(self):
        with self.assertRaises(ValueError):
            ResultMessage(subtype="error_model_overheated")

    def test_assistant_message_exposes_text_and_tool_uses(self):
        message = AssistantMessage(
            content=(TextBlock(text="looking"), ToolUseBlock(id="t1", name="Read", input={"path": "a"}))
        )
        self.assertEqual(message.text, "looking")
        self.assertEqual([call.name for call in message.tool_uses], ["Read"])

    def test_user_message_exposes_tool_results(self):
        message = UserMessage(content=(ToolResultBlock(tool_use_id="t1", content="ok", is_error=True),))
        results = message.tool_results
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].is_error)
        self.assertEqual(results[0].text(), "ok")

    def test_usage_rejects_negative_and_boolean_token_counts(self):
        with self.assertRaises(ValueError):
            Usage(input_tokens=-1)
        with self.assertRaises(TypeError):
            Usage(output_tokens=True)

    def test_usage_addition_and_mapping_round_trip(self):
        total = Usage(input_tokens=10, output_tokens=2) + Usage(input_tokens=5, output_tokens=1, cache_read_input_tokens=7)
        self.assertEqual(
            total.as_dict(),
            {
                "input_tokens": 15,
                "output_tokens": 3,
                "cache_read_input_tokens": 7,
                "cache_creation_input_tokens": 0,
            },
        )
        self.assertEqual(total.total_tokens, 25)
        self.assertEqual(Usage.from_mapping({"input_tokens": "nope", "output_tokens": 4}).output_tokens, 4)


class ExactlyOneResultTests(RuntimeTestCase):
    def test_happy_path_emits_init_assistant_then_exactly_one_result(self):
        report = self.drive(self.runtime([text_turn("done")]), "say done")
        self.assertExactlyOneResult(report)
        self.assertEqual(report.result.subtype, "success")
        self.assertEventKinds(report, ["SystemMessage", "AssistantMessage", "ResultMessage"])

    def test_denied_tool_is_a_refusal_not_a_crash(self):
        workspace = self.workspace()
        provider = self.provider([tool_turn("Write", {"path": "x.txt", "content": "y"}), text_turn("refused")])
        report = self.drive(self.runtime(provider=provider, workspace=workspace), "write")
        self.assertExactlyOneResult(report)
        self.assertEqual(report.result.subtype, "success", "by default a refusal is a completed run")
        self.assertFalse((workspace / "x.txt").exists(), "safety-side failure must mean nothing was written")

    def test_halt_on_denial_emits_its_own_subtype(self):
        provider = self.provider([tool_turn("Write", {"path": "x.txt", "content": "y"})])
        report = self.drive(self.runtime(provider=provider, halt_on_denial=True), "write")
        result = self.assertExactlyOneResult(report)
        self.assertEqual(result.subtype, "error_permission_denied")
        self.assertTrue(result.is_error)
        self.assertEqual(result.permission_denials[0]["tool"], "Write")

    def test_provider_failure_becomes_an_event_not_an_exception(self):
        from providers.base import ProviderError

        provider = self.provider([{"raises": ProviderError("upstream 529 overloaded")}])
        report = self.drive(self.runtime(provider=provider), "go")
        result = self.assertExactlyOneResult(report)
        self.assertEqual(result.subtype, "error_during_execution")
        self.assertTrue(any("upstream 529" in error for error in result.errors))

    def test_unexpected_exception_inside_the_loop_still_closes_with_one_result(self):
        class Exploding:
            name = "exploding"

            def generate(self, request):
                raise RuntimeError("impossible state")

        report = self.drive(self.runtime(provider=Exploding()), "go")
        result = self.assertExactlyOneResult(report)
        self.assertEqual(result.subtype, "error_during_execution")
        self.assertIn("impossible state", result.errors[0])

    def test_empty_prompt_is_reported_not_raised(self):
        report = self.drive(self.runtime([text_turn("never reached")]), "   ")
        result = self.assertExactlyOneResult(report)
        self.assertEqual(result.subtype, "error_during_execution")

    def test_non_string_prompt_is_reported_not_raised(self):
        report = self.drive(self.runtime([text_turn("never reached")]), None)  # type: ignore[arg-type]
        self.assertEqual(self.assertExactlyOneResult(report).subtype, "error_during_execution")

    def test_streaming_order_is_init_first_result_last(self):
        runtime = self.runtime([tool_turn("Read", {"path": "missing"}), text_turn("done")])
        events = list(runtime.run("read"))
        self.assertIsInstance(events[0], SystemMessage)
        self.assertEqual(events[0].subtype, "init")
        self.assertIsInstance(events[-1], ResultMessage)
        self.assertEqual(len([event for event in events if isinstance(event, ResultMessage)]), 1)

    def test_tool_use_ids_are_paired_even_when_the_provider_omits_them(self):
        provider = self.provider([tool_turn("Read", {"path": "a"}), tool_turn("Read", {"path": "b"}), text_turn("done")])
        report = self.drive(self.runtime(provider=provider), "read twice")
        calls = [call for message in report.transcript if isinstance(message, AssistantMessage) for call in message.tool_uses]
        results = [result for message in report.transcript if isinstance(message, UserMessage) for result in message.tool_results]
        self.assertEqual(len(calls), 2)
        self.assertEqual([call.id for call in calls], [result.tool_use_id for result in results])
        self.assertEqual(len({call.id for call in calls}), 2, "ids must be unique or pairing is a guess")


class SerialisationTests(unittest.TestCase):
    def test_init_events_are_not_sent_to_the_model(self):
        payload = transcript_to_api([SystemMessage(subtype="init", content="ready", data={"x": 1})])
        self.assertEqual(payload[0]["content"][0]["text"], "(no context)")

    def test_consecutive_user_turns_merge_so_roles_alternate(self):
        payload = transcript_to_api(
            [
                SystemMessage(subtype="informational", content="host note"),
                UserMessage.text_block("the actual prompt"),
                AssistantMessage(content=()),
                SystemMessage(subtype="compact_boundary", content="summary"),
                UserMessage.text_block("next"),
            ]
        )
        self.assertEqual([message["role"] for message in payload], ["user", "assistant", "user"])
        self.assertIn("[Host context]", payload[0]["content"][0]["text"])
        self.assertIn("Earlier conversation summary", payload[2]["content"][0]["text"])

    def test_payload_never_starts_with_an_assistant_turn(self):
        payload = transcript_to_api([AssistantMessage(content=())])
        self.assertEqual(payload[0]["role"], "user")

    def test_result_events_are_never_replayed(self):
        payload = transcript_to_api([ResultMessage(subtype="success"), UserMessage.text_block("hi")])
        self.assertEqual(len(payload), 1)


class LiteralAliasTests(unittest.TestCase):
    """Closed vocabularies must be ``Literal[...]`` aliases, never ``"a" | "b"``.

    A string union evaluates at runtime and raises ``TypeError`` the moment anyone
    touches it, which makes the module unimportable.
    """

    ALIAS_OWNERS = (
        ("providers.base", ("SystemSubtype", "ResultSubtype", "BlockKind", "StopReason")),
        ("permissions", ("PermissionMode", "ToolKind")),
        ("tools", ("ToolKind",)),
        ("hooks", ("HookEvent", "HookDecisionKind")),
        ("agents", ("Acceptance",)),
    )

    def test_every_closed_alias_is_a_literal(self):
        import importlib

        for module_name, aliases in self.ALIAS_OWNERS:
            module = importlib.import_module(module_name)
            for alias in aliases:
                with self.subTest(module=module_name, alias=alias):
                    value = getattr(module, alias)
                    self.assertIs(typing.get_origin(value), typing.Literal)
                    self.assertTrue(typing.get_args(value))

    def test_the_rejected_form_actually_fails_at_runtime(self):
        # Guards the guard: this documents why the aliases are written this way.
        with self.assertRaises(TypeError):
            exec("BrokenAlias = 'a' | 'b'")


if __name__ == "__main__":
    unittest.main()
