"""Provider layer: the scripted reference provider and the Anthropic adapter.

The Anthropic side is tested against an injected fake client. The real network
path is deliberately not exercised here (no credentials in this environment);
that limitation is recorded in the component README and in the pull request.
"""
from __future__ import annotations

import sys
import types
import unittest
from dataclasses import dataclass

import support  # noqa: F401
from support import RuntimeTestCase, text_turn, tool_turn

from providers.anthropic import AnthropicProvider
from providers.base import (
    Generation,
    GenerationRequest,
    Provider,
    ProviderError,
    TextBlock,
    ThinkingBlock,
    ToolResultBlock,
    ToolUseBlock,
    Usage,
    transcript_to_api,
)
from providers.scripted import ScriptedProvider, ScriptedTurn


class ScriptedContractTests(unittest.TestCase):
    def request(self, index: int = 1) -> GenerationRequest:
        return GenerationRequest(
            system="s",
            messages=({"role": "user", "content": [{"type": "text", "text": "go"}]},),
            tools=(),
            model="m",
            max_tokens=100,
            turn_index=index,
        )

    def test_turn_shapes_all_produce_generations(self):
        provider = ScriptedProvider(
            [
                "bare text",
                {"text": "dict text"},
                {"tool": {"name": "Read", "input": {"path": "a"}}},
                {"tools": [{"name": "A", "input": {}}, {"name": "B", "input": {}}]},
                [TextBlock(text="sequence")],
                ScriptedTurn.tool("Read", {"path": "x"}, also_text="thinking out loud"),
                Generation(content=(TextBlock(text="already built"),)),
            ],
            model="pinned",
        )
        shapes = [provider.generate(self.request()) for _ in range(7)]
        self.assertEqual([block.text for block in shapes[0].content], ["bare text"])
        self.assertEqual([block.text for block in shapes[1].content], ["dict text"])
        self.assertEqual(shapes[2].content[0].name, "Read")
        self.assertEqual(shapes[2].stop_reason, "tool_use")
        self.assertEqual([block.name for block in shapes[3].content], ["A", "B"])
        self.assertEqual(shapes[4].content[0].text, "sequence")
        self.assertEqual([type(block).__name__ for block in shapes[5].content], ["TextBlock", "ToolUseBlock"])
        self.assertEqual(shapes[6].content[0].text, "already built")
        self.assertEqual({shape.model for shape in shapes}, {"pinned"})

    def test_shapes_are_validated(self):
        for bad in (3, {"unexpected": 1}, None):
            with self.subTest(bad=bad):
                with self.assertRaises((TypeError, ValueError)):
                    ScriptedProvider([bad])

    def test_default_usage_fills_turns_without_usage(self):
        provider = ScriptedProvider([{"text": "a"}, {"text": "b", "usage": {"input_tokens": 7}}], default_usage={"input_tokens": 100, "output_tokens": 2})
        first, second = provider.generate(self.request()), provider.generate(self.request())
        self.assertEqual((first.usage.input_tokens, first.usage.output_tokens), (100, 2))
        self.assertEqual((second.usage.input_tokens, second.usage.output_tokens), (7, 0), "an explicit usage wins")

    def test_running_dry_raises_with_the_turn_number(self):
        provider = ScriptedProvider([{"text": "only"}])
        provider.generate(self.request())
        with self.assertRaises(ProviderError) as caught:
            provider.generate(self.request(2))
        message = str(caught.exception)
        self.assertIn("exhausted after 1 scripted turn", message)
        self.assertIn("script more turns", message)

    def test_on_exhausted_alternatives(self):
        repeat = ScriptedProvider([{"text": "again"}], on_exhausted="repeat_last")
        stop = ScriptedProvider([{"text": "once"}], on_exhausted="stop")
        self.assertEqual([repeat.generate(self.request(i)).content[0].text for i in range(1, 4)], ["again", "again", "again"])
        self.assertEqual(stop.generate(self.request()).content[0].text, "once")
        self.assertIn("script exhausted", stop.generate(self.request()).content[0].text)
        with self.assertRaises(ValueError):
            ScriptedProvider([], on_exhausted="whatever")

    def test_scripted_errors_are_raised_not_swallowed(self):
        provider = ScriptedProvider([{"raises": ProviderError("upstream 429")}, {"text": "unreachable"}])
        with self.assertRaises(ProviderError):
            provider.generate(self.request())
        self.assertEqual(provider.cursor, 1)
        broken = ScriptedProvider([ScriptedTurn.error(TimeoutError("slow"))])
        with self.assertRaises(TimeoutError):
            broken.generate(self.request())

    def test_requests_are_recorded_for_introspection(self):
        provider = ScriptedProvider([tool_turn("Read", {"path": "a"}, usage={"input_tokens": 5}), text_turn("done")])
        provider.generate(self.request(1))
        provider.requests.append(self.request(2))
        self.assertEqual(provider.pending(), 1)
        self.assertEqual(provider.last_request().turn_index, 2)
        self.assertEqual(provider.message_roles(), ["user", "user"])
        self.assertEqual(provider.sent_tool_results(), [])

    def test_helpers_build_expected_turns(self):
        # The helpers in tests/support.py emit the dict shorthand, so the shapes are
        # asserted after ScriptedProvider coerces them.
        provider = ScriptedProvider(
            [tool_turn("Grep", {"pattern": "x"}, id="toolu_9", usage={"input_tokens": 3}, also_text="hm"), text_turn("hi")]
        )
        first = provider.generate(self.request())
        self.assertEqual(first.stop_reason, "tool_use")
        self.assertEqual([type(block).__name__ for block in first.content], ["TextBlock", "ToolUseBlock"])
        self.assertEqual(first.content[1].id, "toolu_9")
        self.assertEqual(first.usage.total_tokens, 3)
        second = provider.generate(self.request())
        self.assertEqual(second.content[0].text, "hi")
        self.assertEqual(second.stop_reason, "end_turn")

    def test_the_script_snapshots_its_inputs(self):
        # A test that reuses a payload dict must not be able to change what an
        # already-generated turn says.
        payload = {"path": "a"}
        provider = ScriptedProvider([{"tool": {"name": "Read", "input": payload}}], on_exhausted="repeat_last")
        first = provider.generate(self.request())
        payload["path"] = "mutated after handoff"
        self.assertEqual(first.content[0].input, {"path": "a"})
        self.assertEqual(provider.generate(self.request()).content[0].input, {"path": "a"})

    def test_unknown_turn_keys_are_refused(self):
        with self.assertRaises(TypeError) as caught:
            ScriptedProvider([{"tool": {"name": "Read", "input": {}}, "modle": "typo"}])
        self.assertIn("modle", str(caught.exception))


class AnthropicRequestTests(unittest.TestCase):
    def request(self, **kwargs) -> GenerationRequest:
        base = {
            "system": "be brief",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}],
            "tools": ({"name": "Read", "description": "d", "input_schema": {"type": "object"}}, {"name": "Write", "description": "d", "input_schema": {"type": "object"}}),
            "model": "",
            "max_tokens": 0,
        }
        base.update(kwargs)
        return GenerationRequest(**base)

    def test_payload_carries_the_required_keys(self):
        provider = AnthropicProvider(model="claude-opus-4-1", client=object())
        payload = provider.build_payload(self.request())
        self.assertEqual(payload["model"], "claude-opus-4-1")
        self.assertEqual(payload["max_tokens"], 4096)
        self.assertEqual(payload["messages"], [{"role": "user", "content": [{"type": "text", "text": "hello"}]}])
        self.assertEqual(len(payload["tools"]), 2)

    def test_request_values_override_the_provider_defaults(self):
        provider = AnthropicProvider(model="claude-opus-4-1", max_tokens=128, client=object())
        payload = provider.build_payload(self.request(model="claude-haiku-4-5", max_tokens=2048))
        self.assertEqual(payload["model"], "claude-haiku-4-5", "the model the runtime configured wins")
        self.assertEqual(payload["max_tokens"], 2048)

    def test_prompt_cache_marks_the_system_block_and_the_last_tool_only(self):
        provider = AnthropicProvider(client=object())
        payload = provider.build_payload(self.request())
        self.assertEqual(payload["system"][0]["cache_control"], {"type": "ephemeral"})
        self.assertNotIn("cache_control", payload["tools"][0])
        self.assertEqual(payload["tools"][1]["cache_control"], {"type": "ephemeral"})
        self.assertEqual(payload["messages"], [{"role": "user", "content": [{"type": "text", "text": "hello"}]}])
        plain = AnthropicProvider(client=object(), prompt_cache=False).build_payload(self.request())
        self.assertEqual(plain["system"], "be brief")
        self.assertNotIn("cache_control", plain["tools"][1])

    def test_optional_fields_are_omitted_not_null(self):
        payload = AnthropicProvider(client=object()).build_payload(self.request())
        self.assertNotIn("temperature", payload)
        self.assertNotIn("stop_sequences", payload)
        with_temperature = AnthropicProvider(client=object(), temperature=0.0).build_payload(self.request())
        self.assertEqual(with_temperature["temperature"], 0.0)
        stopped = AnthropicProvider(client=object()).build_payload(self.request(stop_sequences=("\n\nHuman:",)))
        self.assertEqual(stopped["stop_sequences"], ["\n\nHuman:"])

    def test_the_input_messages_are_not_mutated(self):
        provider = AnthropicProvider(client=object())
        request = self.request()
        provider.build_payload(request)
        self.assertNotIn("cache_control", request.tools[1])

    def test_client_construction_arguments(self):
        provider = AnthropicProvider(api_key="sk-test", max_retries=0, timeout=1.5, extra_headers={"x-app": "northstar"})
        self.assertEqual(provider._client_kwargs["api_key"], "sk-test")
        self.assertEqual(provider._client_kwargs["max_retries"], 0)
        self.assertEqual(provider._client_kwargs["timeout"], 1.5)
        self.assertEqual(provider._client_kwargs["default_headers"], {"x-app": "northstar"})

    def test_a_missing_sdk_is_a_provider_error(self):
        provider = AnthropicProvider()
        original = sys.modules.get("anthropic")
        sys.modules["anthropic"] = None  # makes "import anthropic" raise ImportError
        try:
            with self.assertRaises(ProviderError) as caught:
                _ = provider.client
            self.assertIn("anthropic", str(caught.exception))
            self.assertIn("scripted", str(caught.exception))
        finally:
            if original is None:
                del sys.modules["anthropic"]
            else:
                sys.modules["anthropic"] = original

    def test_max_tokens_must_be_positive(self):
        with self.assertRaises(ValueError):
            AnthropicProvider(max_tokens=0)


@dataclass
class FakeResponse:
    content: list
    usage: object = None
    stop_reason: str = ""
    model: str = "claude-sonnet-4-5"


class FakeMessages:
    def __init__(self, responses):
        self.responses = list(responses)
        self.payloads: list[dict] = []

    def create(self, **payload):
        self.payloads.append(payload)
        outcome = self.responses.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeClient:
    def __init__(self, responses):
        self.messages = FakeMessages(responses)


class AnthropicNormaliseTests(unittest.TestCase):
    def test_attribute_style_response(self):
        response = FakeResponse(
            content=[
                types.SimpleNamespace(type="text", text="working"),
                types.SimpleNamespace(type="thinking", thinking="because", signature="sig"),
                types.SimpleNamespace(type="tool_use", id="toolu_1", name="Read", input={"path": "a"}),
                types.SimpleNamespace(type="signature_delta", text="ignored"),
            ],
            usage=types.SimpleNamespace(input_tokens=10, output_tokens=4, cache_read_input_tokens=3, cache_creation_input_tokens=1),
            stop_reason="tool_use",
        )
        generation = AnthropicProvider.normalise(response)
        self.assertEqual([type(block).__name__ for block in generation.content], ["TextBlock", "ThinkingBlock", "ToolUseBlock"])
        self.assertEqual(generation.content[1].signature, "sig")
        self.assertEqual(generation.usage.as_dict(), {"input_tokens": 10, "output_tokens": 4, "cache_read_input_tokens": 3, "cache_creation_input_tokens": 1})
        self.assertEqual(generation.stop_reason, "tool_use")
        self.assertEqual(generation.model, "claude-sonnet-4-5")

    def test_dict_style_response_is_accepted(self):
        generation = AnthropicProvider.normalise(
            {
                "content": [{"type": "text", "text": "hi"}, {"type": "tool_use", "id": "t", "name": "LS", "input": {}}],
                "usage": {"input_tokens": 5, "output_tokens": 6, "ignored": "text", "flag": True},
                "stop_reason": None,
            }
        )
        self.assertEqual(
            generation.usage.as_dict(),
            {"input_tokens": 5, "output_tokens": 6, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0},
            "the cache fields are filled with zero so pricing never reads a missing key",
        )
        self.assertEqual(generation.stop_reason, "tool_use", "inferred from the presence of a tool_use block")

    def test_stop_reason_defaults_to_end_turn(self):
        self.assertEqual(AnthropicProvider.normalise(FakeResponse(content=[{"type": "text", "text": "x"}])).stop_reason, "end_turn")
        self.assertEqual(AnthropicProvider.normalise({"content": []}).stop_reason, "end_turn")

    def test_a_non_dict_tool_input_is_wrapped_not_dropped(self):
        generation = AnthropicProvider.normalise({"content": [{"type": "tool_use", "id": "t", "name": "Read", "input": "just-a-string"}]})
        self.assertEqual(generation.content[0].input, {"value": "just-a-string"})

    def test_usage_absent_is_zero_not_crash(self):
        self.assertEqual(AnthropicProvider.normalise(FakeResponse(content=[])).usage, Usage())

    def test_generate_wraps_sdk_failures_as_provider_errors(self):
        secret_body = "x" * 4000
        client = FakeClient([RuntimeError(f"Error code: 400 - {secret_body} api_key=sk-real-secret-value end")])
        provider = AnthropicProvider(client=client)
        with self.assertRaises(ProviderError) as caught:
            provider.generate(GenerationRequest(system="", messages=(), tools=(), model="", max_tokens=10))
        message = str(caught.exception)
        self.assertIn("anthropic request failed", message)
        self.assertLessEqual(len(message), 400, "a provider error must not carry a whole request body")
        self.assertNotIn("x" * 500, message)
        self.assertIsInstance(caught.exception.__cause__, RuntimeError)

    def test_provider_errors_are_not_double_wrapped(self):
        client = FakeClient([ProviderError("already normalised")])
        with self.assertRaises(ProviderError) as caught:
            AnthropicProvider(client=client).generate(GenerationRequest(system="", messages=(), tools=(), model="", max_tokens=10))
        self.assertEqual(str(caught.exception), "already normalised")

    def test_the_request_payload_is_what_the_sdk_received(self):
        client = FakeClient([FakeResponse(content=[{"type": "text", "text": "ok"}])])
        provider = AnthropicProvider(model="claude-sonnet-4-5", client=client)
        provider.generate(GenerationRequest(system="hi", messages=({"role": "user", "content": []},), tools=(), model="", max_tokens=10))
        self.assertEqual(client.messages.payloads[0]["model"], "claude-sonnet-4-5")
        self.assertEqual(client.messages.payloads[0]["system"][0]["text"], "hi")

    def test_close_only_touches_a_client_it_built(self):
        class Counting:
            closed = 0

            def close(self):
                type(self).closed += 1

        injected = Counting()
        AnthropicProvider(client=injected).close()
        self.assertEqual(injected.closed, 0)


class ProviderThroughTheRuntimeTests(RuntimeTestCase):
    def test_the_adapter_satisfies_the_contract_the_loop_needs(self):
        workspace = self.workspace({"a.txt": "contents\n"})
        client = FakeClient(
            [
                FakeResponse(
                    content=[{"type": "tool_use", "id": "toolu_a", "name": "Read", "input": {"path": "a.txt"}}],
                    usage=types.SimpleNamespace(input_tokens=900, output_tokens=20, cache_read_input_tokens=0, cache_creation_input_tokens=0),
                    stop_reason="tool_use",
                    model="claude-sonnet-4-5",
                ),
                FakeResponse(
                    content=[{"type": "text", "text": "read it"}],
                    usage=types.SimpleNamespace(input_tokens=1000, output_tokens=30, cache_read_input_tokens=0, cache_creation_input_tokens=0),
                    stop_reason="end_turn",
                    model="claude-sonnet-4-5",
                ),
            ]
        )
        provider = AnthropicProvider(model="claude-sonnet-4-5", client=client)
        report = self.drive(self.runtime(provider=provider, workspace=workspace), "read a.txt")
        self.assertEqual(report.subtype, "success")
        self.assertEqual(report.final_text, "read it")
        self.assertEqual(report.transcript[2].tool_results[0].text(), "contents\n")
        self.assertEqual(report.result.total_usage.input_tokens, 1900)
        self.assertAlmostEqual(report.cost_usd, (1900 * 3.0 + 50 * 15.0) / 1e6)
        self.assertEqual(len(client.messages.payloads), 2)
        self.assertEqual(client.messages.payloads[1]["messages"][-1]["role"], "user")

    def test_an_empty_response_is_a_clean_stop_not_a_crash(self):
        # A response with no content blocks is legal (the model declined or hit the
        # token limit). It must end the run quietly, not raise.
        client = FakeClient([object(), object()])
        runtime = self.runtime(provider=AnthropicProvider(client=client))
        report = self.drive(runtime, "go")
        self.assertEqual(report.subtype, "success")
        self.assertEqual(report.final_text, "")
        self.assertEqual(report.tool_calls, ())

    def test_the_base_class_is_abstract_about_generate(self):
        class Bare(Provider):
            pass

        provider = Bare()
        self.assertEqual(provider.name, "base")
        with self.assertRaises(NotImplementedError):
            provider.generate(GenerationRequest(system="", messages=(), tools=(), model="", max_tokens=1))
        provider.close()


class ApiTranscriptTests(unittest.TestCase):
    def test_tool_results_follow_their_use_across_a_compaction_gap(self):
        from providers.base import AssistantMessage, UserMessage

        transcript = [
            UserMessage(content="question"),
            AssistantMessage(content=(ToolUseBlock(id="t1", name="Read", input={}),)),
            UserMessage(content=(ToolResultBlock(tool_use_id="t1", content="out"),)),
            AssistantMessage(content="final"),
        ]
        messages = transcript_to_api(transcript)
        self.assertEqual([message["role"] for message in messages], ["user", "assistant", "user", "assistant"])
        self.assertEqual(messages[2]["content"][0]["type"], "tool_result")

    def test_a_run_may_not_start_with_an_assistant_turn(self):
        from providers.base import AssistantMessage

        messages = transcript_to_api([AssistantMessage(content="orphan")])
        self.assertEqual(messages[0]["role"], "user", "a leading assistant turn is an API 400")
        self.assertEqual(messages[0]["content"], [{"type": "text", "text": "(continued session)"}])


if __name__ == "__main__":
    unittest.main()
