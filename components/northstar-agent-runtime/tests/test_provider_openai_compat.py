"""The OpenAI-compatible provider: chat-wire translation in, runtime blocks out.

Nothing here touches a network or needs an API key: the client is injected, so the
tests assert exactly what would be sent and how a response becomes transcript
blocks. The end-to-end test at the bottom puts the adapter through the real
governed loop, which is the point of the module - a second model family behind the
same permission gate, hooks, ceilings and audit stream.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest

import support  # noqa: F401  (bootstraps sys.path)
from support import RuntimeTestCase, tool_turn

from providers.base import GenerationRequest, ProviderError
from providers.openai_compat import DEFAULT_MODEL, OpenAICompatProvider


class FakeClient:
    """Records the kwargs of every call and replays canned responses in order.

    The last response repeats, which is what the scripted provider does too, so a
    multi-turn test can end on a text turn instead of exhausting its turns.
    """

    def __init__(self, response) -> None:  # noqa: ANN001 - dict or list of dicts
        self.calls: list[dict] = []
        self._responses = response if isinstance(response, list) else [response]
        completions = self

        class _Completions:
            def create(self, **kwargs):  # noqa: ANN003 - test double
                index = len(completions.calls)
                completions.calls.append(kwargs)
                return completions._responses[min(index, len(completions._responses) - 1)]

        self.chat = type("Chat", (), {"completions": _Completions()})()

    @property
    def sent(self) -> dict:
        return self.calls[-1]


def _assistant(text: str = "", tool_calls: list[dict] | None = None, finish: str = "stop", usage: dict | None = None) -> dict:
    return {
        "id": "chatcmpl-1",
        "model": "gpt-4.1-2025-04-14",
        "choices": [{"index": 0, "finish_reason": finish, "message": {"role": "assistant", "content": text, "tool_calls": tool_calls or []}}],
        "usage": usage or {"prompt_tokens": 11, "completion_tokens": 5, "total_tokens": 16},
    }


def request(**overrides) -> GenerationRequest:
    base = {
        "system": "You are governed.",
        "messages": ({"role": "user", "content": [{"type": "text", "text": "hi"}]},),
        "model": DEFAULT_MODEL,
        "max_tokens": 128,
    }
    base.update(overrides)
    return GenerationRequest(**base)


class RequestBuildingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.provider = OpenAICompatProvider(client=FakeClient(_assistant("ok")))

    def test_system_and_user_text_become_chat_messages(self):
        payload = self.provider.build_payload(request())
        self.assertEqual(payload["messages"][0], {"role": "system", "content": "You are governed."})
        self.assertEqual(payload["messages"][1], {"role": "user", "content": "hi"})
        self.assertEqual(payload["model"], DEFAULT_MODEL)
        self.assertEqual(payload["max_tokens"], 128)

    def test_tool_definitions_are_wrapped_as_functions(self):
        payload = self.provider.build_payload(
            request(tools=({"name": "Read", "description": "read a file", "input_schema": {"type": "object", "properties": {}}},))
        )
        tool = payload["tools"][0]
        self.assertEqual(tool["type"], "function")
        self.assertEqual(tool["function"]["name"], "Read")
        self.assertEqual(tool["function"]["description"], "read a file")
        self.assertEqual(tool["function"]["parameters"]["type"], "object")
        self.assertEqual(payload["tool_choice"], "auto", "never force a call: the loop stays governable")

    def test_tool_use_becomes_tool_calls_with_encoded_arguments(self):
        payload = self.provider.build_payload(
            request(messages=({"role": "assistant", "content": [
                {"type": "text", "text": "reading"},
                {"type": "tool_use", "id": "tu_1", "name": "Read", "input": {"path": "notes.txt"}},
            ]},))
        )
        message = payload["messages"][1]
        self.assertEqual(message["content"], "reading")
        call = message["tool_calls"][0]
        self.assertEqual(call["id"], "tu_1")
        self.assertEqual(call["function"]["name"], "Read")
        self.assertEqual(json.loads(call["function"]["arguments"]), {"path": "notes.txt"})

    def test_tool_result_becomes_a_tool_message_immediately_after(self):
        payload = self.provider.build_payload(
            request(messages=(
                {"role": "assistant", "content": [{"type": "tool_use", "id": "tu_1", "name": "Read", "input": {"path": "n"}}]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "tu_1", "content": "file body", "is_error": False},
                    {"type": "text", "text": "and a note"},
                ]},
            ))
        )
        roles = [message.get("role") for message in payload["messages"]]
        self.assertEqual(roles, ["system", "assistant", "tool", "user"])
        self.assertEqual(payload["messages"][2]["tool_call_id"], "tu_1")
        self.assertEqual(payload["messages"][2]["content"], "file body")
        self.assertEqual(payload["messages"][3]["content"], "and a note")

    def test_thinking_is_dropped_from_the_request_only(self):
        payload = self.provider.build_payload(
            request(messages=({"role": "assistant", "content": [
                {"type": "thinking", "thinking": "private chain of thought"},
                {"type": "text", "text": "public answer"},
            ]},))
        )
        self.assertEqual(payload["messages"][1]["content"], "public answer")
        self.assertNotIn("private chain of thought", json.dumps(payload))

    def test_stop_sequences_and_temperature_pass_through(self):
        provider = OpenAICompatProvider(client=FakeClient(_assistant("ok")), temperature=0.2)
        payload = provider.build_payload(request(stop_sequences=("END",)))
        self.assertEqual(payload["stop"], ["END"])
        self.assertEqual(payload["temperature"], 0.2)

    def test_extra_body_reaches_the_sdk_call(self):
        provider = OpenAICompatProvider(client=FakeClient(_assistant("ok")), extra_body={"service_tier": "default"})
        self.assertEqual(provider.build_payload(request())["extra_body"], {"service_tier": "default"})


class TokenLimitFieldTests(unittest.TestCase):
    def test_auto_picks_the_reasoning_era_name(self):
        provider = OpenAICompatProvider(client=FakeClient(_assistant("ok")))
        self.assertEqual(provider.resolve_token_limit_field("gpt-4.1"), "max_tokens")
        self.assertEqual(provider.resolve_token_limit_field("gpt-5-mini"), "max_completion_tokens")
        self.assertEqual(provider.resolve_token_limit_field("o3"), "max_completion_tokens")
        self.assertEqual(provider.resolve_token_limit_field("O1-preview".lower()), "max_completion_tokens")

    def test_explicit_choices_are_honoured(self):
        for field, expected in (("none", None), ("max_tokens", "max_tokens"), ("max_completion_tokens", "max_completion_tokens")):
            provider = OpenAICompatProvider(client=FakeClient(_assistant("ok")), token_limit_field=field)
            self.assertEqual(provider.resolve_token_limit_field("gpt-5"), expected, field)
        with self.assertRaises(ValueError):
            OpenAICompatProvider(client=None, token_limit_field="tokens")

    def test_none_sends_no_limit_at_all(self):
        provider = OpenAICompatProvider(client=FakeClient(_assistant("ok")), token_limit_field="none")
        payload = provider.build_payload(request())
        self.assertNotIn("max_tokens", payload)
        self.assertNotIn("max_completion_tokens", payload)


class NormaliseTests(unittest.TestCase):
    def test_plain_text_turn(self):
        generation = OpenAICompatProvider.normalise(_assistant("hello there"))
        self.assertEqual([block.text for block in generation.content], ["hello there"])
        self.assertEqual(generation.stop_reason, "end_turn")
        self.assertEqual(generation.model, "gpt-4.1-2025-04-14")

    def test_usage_maps_onto_the_runtime_vocabulary(self):
        response = _assistant("x", usage={"prompt_tokens": 100, "completion_tokens": 7, "prompt_tokens_details": {"cached_tokens": 40}})
        usage = OpenAICompatProvider.normalise(response).usage
        self.assertEqual((usage.input_tokens, usage.output_tokens), (100, 7))
        self.assertEqual(usage.cache_read_input_tokens, 40, "server-side prefix caching must stay visible to the budget")
        self.assertEqual(usage.cache_creation_input_tokens, 0)

    def test_finish_reason_mapping(self):
        for finish, expected in (("stop", "end_turn"), ("tool_calls", "tool_use"), ("length", "max_tokens"), ("content_filter", "refusal")):
            with self.subTest(finish=finish):
                blocks = [{"type": "tool_use", "id": "t", "name": "Read", "input": {}}] if finish == "tool_calls" else []
                response = _assistant("t", tool_calls=blocks, finish=finish)
                self.assertEqual(OpenAICompatProvider.normalise(response).stop_reason, expected)

    def test_a_missing_finish_reason_with_a_tool_call_is_still_tool_use(self):
        call = {"id": "c1", "type": "function", "function": {"name": "Read", "arguments": "{}"}}
        generation = OpenAICompatProvider.normalise(_assistant("", tool_calls=[call], finish="stop"))
        self.assertEqual(generation.stop_reason, "tool_use")

    def test_malformed_arguments_fail_closed(self):
        call = {"id": "c1", "type": "function", "function": {"name": "Write", "arguments": "{\"path\": \"a.txt\""}}
        with self.assertRaises(ProviderError) as caught:
            OpenAICompatProvider.normalise(_assistant("", tool_calls=[call], finish="tool_calls"))
        self.assertIn("not valid JSON", str(caught.exception))

    def test_non_object_arguments_fail_closed(self):
        call = {"id": "c1", "type": "function", "function": {"name": "Write", "arguments": "[1,2,3]"}}
        with self.assertRaises(ProviderError):
            OpenAICompatProvider.normalise(_assistant("", tool_calls=[call], finish="tool_calls"))

    def test_empty_arguments_are_an_empty_input(self):
        call = {"id": "c1", "type": "function", "function": {"name": "LS", "arguments": ""}}
        generation = OpenAICompatProvider.normalise(_assistant("", tool_calls=[call], finish="tool_calls"))
        self.assertEqual(generation.content[0].input, {})

    def test_no_choices_is_an_error_not_a_crash(self):
        with self.assertRaises(ProviderError):
            OpenAICompatProvider.normalise({"choices": []})

    def test_transport_errors_become_provider_errors(self):
        class Boom:
            class chat:  # noqa: N801
                class completions:  # noqa: N801
                    @staticmethod
                    def create(**kwargs):  # noqa: ANN003
                        raise RuntimeError("connection refused")

        with self.assertRaises(ProviderError) as caught:
            OpenAICompatProvider(client=Boom()).generate(request())
        self.assertIn("connection refused", str(caught.exception))


class ClientConstructionTests(unittest.TestCase):
    def test_a_local_endpoint_needs_no_real_key(self):
        provider = OpenAICompatProvider(base_url="http://127.0.0.1:11434/v1")
        self.assertEqual(provider._client_kwargs["base_url"], "http://127.0.0.1:11434/v1")
        self.assertEqual(provider._client_kwargs["api_key"], "not-needed", "the SDK requires a key; local servers ignore it")

    @unittest.skipIf(importlib.util.find_spec("openai") is not None, "the openai package is installed here")
    def test_a_missing_sdk_is_reported_as_a_provider_error(self):
        with self.assertRaises(ProviderError) as caught:
            OpenAICompatProvider().generate(request())
        self.assertIn("pip install openai", str(caught.exception))


class GovernedLoopTests(RuntimeTestCase):
    """The whole point: a chat-shaped model behind the unchanged gate."""

    def test_tool_call_from_a_chat_model_still_passes_the_permission_gate(self):
        call = {"id": "c1", "type": "function", "function": {"name": "Write", "arguments": json.dumps({"path": "out.txt", "content": "written"})}}
        provider = OpenAICompatProvider(
            client=FakeClient([
                _assistant("", tool_calls=[call], finish="tool_calls"),
                _assistant("nothing to write, then"),
            ]),
            model="gpt-4.1",
        )
        root = self.workspace()
        report = self.drive(self.runtime(provider=provider, workspace=root, max_turns=3))
        self.assertExactlyOneResult(report)
        self.assertEqual(report.subtype, "success")
        self.assertTrue(report.denials, "the gate must see the chat model's tool call like any other")
        self.assertEqual(report.denials[0].source, "mode", "denied by permission_mode=default with no approver")
        self.assertFalse((root / "out.txt").exists())

    def test_cost_and_usage_are_recorded_for_an_unpriced_model(self):
        provider = OpenAICompatProvider(client=FakeClient(_assistant("done", usage={"prompt_tokens": 1000, "completion_tokens": 100})), model="gpt-4.1")
        report = self.drive(self.runtime(provider=provider, max_turns=2))
        self.assertTrue(report.result.pricing_estimated, "unknown models must be flagged, never silently priced")
        self.assertGreater(report.result.total_cost_usd, 0)
        self.assertEqual(report.result.total_usage.input_tokens, 1000)

    def test_stop_reason_max_tokens_ends_the_run_cleanly(self):
        provider = OpenAICompatProvider(client=FakeClient(_assistant("cut off", finish="length")), model="gpt-4.1")
        report = self.drive(self.runtime(provider=provider, max_turns=1))
        self.assertExactlyOneResult(report)
        self.assertEqual(len(report.errors), 0)


class CliWiringTests(RuntimeTestCase):
    def _invoke(self, argv):
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

    def test_a_claude_model_on_the_chat_provider_is_refused_before_any_request(self):
        code, out, err = self._invoke(["run", "--workspace", ".", "--provider", "openai", "--model", "claude-sonnet-4-5", "--prompt", "hi"])
        self.assertEqual(code, 64)
        self.assertIn("cannot serve", err)

    def test_a_non_claude_model_on_the_anthropic_provider_is_refused_too(self):
        code, out, err = self._invoke(["run", "--workspace", ".", "--provider", "anthropic", "--model", "gpt-4.1", "--prompt", "hi"])
        self.assertEqual(code, 64)
        self.assertIn("cannot serve", err)

    def test_the_default_model_follows_the_provider(self):
        from cli import PROVIDER_DEFAULT_MODELS, resolve_model

        self.assertEqual(resolve_model("openai"), PROVIDER_DEFAULT_MODELS["openai"])
        self.assertEqual(resolve_model("scripted"), "claude-sonnet-4-5")
        self.assertEqual(resolve_model("scripted", "gpt-4.1-mini"), "gpt-4.1-mini")

    def test_doctor_reports_the_provider_it_was_asked_about(self):
        code, out, err = self._invoke(["doctor", "--workspace", ".", "--provider", "openai"])
        self.assertIn("openai-compatible", out)
        self.assertIn("$OPENAI_API_KEY", out)
        self.assertNotIn("anthropic-sdk", out, "doctor must not nag about an SDK this provider does not use")
