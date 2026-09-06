import subprocess
import sys
import types
import unittest
from pathlib import Path

from providers.anthropic import (
    AnthropicProvider,
    build_request_kwargs,
    normalize_response,
    normalize_usage,
)
from providers.base import ProviderError, ProviderRequest, TextBlock, ToolUseBlock

COMPONENT_DIR = Path(__file__).resolve().parents[1]


def fake_usage(**overrides):
    base = {
        "input_tokens": 100,
        "output_tokens": 40,
        "cache_read_input_tokens": 10,
        "cache_creation_input_tokens": 4,
    }
    base.update(overrides)
    return types.SimpleNamespace(**base)


def fake_response(text=None, tool=None, usage=None, stop_reason="end_turn"):
    content = []
    if text is not None:
        content.append(types.SimpleNamespace(type="text", text=text))
    if tool is not None:
        tool_id, tool_name, tool_input = tool
        content.append(types.SimpleNamespace(type="tool_use", id=tool_id, name=tool_name, input=tool_input))
    return types.SimpleNamespace(content=content, usage=usage, stop_reason=stop_reason)


class FakeClient:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.kwargs = None

        client = self

        class _Messages:
            def create(self, **kwargs):
                client.kwargs = kwargs
                if client.error is not None:
                    raise client.error
                return client.response

        self.messages = _Messages()


class NormalizeUsageTests(unittest.TestCase):
    def test_reads_all_four_counters(self):
        usage = normalize_usage(fake_usage())
        self.assertEqual(usage.input_tokens, 100)
        self.assertEqual(usage.output_tokens, 40)
        self.assertEqual(usage.cache_read_input_tokens, 10)
        self.assertEqual(usage.cache_creation_input_tokens, 4)

    def test_missing_cache_fields_default_to_zero(self):
        usage = normalize_usage(types.SimpleNamespace(input_tokens=7, output_tokens=9))
        self.assertEqual(usage.input_tokens, 7)
        self.assertEqual(usage.output_tokens, 9)
        self.assertEqual(usage.cache_read_input_tokens, 0)
        self.assertEqual(usage.cache_creation_input_tokens, 0)

    def test_none_values_count_as_zero(self):
        usage = normalize_usage(fake_usage(cache_read_input_tokens=None))
        self.assertEqual(usage.cache_read_input_tokens, 0)


class NormalizeResponseTests(unittest.TestCase):
    def test_text_and_tool_use_blocks(self):
        response = normalize_response(fake_response(
            text="let me read",
            tool=("toolu_1", "Read", {"path": "a.txt"}),
            usage=fake_usage(),
            stop_reason="tool_use",
        ))
        self.assertEqual(response.content[0], TextBlock("let me read"))
        self.assertEqual(response.content[1], ToolUseBlock("toolu_1", "Read", {"path": "a.txt"}))
        self.assertEqual(response.stop_reason, "tool_use")
        self.assertEqual(response.usage.input_tokens, 100)

    def test_unknown_block_type_raises(self):
        response = types.SimpleNamespace(
            content=[types.SimpleNamespace(type="thinking", thinking="x")],
            usage=fake_usage(),
            stop_reason="end_turn",
        )
        with self.assertRaises(ProviderError):
            normalize_response(response)

    def test_stop_reason_defaults_to_end_turn(self):
        response = normalize_response(fake_response(text="done", usage=fake_usage(), stop_reason=None))
        self.assertEqual(response.stop_reason, "end_turn")


class RequestConstructionTests(unittest.TestCase):
    def test_kwargs_carry_model_messages_system_tools(self):
        request = ProviderRequest(
            model="claude-sonnet-4-5",
            messages=({"role": "user", "content": "hi"},),
            system="be nice",
            tools=({"name": "Read", "description": "d", "input_schema": {"type": "object"}},),
            max_tokens=123,
        )
        kwargs = build_request_kwargs(request, max_tokens=4096)
        self.assertEqual(kwargs["model"], "claude-sonnet-4-5")
        self.assertEqual(kwargs["messages"], [{"role": "user", "content": "hi"}])
        self.assertEqual(kwargs["system"], "be nice")
        self.assertEqual(kwargs["tools"], [{"name": "Read", "description": "d", "input_schema": {"type": "object"}}])
        self.assertEqual(kwargs["max_tokens"], 123)

    def test_empty_system_and_tools_are_omitted(self):
        request = ProviderRequest(model="m", messages=({"role": "user", "content": "hi"},))
        kwargs = build_request_kwargs(request, max_tokens=4096)
        self.assertNotIn("system", kwargs)
        self.assertNotIn("tools", kwargs)
        self.assertEqual(kwargs["max_tokens"], 4096)


class AnthropicProviderTests(unittest.TestCase):
    def test_round_trip_with_fake_client(self):
        client = FakeClient(response=fake_response(text="OK", usage=fake_usage()))
        provider = AnthropicProvider(client=client)
        response = provider.create_message(ProviderRequest(model="m", messages=({"role": "user", "content": "x"},)))
        self.assertEqual(response.content[0].text, "OK")
        self.assertEqual(client.kwargs["model"], "m")

    def test_client_exception_maps_to_provider_error_without_leaking_details(self):
        class _Boom(Exception):
            pass

        secret_detail = "sk-super-secret-key-1234567890abcd"
        client = FakeClient(error=_Boom(f"request failed for {secret_detail}"))
        provider = AnthropicProvider(client=client)
        with self.assertRaises(ProviderError) as ctx:
            provider.create_message(ProviderRequest(model="m", messages=()))
        self.assertIn("_Boom", str(ctx.exception))
        self.assertNotIn(secret_detail, str(ctx.exception))

    def test_importing_the_module_does_not_import_the_sdk(self):
        code = (
            "import sys\n"
            "import providers.anthropic\n"
            "assert 'anthropic' not in sys.modules, 'SDK must not be imported at module level'\n"
            "print('ok')\n"
        )
        run = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=str(COMPONENT_DIR))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("ok", run.stdout)


if __name__ == "__main__":
    unittest.main()
