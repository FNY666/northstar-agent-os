import unittest

from providers.base import ProviderError, ProviderRequest
from providers.scripted import ScriptedProvider, normalize_step


def make_request(n: int = 1) -> ProviderRequest:
    return ProviderRequest(model="claude-sonnet-4-5", messages=({"role": "user", "content": f"prompt {n}"},))


class ScriptedProviderTests(unittest.TestCase):
    def test_replays_steps_in_order_deterministically(self):
        provider = ScriptedProvider([{"text": "one"}, {"text": "two"}])
        first = provider.create_message(make_request())
        second = provider.create_message(make_request())
        self.assertEqual(first.content[0].text, "one")
        self.assertEqual(second.content[0].text, "two")

    def test_records_every_request_it_receives(self):
        provider = ScriptedProvider(["a", "b"])
        provider.create_message(make_request(1))
        provider.create_message(make_request(2))
        self.assertEqual([c.messages[0]["content"] for c in provider.calls], ["prompt 1", "prompt 2"])
        self.assertEqual([c.model for c in provider.calls], ["claude-sonnet-4-5", "claude-sonnet-4-5"])

    def test_script_exhaustion_raises_provider_error(self):
        provider = ScriptedProvider(["only one"])
        provider.create_message(make_request())
        with self.assertRaises(ProviderError):
            provider.create_message(make_request())

    def test_error_step_raises_provider_error(self):
        provider = ScriptedProvider([{"error": "boom"}])
        with self.assertRaises(ProviderError) as ctx:
            provider.create_message(make_request())
        self.assertIn("boom", str(ctx.exception))

    def test_default_usage_when_omitted(self):
        provider = ScriptedProvider(["hi"])
        response = provider.create_message(make_request())
        self.assertGreater(response.usage.input_tokens, 0)
        self.assertGreater(response.usage.output_tokens, 0)
        self.assertEqual(response.usage.cache_read_input_tokens, 0)
        self.assertEqual(response.usage.cache_creation_input_tokens, 0)

    def test_explicit_usage_includes_cache_fields(self):
        provider = ScriptedProvider(
            [{"text": "hi", "usage": {"input_tokens": 100, "output_tokens": 20,
                                      "cache_read_input_tokens": 5, "cache_creation_input_tokens": 3}}]
        )
        response = provider.create_message(make_request())
        self.assertEqual(response.usage.input_tokens, 100)
        self.assertEqual(response.usage.output_tokens, 20)
        self.assertEqual(response.usage.cache_read_input_tokens, 5)
        self.assertEqual(response.usage.cache_creation_input_tokens, 3)

    def test_tool_step_ids_are_sequential_and_stable(self):
        provider = ScriptedProvider([
            {"tools": [{"name": "Read", "input": {"path": "a"}}]},
            {"tools": [{"name": "Grep", "input": {"pattern": "x"}}, {"name": "List", "input": {}}]},
        ])
        first = provider.create_message(make_request())
        second = provider.create_message(make_request())
        self.assertEqual(first.content[0].id, "toolu_script_1")
        self.assertEqual([b.id for b in second.content], ["toolu_script_2", "toolu_script_3"])
        self.assertEqual(second.content[0].name, "Grep")
        self.assertEqual(second.content[0].input, {"pattern": "x"})

    def test_string_step_is_final_text(self):
        provider = ScriptedProvider(["plain string step"])
        response = provider.create_message(make_request())
        self.assertEqual(response.stop_reason, "end_turn")
        self.assertEqual(response.content[0].text, "plain string step")

    def test_tool_step_stop_reason_is_tool_use(self):
        provider = ScriptedProvider([{"tools": [{"name": "Read", "input": {}}]}])
        response = provider.create_message(make_request())
        self.assertEqual(response.stop_reason, "tool_use")

    def test_invalid_steps_raise(self):
        with self.assertRaises(ProviderError):
            normalize_step(42)
        with self.assertRaises(ProviderError):
            normalize_step({"usage": {}})
        with self.assertRaises(ProviderError):
            normalize_step({"text": "x", "tools": "not-a-list"})
        with self.assertRaises(ProviderError):
            normalize_step({"text": "x", "tools": [{"input": {}}]})

    def test_wire_conversion_round_trips(self):
        provider = ScriptedProvider([{"text": "t", "tools": [{"name": "Read", "input": {"path": "p"}}]}])
        response = provider.create_message(make_request())
        wire = [b.to_wire() for b in response.content]
        self.assertEqual(wire[0], {"type": "text", "text": "t"})
        self.assertEqual(wire[1]["type"], "tool_use")
        self.assertEqual(wire[1]["name"], "Read")
        self.assertEqual(wire[1]["input"], {"path": "p"})


if __name__ == "__main__":
    unittest.main()
