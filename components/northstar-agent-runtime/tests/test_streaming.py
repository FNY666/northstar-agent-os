"""Token-level streaming: what ``stream=True`` may and may not change.

The claim being tested is narrow and it is the whole point: streaming is a
**presentation** of the same governed run. It must not alter the transcript, the
ceilings, the permission decisions, the exit code, or the fact that a run ends with
exactly one ``result``. What it *may* do is fail a run - loudly - when a provider's
stream and the turn it finally returns disagree, because a lie told in real time is
still a lie even when the record ends up correct.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from agents import AgentDefinition, AgentRegistry
from cli import USAGE_ERROR, main
from loop import (
    MAX_STREAM_EVENTS_PER_TURN,
    AgentRuntime,
    RuntimeConfig,
    RuntimeConfigurationError,
)
from providers.base import (
    MAX_STREAM_TURN_CHARS,
    Generation,
    GenerationRequest,
    Provider,
    ProviderError,
    StreamDelta,
    TextBlock,
    Usage,
    split_for_stream,
    stream_comparable_text,
    stream_fidelity,
)
from providers.scripted import ScriptedProvider, ScriptedTurn
from sessions import RECORD_TYPES
from events import event_to_dict


class _Streaming(Provider):
    """Test provider whose stream is written out per test."""

    name = "test"
    streams = True

    def __init__(self, items=None, *, generation=None, error: Exception | None = None, finish: bool = True) -> None:
        self.items = list(items or [])
        self.generation = generation if generation is not None else Generation(content=("done",))
        self.error = error
        #: ``False`` models a stream that stops early, without ever returning a turn.
        self.finish = finish
        self.calls = 0
        self.closed = 0

    def generate(self, request: GenerationRequest) -> Generation:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.generation

    def stream(self, request: GenerationRequest):
        self.calls += 1
        try:
            for item in self.items:
                if isinstance(item, Exception):
                    raise item
                yield item
            if self.error is not None:
                raise self.error
            if self.finish:
                yield self.generation
        finally:
            self.closed += 1


def run(provider: Provider, *, stream: bool = True, **config: object) -> list:
    runtime = AgentRuntime(provider=provider, config=RuntimeConfig(stream=stream, **config))  # type: ignore[arg-type]
    return list(runtime.run("go"))


def kinds(events: list) -> list[str]:
    return [type(event).__name__ for event in events]


def deltas(events: list) -> list[str]:
    return [event.text for event in events if isinstance(event, StreamDelta)]


class ContractTests(unittest.TestCase):
    """The provider-facing helpers, which the loop and every adapter share."""

    def test_fidelity_is_exact_in_both_directions(self):
        self.assertIsNone(stream_fidelity(["a", "b"], "ab"))
        self.assertIsNone(stream_fidelity([], ""))
        self.assertIn("1 char(s) the turn does not contain", stream_fidelity(["abc"], "ab"))
        self.assertIn("short of", stream_fidelity(["a"], "abc"))
        self.assertIn("diverge after 1", stream_fidelity(["ax"], "ab"))
        self.assertIn("no text at all", stream_fidelity([], "ab"))

    def test_comparison_uses_block_order_without_a_separator(self):
        # AssistantMessage.text joins blocks with newlines for a human reader; a stream
        # is chunked per block, so comparing against the display text would raise a
        # false alarm on any multi-block answer.
        turn = Generation(content=("a", "b"))
        self.assertEqual(stream_comparable_text(turn), "ab")
        self.assertNotEqual(stream_comparable_text(turn), "a\nb")

    def test_a_turn_of_only_tools_streams_nothing_and_still_agrees(self):
        turn = Generation(content=({"type": "tool_use", "id": "1", "name": "t", "input": {}},))
        self.assertEqual(stream_comparable_text(turn), "")
        self.assertIsNone(stream_fidelity([], stream_comparable_text(turn)))

    def test_splitting_round_trips_exactly(self):
        text = "x" * 5_000
        self.assertEqual("".join(split_for_stream(text)), text)
        self.assertEqual([len(part) for part in split_for_stream(text, size=2_000)], [2_000, 2_000, 1_000])
        self.assertEqual(split_for_stream(""), [])
        with self.assertRaises(ValueError):
            split_for_stream("abc", size=0)


class LoopStreamTests(unittest.TestCase):
    def test_deltas_come_before_the_assistant_message_and_result_last(self):
        provider = ScriptedProvider([ScriptedTurn.streamed("hello there", ["hello ", "there"])])
        events = run(provider)
        self.assertEqual(
            kinds(events),
            ["SystemMessage", "StreamDelta", "StreamDelta", "AssistantMessage", "ResultMessage"],
        )
        self.assertEqual("".join(deltas(events)), "hello there")
        self.assertEqual(events[-1].subtype, "success")

    def test_streaming_changes_no_number_the_run_reports(self):
        script = [{"text": "one two", "stream": ["one ", "two"]}, {"tool": {"name": "LS", "input": {"path": "."}}}, {"text": "done"}]
        streamed = run(ScriptedProvider(script), max_tool_calls=None)
        plain = run(ScriptedProvider(script), stream=False, max_tool_calls=None)
        self.assertEqual([e for e in kinds(streamed) if e != "StreamDelta"], kinds(plain))
        self.assertEqual(streamed[-1].subtype, plain[-1].subtype)
        self.assertEqual(streamed[-1].num_turns, plain[-1].num_turns)
        self.assertEqual(streamed[-1].total_usage.as_dict(), plain[-1].total_usage.as_dict())
        self.assertEqual(streamed[-1].total_cost_usd, plain[-1].total_cost_usd)

    def test_usage_is_attributed_from_the_turn_not_from_the_stream(self):
        provider = _Streaming(
            [StreamDelta(text="partial ")],
            generation=Generation(content=("partial answer",), usage=Usage(input_tokens=40, output_tokens=8), model="m"),
        )
        events = run(provider)
        self.assertEqual(events[-1].total_usage.input_tokens, 40)
        self.assertEqual(events[-1].total_cost_usd, events[-1].total_cost_usd)

    def test_a_provider_that_shows_text_it_did_return_fails_the_run(self):
        provider = _Streaming([StreamDelta(text="everything is fine")], generation=Generation(content=("disk full",)))
        events = run(provider)
        self.assertEqual(events[-1].subtype, "error_during_execution")
        self.assertIn("stream and the turn diverge", events[-1].errors[0])
        self.assertNotIn("AssistantMessage", kinds(events), "a turn that cannot be described must not be recorded")

    def test_a_mid_stream_fault_leaves_no_partial_turn_behind(self):
        provider = _Streaming([StreamDelta(text="half a se"), ProviderError("connection reset")])
        with tempfile.TemporaryDirectory() as tmp:
            runtime = AgentRuntime(
                provider=provider,
                config=RuntimeConfig(stream=True, session_id="probe"),
                sessions=_store(tmp),
            )
            events = list(runtime.run("go"))
            records = _records(tmp)
        self.assertEqual(events[-1].subtype, "error_during_execution")
        self.assertIn("connection reset", events[-1].errors[0])
        self.assertIn("half a se", deltas(events), "the operator did see it; the audit says it never completed")
        self.assertEqual([record["type"] for record in records].count("assistant"), 0)
        self.assertNotIn("half a se", json.dumps(records))

    def test_the_provider_stream_is_closed_when_the_run_is_interrupted(self):
        provider = _Streaming([StreamDelta(text=str(index)) for index in range(50)])
        runtime = AgentRuntime(provider=provider, config=RuntimeConfig(stream=True))
        stream = runtime.run("go")
        for _ in range(3):
            next(stream)
        stream.close()
        self.assertEqual(provider.closed, 1, "an interrupted run must not hold the provider's stream open")

    def test_fabricated_events_after_the_turn_are_a_provider_fault(self):
        provider = _Streaming([Generation(content=("text",)), StreamDelta(text="trailing")])
        events = run(provider)
        self.assertEqual(events[-1].subtype, "error_during_execution")
        self.assertIn("after the turn was complete", events[-1].errors[0])

    def test_a_second_turn_in_one_stream_is_a_provider_fault(self):
        provider = _Streaming([Generation(content=("a",)), Generation(content=("b",))])
        events = run(provider)
        self.assertIn("more than one Generation", events[-1].errors[0])

    def test_a_stream_that_ends_without_a_turn_is_a_provider_fault(self):
        provider = _Streaming([StreamDelta(text="only text")], finish=False)
        events = run(provider)
        self.assertIn("ended without returning the turn", events[-1].errors[0])

    def test_a_junk_item_in_the_stream_is_a_provider_fault(self):
        provider = _Streaming([{"type": "text", "text": "not a StreamDelta"}])
        events = run(provider)
        self.assertIn("instead of a StreamDelta or a Generation", events[-1].errors[0])

    def test_empty_chunks_cost_no_event(self):
        provider = _Streaming([StreamDelta(text=""), StreamDelta(text="x"), StreamDelta(text="")])
        self.assertEqual(deltas(run(provider)), ["x"])

    def test_an_oversized_delta_is_rechunked_not_dropped(self):
        provider = _Streaming([StreamDelta(text="q" * 9_000)], generation=Generation(content=("q" * 9_000,)))
        events = run(provider)
        sizes = [len(text) for text in deltas(events)]
        self.assertEqual(sizes, [2_000, 2_000, 2_000, 2_000, 1_000])
        self.assertEqual(sum(sizes), 9_000)
        self.assertEqual(events[-1].subtype, "success")


class CapTests(unittest.TestCase):
    """Volume limits are the client's, so exceeding them is a note, not a fault."""

    def test_a_turn_longer_than_the_char_cap_is_shown_as_a_prefix(self):
        long_text = "x" * (MAX_STREAM_TURN_CHARS + 500)
        provider = _Streaming(
            [StreamDelta(text="x" * 2_000) for _ in range(MAX_STREAM_TURN_CHARS // 2_000 + 1)],
            generation=Generation(content=(long_text,)),
        )
        events = run(provider)
        notes = [event.content for event in events if event.__class__.__name__ == "SystemMessage" and event.subtype == "informational"]
        self.assertEqual(len(notes), 1)
        self.assertIn("reached the record but not the live view", notes[0])
        self.assertIn("AssistantMessage", kinds(events))
        self.assertEqual(events[-1].subtype, "success")
        self.assertEqual(len(events[-2].text), len(long_text))

    def test_an_event_flood_is_cut_at_the_per_turn_cap(self):
        text = "z" * (MAX_STREAM_EVENTS_PER_TURN + 200)
        provider = _Streaming([StreamDelta(text="z") for _ in range(MAX_STREAM_EVENTS_PER_TURN + 200)], generation=Generation(content=(text,)))
        events = run(provider)
        self.assertEqual(len(deltas(events)), MAX_STREAM_EVENTS_PER_TURN)
        self.assertEqual(events[-1].subtype, "success")

    def test_a_cap_that_breaks_the_prefix_relation_is_still_a_fault(self):
        # Truncation may make the live view *shorter*; it may never make it *different*.
        # So once the client has withheld text, the forwarded prefix must still match the
        # head of the record - which is what this provider violates.
        flood = StreamDelta(text="x" * 2_000)
        provider = _Streaming(
            [flood for _ in range(MAX_STREAM_TURN_CHARS // 2_000 * 2)],
            generation=Generation(content=("y" * (MAX_STREAM_TURN_CHARS * 2))),
        )
        events = run(provider)
        self.assertEqual(events[-1].subtype, "error_during_execution")
        self.assertIn("not a prefix", events[-1].errors[0])


class ConfigurationTests(unittest.TestCase):
    def test_a_provider_that_cannot_stream_is_refused_rather_than_degraded(self):
        plain = ScriptedProvider([{"text": "x"}])
        plain.streams = False
        with self.assertRaises(RuntimeConfigurationError) as caught:
            AgentRuntime(provider=plain, config=RuntimeConfig(stream=True))
        self.assertIn("cannot stream text incrementally", str(caught.exception))

    def test_the_default_stream_implementation_is_a_safe_fallback_for_direct_callers(self):
        class Whole(Provider):
            name = "whole"

            def generate(self, request):
                return Generation(content=("all at once",))

        items = list(Whole().stream(GenerationRequest(system="", messages=())))
        self.assertEqual([type(item).__name__ for item in items], ["Generation"])
        self.assertEqual(items[0].text(), "all at once")

    def test_claiming_the_capability_without_implementing_it_is_caught(self):
        # ScriptedProvider.streams is True; a provider that copies the flag but not the
        # method must fail the same way, which is why the check is on content and not on
        # the flag.
        provider = _Streaming([], generation=Generation(content=("text appeared from nowhere",)))
        provider.stream = lambda request: iter([provider.generation])  # type: ignore[assignment]
        events = run(provider)
        self.assertIn("carried no text at all", events[-1].errors[0])

    def test_stream_must_be_a_boolean(self):
        with self.assertRaises(RuntimeConfigurationError):
            RuntimeConfig(stream="yes")

    def test_stream_is_declared_in_the_init_record(self):
        events = run(ScriptedProvider([{"text": "x"}]))
        self.assertTrue(events[0].data["stream"])
        off = run(ScriptedProvider([{"text": "x"}]), stream=False)
        self.assertNotIn("stream", off[0].data)


class TranscriptStabilityTests(unittest.TestCase):
    """The audit trail is exactly what it was, byte for byte, apart from identity."""

    def test_no_stream_specific_record_type_exists(self):
        self.assertNotIn("stream_delta", RECORD_TYPES)
        self.assertNotIn("stream", RECORD_TYPES)

    def test_the_records_written_are_identical_with_and_without_streaming(self):
        script = [{"text": "hello world"}, {"tool": {"name": "LS", "input": {"path": "."}}}, {"text": "done"}]
        with tempfile.TemporaryDirectory() as streamed, tempfile.TemporaryDirectory() as plain:
            # Both runs must be *driven*: run() is a generator, so an un-consumed call
            # would write nothing and the comparison below would pass vacuously.
            list(AgentRuntime(provider=ScriptedProvider(script), config=RuntimeConfig(stream=True), sessions=_store(streamed)).run("go"))
            list(AgentRuntime(provider=ScriptedProvider(script), config=RuntimeConfig(stream=False), sessions=_store(plain)).run("go"))
            left = _strip(_records(streamed))
            right = _strip(_records(plain))
        self.assertGreater(len(left), 3, "the run must actually have written something")
        # Everything the transcript is *for* - the turns, the tool calls, the results,
        # the compaction boundaries - is byte-identical. The single difference is the
        # init record declaring how the run was presented, which is a fact about the run
        # and not a claim the model ever saw.
        self.assertEqual(
            [record for record in left if record["type"] != "session_start"],
            [record for record in right if record["type"] != "session_start"],
        )
        init_left = next(record for record in left if record["type"] == "session_start")
        init_right = next(record for record in right if record["type"] == "session_start")
        self.assertTrue(init_left["data"].pop("stream"))
        self.assertNotIn("stream", init_right["data"])
        self.assertEqual(init_left, init_right)

    def test_truncation_note_is_an_event_and_not_a_record(self):
        long_text = "x" * (MAX_STREAM_TURN_CHARS + 1_000)
        provider = _Streaming([StreamDelta(text="x" * 2_000) for _ in range(120)], generation=Generation(content=(long_text,)))
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            events = list(
                AgentRuntime(provider=provider, config=RuntimeConfig(stream=True), sessions=store).run("go")
            )
            records = _records(tmp)
        self.assertTrue(any(isinstance(event, StreamDelta) for event in events))
        self.assertNotIn("capped", json.dumps(records))

    def test_a_resumed_run_cannot_replay_deltas(self):
        # Deltas are not in the transcript, so a resumed run has nothing to re-stream: the
        # first turn's text must not be re-emitted.
        script = [{"text": "first turn", "stream": ["first ", "turn"]}]
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            AgentRuntime(provider=ScriptedProvider(script), config=RuntimeConfig(stream=True), sessions=store).run("go")
            resumed = AgentRuntime(
                provider=ScriptedProvider([{"text": "second"}]),
                config=RuntimeConfig(stream=True, session_id=store.session_id),
                sessions=store,
            )
            events = list(resumed.run("more", resume=store.transcript()))
        self.assertNotIn("first ", deltas(events))


class ProviderAdapterTests(unittest.TestCase):
    """Both live adapters, against injected fakes: the wire, not the network."""

    def test_anthropic_forwards_text_deltas_and_records_the_final_message(self):
        from providers.anthropic import AnthropicProvider

        class Stream:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            @property
            def text_stream(self):
                return iter(["Hel", "lo"])

            def get_final_message(self):
                return SimpleNamespace(
                    model="claude-sonnet-4-5",
                    stop_reason="end_turn",
                    usage=SimpleNamespace(input_tokens=9, output_tokens=4),
                    content=[
                        SimpleNamespace(type="thinking", thinking="private", signature="s"),
                        SimpleNamespace(type="text", text="Hel"),
                        SimpleNamespace(type="text", text="lo"),
                    ],
                )

        provider = AnthropicProvider(client=SimpleNamespace(messages=SimpleNamespace(stream=lambda **kw: Stream())))
        items = list(provider.stream(GenerationRequest(system="", messages=())))
        shown = [item.text for item in items if isinstance(item, StreamDelta)]
        generation = items[-1]
        self.assertEqual(shown, ["Hel", "lo"])
        self.assertEqual(stream_comparable_text(generation), "Hello")
        self.assertIsNone(stream_fidelity(shown, stream_comparable_text(generation)))
        self.assertEqual(len(generation.content), 3, "the thinking block is part of the record")
        self.assertNotIn("private", "".join(shown), "reasoning is never streamed")
        self.assertEqual(generation.usage.input_tokens, 9)

    def test_anthropic_stream_failure_becomes_a_provider_error(self):
        from providers.anthropic import AnthropicProvider

        class Boom:
            def __enter__(self):
                raise RuntimeError("401 unauthorized")

            def __exit__(self, *exc):
                return False

        provider = AnthropicProvider(client=SimpleNamespace(messages=SimpleNamespace(stream=lambda **kw: Boom())))
        with self.assertRaises(ProviderError) as caught:
            list(provider.stream(GenerationRequest(system="", messages=())))
        # The reason survives; a request body never does (see _reason's cap).
        self.assertIn("anthropic stream failed", str(caught.exception))
        self.assertLess(len(str(caught.exception)), 120)

    def test_openai_reassembles_sse_and_keeps_the_usage(self):
        from providers.openai_compat import OpenAICompatProvider

        chunks = [
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="Hello"), finish_reason=None)], usage=None, model="gpt-4.1"),
            SimpleNamespace(
                choices=[SimpleNamespace(delta=SimpleNamespace(reasoning_content="hidden", content=" world"), finish_reason=None)],
                usage=None,
                model="gpt-4.1",
            ),
            SimpleNamespace(choices=[], usage=SimpleNamespace(prompt_tokens=11, completion_tokens=5)),
        ]
        seen: dict = {}

        def create(**kwargs):
            seen.update(kwargs)
            return iter(chunks)

        provider = OpenAICompatProvider(client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))))
        items = list(provider.stream(GenerationRequest(system="s", messages=(), model="gpt-4.1")))
        shown = [item.text for item in items if isinstance(item, StreamDelta)]
        generation = items[-1]
        self.assertEqual(shown, ["Hello", " world"])
        self.assertEqual(stream_comparable_text(generation), "Hello world")
        self.assertNotIn("hidden", "".join(shown))
        self.assertEqual(generation.usage.input_tokens, 11, "a stream must still report cost")
        self.assertEqual(seen["stream"], True)
        self.assertEqual(seen["stream_options"], {"include_usage": True})

    def test_openai_assembles_tool_arguments_that_never_arrived_whole(self):
        from providers.openai_compat import OpenAICompatProvider

        GOOD = '{"path": "a.txt", "content": "hi"}'
        TRUNCATED = '{"path"'

        def fragments(args):
            call = SimpleNamespace(index=0, id="c1", function=SimpleNamespace(name="Write", arguments=args[0]))
            choice = SimpleNamespace(delta=SimpleNamespace(tool_calls=[call]), finish_reason="tool_calls")
            return iter([SimpleNamespace(choices=[choice], usage=None)])

        ok_client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **kw: fragments([GOOD]))))
        generation = list(OpenAICompatProvider(client=ok_client).stream(GenerationRequest(system="", messages=(), model="gpt-4.1")))[-1]
        self.assertEqual(generation.tool_uses[0].input, {"path": "a.txt", "content": "hi"})
        self.assertEqual(generation.stop_reason, "tool_use")

        # Truncated arguments must fail closed: an empty payload on a write tool is a
        # hallucinated call executed as a real one.
        broken_client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **kw: fragments([TRUNCATED]))))
        with self.assertRaises(ProviderError):
            list(OpenAICompatProvider(client=broken_client).stream(GenerationRequest(system="", messages=(), model="gpt-4.1")))

    def test_a_gateway_without_streaming_reports_a_provider_error(self):
        from providers.openai_compat import OpenAICompatProvider

        def create(**kwargs):
            raise TypeError("does not support stream")

        provider = OpenAICompatProvider(client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))))
        with self.assertRaises(ProviderError) as caught:
            list(provider.stream(GenerationRequest(system="", messages=(), model="gpt-4.1")))
        self.assertIn("chat completions stream failed", str(caught.exception))

    def test_usage_can_be_declared_away_for_gateways_that_reject_the_field(self):
        from providers.openai_compat import OpenAICompatProvider

        seen: dict = {}

        def create(**kwargs):
            seen.update(kwargs)
            return iter([])

        provider = OpenAICompatProvider(client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))), stream_usage=False)
        list(provider.stream(GenerationRequest(system="", messages=(), model="gpt-4.1")))
        self.assertNotIn("stream_options", seen)
        self.assertEqual(seen["stream"], True)


class RenderingTests(unittest.TestCase):
    def test_event_to_dict_gives_a_stream_delta_its_own_type(self):
        payload = event_to_dict(StreamDelta(text="hi", block_index=1, turn_index=2, provider="p"))
        self.assertEqual(
            payload,
            {"type": "stream_delta", "text": "hi", "block_index": 1, "turn_index": 2, "provider": "p"},
        )

    def test_a_delta_carries_no_cost_no_usage_and_no_tool_input(self):
        fields = set(StreamDelta(text="x").as_dict())
        self.assertEqual(fields, {"type", "text", "block_index", "turn_index", "provider"})


class CliStreamTests(unittest.TestCase):
    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix="nsar-stream-"))

    def cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        saved, sys.stdin = sys.stdin, io.StringIO("")
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(list(argv))
        finally:
            sys.stdin = saved
        return code, out.getvalue(), err.getvalue()

    def script(self, turns: list) -> Path:
        path = self.workspace / "s.json"
        path.write_text(json.dumps(turns), encoding="utf-8")
        return path

    def test_human_output_prints_streamed_text_once(self):
        script = self.script([{"text": "hello streamed world", "stream": ["hello ", "streamed ", "world"]}])
        code, out, _ = self.cli("run", "--workspace", str(self.workspace), "--prompt", "p", "--script", str(script), "--stream")
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count("hello streamed world"), 1)
        self.assertIn("[success]", out)

    def test_json_output_emits_deltas_then_the_assistant_event_then_the_result(self):
        script = self.script([{"text": "a b", "stream": ["a ", "b"]}])
        code, out, _ = self.cli("run", "--workspace", str(self.workspace), "--prompt", "p", "--script", str(script), "--stream", "--json")
        self.assertEqual(code, 0, out)
        parsed = [json.loads(line) for line in out.splitlines() if line.strip()]
        self.assertEqual([item["type"] for item in parsed[:4]], ["system", "stream_delta", "stream_delta", "assistant"])
        self.assertEqual(parsed[-1]["type"], "result")
        self.assertTrue(parsed[0]["data"]["stream"])
        self.assertEqual("".join(item["text"] for item in parsed if item["type"] == "stream_delta"), "a b")

    def test_quiet_still_prints_exactly_one_result_line(self):
        script = self.script([{"text": "x" * 80, "stream": ["x" * 40, "x" * 40]}])
        code, out, _ = self.cli("run", "--workspace", str(self.workspace), "--prompt", "p", "--script", str(script), "--stream", "--quiet")
        self.assertEqual(code, 0, out)
        self.assertNotIn("xxxx", out)
        self.assertEqual(out.count("[success]"), 1)

    def test_dry_run_reports_the_stream_flag(self):
        code, out, _ = self.cli("run", "--workspace", str(self.workspace), "--prompt", "p", "--scripted-text", "x", "--stream", "--dry-run")
        self.assertEqual(code, 0, out)
        self.assertIn("stream=on", out)

    def test_the_session_file_gains_no_delta_records(self):
        script = self.script([{"text": "hello streamed world", "stream": ["hello ", "streamed ", "world"]}])
        session = self.workspace / "S"
        code, _, _ = self.cli(
            "run", "--workspace", str(self.workspace), "--session-dir", str(session), "--prompt", "p",
            "--script", str(script), "--stream", "--allow-tool", "LS",
        )
        self.assertEqual(code, 0)
        files = list(session.glob("*.jsonl"))
        self.assertEqual(len(files), 1)
        body = files[0].read_text(encoding="utf-8")
        self.assertNotIn("stream_delta", body)
        self.assertIn("hello streamed world", body, "the record holds the whole turn, not the chunks")


def _store(directory: str):
    from sessions import SessionStore

    return SessionStore(Path(directory), session_id="probe")


def _records(directory: str) -> list[dict]:
    path = next(Path(directory).glob("*.jsonl"))
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _strip(records: list[dict]) -> list[dict]:
    """Drop the fields two runs cannot share (ids, timestamps, durations)."""
    volatile = {"session_id", "ts", "timestamp", "created_at", "duration_ms", "run_id", "message_id", "id", "uuid"}

    def scrub(value):
        if isinstance(value, dict):
            return {key: scrub(item) for key, item in sorted(value.items()) if key not in volatile}
        if isinstance(value, list):
            return [scrub(item) for item in value]
        return value

    return [scrub(record) for record in records]


class PresentationIsNotInheritedTests(unittest.TestCase):
    """``stream`` is a property of the operator's terminal, not of a delegated turn."""

    def test_a_subagent_on_a_non_streaming_provider_runs_normally(self):
        # The child run must not inherit stream=True: if it did, constructing it against
        # a provider that cannot stream would be a configuration error inside the parent,
        # and a presentation choice would have broken a delegation.
        child = ScriptedProvider([{"text": "child answer"}])
        child.streams = False

        def refuse_streaming(request):  # a delegated run must not inherit the terminal
            raise AssertionError("a subagent must not stream")

        child.stream = refuse_streaming
        runtime = AgentRuntime(
            provider=ScriptedProvider(
                [{"tool": {"name": "Task", "input": {"agent": "quiet", "prompt": "look"}, "id": "t1"}}, {"text": "wrapping up"}]
            ),
            config=RuntimeConfig(stream=True, max_turns=4, allowed_tools=("Task",), max_tool_calls=None),
            agents=AgentRegistry([AgentDefinition(name="quiet", description="quiet", provider="quiet", tools=("LS",))]),
            providers={"quiet": child},
        )
        events = list(runtime.run("go"))
        result = events[-1]
        self.assertEqual(result.subtype, "success", result.errors)
        self.assertEqual(len(child.requests), 1, "the child ran exactly one turn")
        self.assertEqual(child.cursor, 1, "the child consumed its script through generate()")
        # The parent's text turn streamed; the child's never tried to, even though the
        # child's provider is a ScriptedProvider that *can* stream.
        self.assertEqual(deltas(events), ["wrapping up"])

    def test_parent_deltas_are_labelled_with_their_turn(self):
        provider = ScriptedProvider(
            [
                ScriptedTurn.streamed("parent says hi", ["parent ", "says ", "hi"], stop_reason="tool_use"),
                {"text": "end"},
            ]
        )
        events = list(
            AgentRuntime(
                provider=provider,
                config=RuntimeConfig(stream=True, max_turns=4, allowed_tools=("Task",), max_tool_calls=None),
                agents=AgentRegistry([AgentDefinition(name="quiet", description="q", tools=("LS",))]),
            ).run("go")
        )
        shown = [event for event in events if isinstance(event, StreamDelta)]
        self.assertEqual([event.turn_index for event in shown], [1, 1, 1])
        self.assertEqual({event.provider for event in shown}, {"scripted"})


class SdkParityTests(unittest.TestCase):
    def test_stream_run_yields_delta_dicts_and_the_same_result(self):
        from sdk import RunOptions, run as sdk_run, stream_run

        turns = [{"text": "a b c", "stream": ["a ", "b ", "c"]}]
        dicts = list(stream_run(RunOptions(prompt="go", provider="scripted", scripted_turns=turns, stream=True)))
        self.assertEqual([item["type"] for item in dicts[:4]], ["system", "stream_delta", "stream_delta", "stream_delta"])
        self.assertEqual("".join(item["text"] for item in dicts if item["type"] == "stream_delta"), "a b c")
        self.assertEqual(dicts[-1]["type"], "result")

        report = sdk_run(RunOptions(prompt="go", provider="scripted", scripted_turns=turns, stream=True))
        quiet = sdk_run(RunOptions(prompt="go", provider="scripted", scripted_turns=turns))
        self.assertEqual(report.subtype, quiet.subtype)
        self.assertEqual(report.num_turns, quiet.num_turns)
        self.assertEqual(report.total_usage, quiet.total_usage)
        self.assertEqual(report.total_cost_usd, quiet.total_cost_usd)
        self.assertEqual(report.num_turns, quiet.num_turns)
        self.assertGreater(len(report.events), len(quiet.events), "only the event list differs")

    def test_a_bad_stream_value_is_rejected_before_any_turn_runs(self):
        # The config validates `stream` like every other ceiling, so an embedder passing
        # a truthy string gets an error instead of a run that silently streams.
        from sdk import RunOptions, stream_run

        with self.assertRaises(ValueError):
            list(stream_run(RunOptions(prompt="go", provider="scripted", stream="yes", scripted_turns=[{"text": "x"}])))


if __name__ == "__main__":

    unittest.main()
