"""Span tree, cost attribute timing, and content redaction.

The timing invariant is the expensive one: OpenTelemetry silently discards an
attribute written after ``end()``, so a runtime that records usage after closing
the generation span produces traces with no cost in them and no error anywhere.
"""
from __future__ import annotations

import json
import unittest

import support  # noqa: F401
from support import RuntimeTestCase, text_turn, tool_turn

from tracing import FORBIDDEN_ATTRIBUTE_KEYS, SpanHandle, Tracer, otel_available


class SpanShapeTests(RuntimeTestCase):
    def test_hierarchy_is_run_turn_then_work(self):
        from agents import AgentRegistry, explorer_agent

        workspace = self.workspace({"a.txt": "alpha\n"})
        provider = self.provider(
            [tool_turn("Read", {"path": "a.txt"}), tool_turn("Task", {"agent": "explorer", "prompt": "look"}), text_turn("done")]
        )
        child = self.provider([tool_turn("Read", {"path": "a.txt"}), text_turn("sub answer")])
        report = self.drive(
            self.runtime(
                provider=provider,
                workspace=workspace,
                providers={"e": child},
                agents=AgentRegistry([explorer_agent().override(provider="e")]),
            )
        )
        names = list(self.tracer.names())
        self.assertEqual(names[0], "generation")  # spans are recorded as they end
        run = self.tracer.find("run")
        self.assertIsNotNone(run)
        children = [self.tracer.spans[i].name for i in range(len(self.tracer.spans))]
        self.assertIn("turn[1]", children)
        self.assertIn("turn[2]", children)
        self.assertIn("generation", children)
        self.assertIn("tool:Read", children)
        self.assertIn("subagent:explorer", children)
        self.assertEqual(run.parent_span_id, "", "the run span is the root")
        turn = self.tracer.find("turn[1]")
        self.assertEqual(turn.parent_span_id, run.span_id)
        generation = next(record for record in self.tracer.spans if record.name == "generation")
        self.assertEqual(generation.parent_span_id, turn.span_id)
        self.assertEqual(run.attributes["turn.count"], 3)
        self.assertTrue(report.ok)

    def test_the_child_run_hangs_off_its_delegation_span(self):
        provider = self.provider([tool_turn("Task", {"agent": "explorer", "prompt": "look"}), text_turn("done")])
        self.drive(self.runtime(provider=provider))
        delegation = self.tracer.find("subagent:explorer")
        nested = [record for record in self.tracer.spans if record.name == "run"]
        self.assertEqual(len(nested), 2, "the subagent contributes its own run span")
        child = next(record for record in nested if record.span_id != self.tracer.find("run").span_id)
        self.assertEqual(child.parent_span_id, delegation.span_id)

    def test_span_names_are_rendered_for_humans(self):
        provider = self.provider([tool_turn("Read", {"path": "x"}), text_turn("done")])
        report = self.drive(self.runtime(provider=provider))
        tree = report.trace
        self.assertIn("run (", tree)
        self.assertIn("turn[1]", tree)
        self.assertIn("tool:Read", tree)

    def test_refused_calls_still_appear_as_tool_spans(self):
        provider = self.provider([tool_turn("Write", {"path": "x.txt", "content": "y"}), text_turn("ok")])
        self.drive(self.runtime(provider=provider))
        span = self.tracer.find("tool:Write")
        self.assertIsNotNone(span)
        self.assertTrue(span.attributes["tool.denied"])
        self.assertTrue(span.attributes["tool.is_error"])
        self.assertEqual(span.attributes["permission.source"], "mode")

    def test_collect_false_keeps_no_records(self):
        tracer = Tracer(collect=False)
        with tracer.span("run") as run:
            run.set_attribute("a", 1)
        self.assertEqual(tracer.records(), ())


class TimingTests(RuntimeTestCase):
    def test_generation_usage_and_cost_are_on_the_span(self):
        provider = self.provider([tool_turn("Read", {"path": "x"}, usage={"input_tokens": 1000, "output_tokens": 40})])
        self.drive(self.runtime(provider=provider))
        generation = self.tracer.find("generation")
        self.assertEqual(generation.attributes["usage.input_tokens"], 1000)
        self.assertEqual(generation.attributes["usage.output_tokens"], 40)
        self.assertAlmostEqual(generation.attributes["cost.usd"], 1000 / 1e6 * 3.0 + 40 / 1e6 * 15.0)
        self.assertFalse(generation.attributes["pricing.estimated"])

    def test_no_attribute_anywhere_was_dropped_because_a_span_had_ended(self):
        provider = self.provider([tool_turn("Read", {"path": "x"}), text_turn("done")])
        workspace = self.workspace({"x": "y"})
        self.drive(self.runtime(provider=provider, workspace=workspace, compaction_threshold_tokens=600))
        dropped = self.tracer.total_dropped_attributes()
        self.assertEqual(dropped, (), f"attributes written after end() are lost: {dropped}")
        for record in self.tracer.records():
            with self.subTest(span=record.name):
                self.assertEqual(record.dropped_after_end, [])

    def test_the_run_span_carries_the_priced_total(self):
        workspace = self.workspace({"x": "y"})
        provider = self.provider(
            [
                tool_turn("Read", {"path": "x"}, usage={"input_tokens": 1_000_000, "output_tokens": 10}),
                text_turn("done"),
            ]
        )
        report = self.drive(self.runtime(provider=provider, workspace=workspace))
        run = self.tracer.find("run")
        self.assertAlmostEqual(run.attributes["cost.usd"], 3.00015)
        self.assertEqual(run.attributes["usage.total_tokens"], 1_000_010)
        self.assertEqual(run.attributes["result.subtype"], "success")
        self.assertEqual(run.attributes["tool.call_count"], 1)
        self.assertEqual(run.attributes["denial.count"], 0)
        self.assertTrue(report.ok)

    def test_the_subagent_cost_is_visible_on_the_delegation_span(self):
        parent = self.provider([tool_turn("Task", {"agent": "explorer", "prompt": "look", "usage": None})])
        child = self.provider([tool_turn("Read", {"path": "a"}, usage={"input_tokens": 500_000})], on_exhausted="stop")
        from agents import AgentRegistry, explorer_agent

        runtime = self.runtime(
            provider=parent,
            providers={"e": child},
            agents=AgentRegistry([explorer_agent().override(provider="e", max_turns=2)]),
        )
        self.drive(runtime, "delegate")
        delegation = self.tracer.find("subagent:explorer")
        self.assertGreater(delegation.attributes["subagent.cost_usd"], 0.0)
        self.assertGreater(self.tracer.find("run").attributes["cost.usd"], delegation.attributes["subagent.cost_usd"] - 1e-9)

    def test_the_wrapper_refuses_late_writes_rather_than_losing_them_silently(self):
        tracer = Tracer()
        handle = tracer.start_span("work")
        self.assertTrue(handle.set_attribute("a", 1))
        handle.end()
        self.assertFalse(handle.set_attribute("b", 2))
        record = tracer.find("work")
        self.assertEqual(record.attributes, {"a": 1})
        self.assertEqual(record.dropped_after_end, ["b"])


class RedactionTests(RuntimeTestCase):
    def test_prompt_and_tool_output_never_reach_a_span(self):
        secret_prompt = "inspect THE-PROMPT-SECRET please"
        workspace = self.workspace({"notes.txt": "THE-OUTPUT-SECRET\n"})
        provider = self.provider([tool_turn("Read", {"path": "notes.txt"}), text_turn("done")])
        runtime = self.runtime(provider=provider, workspace=workspace)
        runtime.run_collect(secret_prompt)
        dump = json.dumps([record.attributes for record in self.tracer.records()], ensure_ascii=False)
        self.assertNotIn("THE-PROMPT-SECRET", dump)
        self.assertNotIn("THE-OUTPUT-SECRET", dump)
        for record in self.tracer.records():
            self.assertNotIn("prompt", {key.lower() for key in record.attributes})
            self.assertNotIn("tool.result", {key.lower() for key in record.attributes})

    def test_content_bearing_attribute_keys_are_refused(self):
        tracer = Tracer()
        with tracer.span("work") as handle:
            for key in sorted(FORBIDDEN_ATTRIBUTE_KEYS):
                self.assertFalse(handle.set_attribute(key, "small value"), key)
            self.assertEqual(len(handle.rejected), len(FORBIDDEN_ATTRIBUTE_KEYS))
        record = tracer.find("work")
        self.assertEqual(record.attributes, {})
        self.assertTrue(all("conversation content" in item for item in record.rejected_attributes))

    def test_long_strings_are_refused_even_under_an_ordinary_key(self):
        tracer = Tracer()
        with tracer.span("work") as handle:
            self.assertFalse(handle.set_attribute("note", "x" * 500))
            self.assertTrue(handle.set_attribute("note", "x" * 50))
        self.assertEqual(tracer.find("work").attributes["note"], "x" * 50)

    def test_only_scalar_values_are_accepted(self):
        tracer = Tracer()
        with tracer.span("work") as handle:
            self.assertFalse(handle.set_attribute("nested", {"a": 1}))
            self.assertFalse(handle.set_attribute("blob", b"bytes"))
            self.assertFalse(handle.set_attribute("mixed", [1, "two"]))
            self.assertFalse(handle.set_attribute("huge_list", ["x"] * 33))
            self.assertTrue(handle.set_attribute("flag", True))
            self.assertTrue(handle.set_attribute("count", 3))
            self.assertTrue(handle.set_attribute("ratio", 0.5))
            self.assertTrue(handle.set_attribute("names", ["Read", "Write"]))
        record = tracer.find("work")
        self.assertEqual(record.attributes, {"flag": True, "count": 3, "ratio": 0.5, "names": ["Read", "Write"]})

    def test_an_over_long_error_message_is_clipped_not_rejected(self):
        tracer = Tracer()
        handle = tracer.start_span("work")
        handle.record_error("E" * 5000)
        self.assertEqual(len(handle.error), 200)
        handle.end()
        self.assertEqual(tracer.find("work").error, "E" * 200)


class OpenTelemetryIntegrationTests(RuntimeTestCase):
    """Proof that the ordering rule matters, against the real SDK."""

    def setUp(self) -> None:
        super().setUp()
        if not _sdk_available():
            self.skipTest("opentelemetry-sdk is not installed (it is the optional extra)")
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

        self.exporter = InMemorySpanExporter()
        # Deliberately not "self.provider": the base class uses that name for the
        # scripted model provider.
        self.otel_provider = TracerProvider()
        self.otel_provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.addCleanup(self.otel_provider.shutdown)
        self.otel_tracer = self.otel_provider.get_tracer("northstar-test")

    def finished(self) -> dict:
        """Latest span per name; use spans() when a name repeats per turn."""
        return {span.name: span for span in self.exporter.get_finished_spans()}

    def spans(self, name: str) -> list:
        return [span for span in self.exporter.get_finished_spans() if span.name == name]

    def test_opentelemetry_really_does_discard_attributes_written_after_end(self):
        span = self.otel_tracer.start_span("late-writer")
        span.set_attribute("before", 1)
        span.end()
        span.set_attribute("after", 2)
        recorded = self.finished()["late-writer"]
        self.assertEqual(dict(recorded.attributes), {"before": 1})
        self.assertNotIn("after", recorded.attributes, "this is the silent-drop behaviour being designed around")

    def test_a_real_sdk_pipeline_receives_the_run_with_its_cost(self):
        workspace = self.workspace({"x": "y"})
        runtime = self.runtime(
            provider=self.provider(
                [
                    tool_turn("Read", {"path": "x"}, usage={"input_tokens": 2_000_000, "output_tokens": 100}),
                    text_turn("done"),
                ]
            ),
            workspace=workspace,
            tracer=Tracer(otel_tracer=self.otel_tracer),
        )
        self.drive(runtime, "read")
        spans = self.finished()
        for name in ("run", "turn[1]", "generation", "tool:Read"):
            self.assertIn(name, spans)
        # Two turns, so two generation spans: the priced one is the first.
        generation = self.spans("generation")[0]
        self.assertAlmostEqual(generation.attributes["cost.usd"], 2_000_000 / 1e6 * 3.0 + 100 / 1e6 * 15.0)
        self.assertEqual(generation.attributes["usage.input_tokens"], 2_000_000)
        self.assertEqual(spans["run"].attributes["result.subtype"], "success")
        self.assertEqual(spans["tool:Read"].attributes["tool.is_error"], False)
        self.assertEqual(spans["tool:Read"].parent.span_id, spans["turn[1]"].context.span_id)

    def test_the_exported_trace_contains_no_conversation_text(self):
        workspace = self.workspace({"notes.txt": "THE-OUTPUT-SECRET\n"})
        runtime = self.runtime(
            provider=self.provider([tool_turn("Read", {"path": "notes.txt"}), text_turn("done")]),
            workspace=workspace,
            tracer=Tracer(otel_tracer=self.otel_tracer),
        )
        runtime.run_collect("inspect THE-PROMPT-SECRET")
        dump = json.dumps({name: dict(span.attributes) for name, span in self.finished().items()}, ensure_ascii=False)
        self.assertNotIn("THE-PROMPT-SECRET", dump)
        self.assertNotIn("THE-OUTPUT-SECRET", dump)

    def test_otel_presence_is_reported(self):
        self.assertTrue(otel_available())


def _sdk_available() -> bool:
    try:
        import opentelemetry.sdk  # noqa: F401
    except ImportError:
        return False
    return True


class TracerUnitTests(unittest.TestCase):
    def test_spans_track_open_handles_and_reset(self):
        tracer = Tracer()
        handle = tracer.start_span("work")
        self.assertEqual(tracer.open_spans, [handle])
        handle.end()
        self.assertEqual(tracer.open_spans, [])
        tracer.reset()
        self.assertEqual(tracer.records(), ())

    def test_child_spans_record_error_and_repropagate(self):
        tracer = Tracer()
        with self.assertRaises(RuntimeError):
            with tracer.span("run") as run:
                with run.child("work"):
                    raise RuntimeError("nope")
        self.assertIn("nope", tracer.find("work").error)
        self.assertIn("nope", tracer.find("run").error)

    def test_usage_helper_accepts_a_mapping(self):
        tracer = Tracer()
        with tracer.span("generation") as handle:
            handle.record_usage({"input_tokens": 5, "output_tokens": 2}, 0.5)
            self.assertFalse(handle.usage_recorded())
        record = tracer.find("generation")
        self.assertEqual(record.attributes["usage.input_tokens"], 5)
        self.assertEqual(record.attributes["cost.usd"], 0.5)


if __name__ == "__main__":
    unittest.main()
