import unittest

try:
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    HAS_SDK = True
except ImportError:  # pragma: no cover - sdk is an optional extra
    HAS_SDK = False

from agents import AgentRegistry, evaluator_agent
from helpers import make_runtime
from providers.scripted import ScriptedProvider
from tracing import RuntimeTracer, TRACER_NAME

SECRET_PROMPT = "SECRET-PROMPT-MARKER-abc123"
SECRET_FILE_CONTENT = "SECRET-FILE-CONTENT-xyz789"


def make_exporter():
    return InMemorySpanExporter()


def trace_runtime(runtime, exporter):
    """Point the runtime's tracer at an in-memory exporter (no global state)."""
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    runtime.tracer = RuntimeTracer(tracer=provider.get_tracer(TRACER_NAME))
    return runtime


def children_of(exporter, span):
    return [s for s in exporter.get_finished_spans() if s.parent and s.parent.span_id == span.context.span_id]


@unittest.skipUnless(HAS_SDK, "opentelemetry-sdk extra not installed")
class SpanHierarchyTests(unittest.TestCase):
    def test_run_turn_generation_tool_subagent_hierarchy(self):
        exporter = make_exporter()
        child = ScriptedProvider(["child done"])
        runtime, _ = make_runtime(
            [
                {"text": "delegating", "tools": [{"name": "Task", "input": {"agent": "evaluator", "prompt": "p"}}]},
                {"text": "reading", "tools": [{"name": "Read", "input": {"path": "missing.txt"}}]},
                "done",
            ],
            subagents=AgentRegistry([evaluator_agent(provider=child)]),
        )
        trace_runtime(runtime, exporter)
        runtime.run("go")
        spans = exporter.get_finished_spans()

        # one parent-level tree: run → turn[1] → {generation, tool:Task, tool:Read}
        run_spans = [s for s in spans if s.name == "run" and s.attributes.get("agent.depth") == 0]
        self.assertEqual(len(run_spans), 1)
        run_span = run_spans[0]
        children = children_of(exporter, run_span)
        self.assertIn("turn[1]", [c.name for c in children])
        turn1 = next(c for c in children if c.name == "turn[1]")
        turn_children = children_of(exporter, turn1)
        names = {c.name for c in turn_children}
        self.assertIn("generation", names)
        self.assertIn("tool:Task", names)
        # the Read happens on the second turn
        turn2 = next(c for c in children if c.name == "turn[2]")
        self.assertIn("tool:Read", {c.name for c in children_of(exporter, turn2)})

        # tool:Task → subagent:evaluator → child run(depth 1)
        task_span = next(c for c in turn_children if c.name == "tool:Task")
        sub_children = children_of(exporter, task_span)
        self.assertIn("subagent:evaluator", [c.name for c in sub_children])
        sub_span = next(c for c in sub_children if c.name == "subagent:evaluator")
        grand = children_of(exporter, sub_span)
        self.assertIn("run", [c.name for c in grand])
        child_run = next(c for c in grand if c.name == "run")
        self.assertEqual(child_run.attributes.get("agent.depth"), 1)

    def test_turn_spans_are_sequential(self):
        exporter = make_exporter()
        runtime, _ = make_runtime([
            {"text": "t1", "tools": [{"name": "Read", "input": {"path": "m1.txt"}}]},
            {"text": "t2", "tools": [{"name": "Read", "input": {"path": "m2.txt"}}]},
            "done",
        ])
        trace_runtime(runtime, exporter)
        runtime.run("go")
        turns = sorted(s.name for s in exporter.get_finished_spans() if s.name.startswith("turn["))
        self.assertIn("turn[1]", turns)
        self.assertIn("turn[2]", turns)
        self.assertIn("turn[3]", turns)


@unittest.skipUnless(HAS_SDK, "opentelemetry-sdk extra not installed")
class SpanUsageTimingTests(unittest.TestCase):
    def test_generation_span_carries_usage_and_cost(self):
        # Invariant: usage must be recorded BEFORE the span ends — the OTel SDK
        # silently drops set_attribute after end(), so a finished span carrying
        # these attributes proves they were set in time.
        exporter = make_exporter()
        runtime, _ = make_runtime(
            [
                {"text": "t", "tools": [{"name": "Read", "input": {"path": "m.txt"}}],
                 "usage": {"input_tokens": 1234, "output_tokens": 56,
                           "cache_read_input_tokens": 7, "cache_creation_input_tokens": 2}},
                "done",
            ],
        )
        trace_runtime(runtime, exporter)
        runtime.run("go")
        gen = [s for s in exporter.get_finished_spans() if s.name == "generation"][0]
        self.assertEqual(gen.attributes.get("gen.input_tokens"), 1234)
        self.assertEqual(gen.attributes.get("gen.output_tokens"), 56)
        self.assertEqual(gen.attributes.get("gen.cache_read_input_tokens"), 7)
        self.assertEqual(gen.attributes.get("gen.cache_creation_input_tokens"), 2)
        self.assertGreater(gen.attributes.get("gen.cost_usd"), 0.0)
        self.assertFalse(gen.attributes.get("gen.pricing_estimated"))

    def test_run_span_carries_result_and_session(self):
        exporter = make_exporter()
        runtime, _ = make_runtime(["done"])
        trace_runtime(runtime, exporter)
        report = runtime.run("go")
        run_span = next(s for s in exporter.get_finished_spans() if s.name == "run")
        self.assertEqual(run_span.attributes.get("agent.result"), "success")
        self.assertEqual(run_span.attributes.get("agent.session_id"), report.session_id)
        self.assertEqual(run_span.attributes.get("agent.model"), "claude-sonnet-4-5")

    def test_subagent_span_carries_cost_before_end(self):
        exporter = make_exporter()
        child = ScriptedProvider(["child done"])
        runtime, _ = make_runtime(
            [
                {"text": "delegating", "tools": [{"name": "Task", "input": {"agent": "evaluator", "prompt": "p"}}]},
                "done",
            ],
            subagents=AgentRegistry([evaluator_agent(provider=child)]),
        )
        trace_runtime(runtime, exporter)
        runtime.run("go")
        sub = next(s for s in exporter.get_finished_spans() if s.name == "subagent:evaluator")
        self.assertEqual(sub.attributes.get("subagent.type"), "evaluator")
        self.assertEqual(sub.attributes.get("subagent.result"), "success")
        self.assertGreater(sub.attributes.get("subagent.cost_usd"), 0.0)


@unittest.skipUnless(HAS_SDK, "opentelemetry-sdk extra not installed")
class SpanPrivacyTests(unittest.TestCase):
    def test_no_prompt_or_tool_output_text_in_attributes(self):
        exporter = make_exporter()
        workspace_file = "note.txt"
        runtime, _ = make_runtime(
            [
                {"text": "writing", "tools": [{"name": "Write", "input": {"path": workspace_file, "content": SECRET_FILE_CONTENT}}]},
                {"text": "reading", "tools": [{"name": "Read", "input": {"path": workspace_file}}]},
                "done",
            ],
            permission_mode="bypassPermissions",
        )
        trace_runtime(runtime, exporter)
        runtime.run(SECRET_PROMPT)
        for span in exporter.get_finished_spans():
            for key, value in span.attributes.items():
                if isinstance(value, str):
                    self.assertNotIn(SECRET_PROMPT, value, f"prompt text leaked into span attribute {key}")
                    self.assertNotIn(SECRET_FILE_CONTENT, value, f"tool output leaked into span attribute {key}")

    def test_tool_is_error_recorded_for_both_outcomes(self):
        exporter = make_exporter()
        runtime, _ = make_runtime(
            [
                {"text": "ops", "tools": [
                    {"name": "Read", "input": {"path": "missing.txt"}},
                    {"name": "Read", "input": {"path": "also-missing.txt"}},
                ]},
                "done",
            ],
        )
        trace_runtime(runtime, exporter)
        runtime.run("go")
        read_spans = [s for s in exporter.get_finished_spans() if s.name == "tool:Read"]
        self.assertEqual(len(read_spans), 2)
        self.assertTrue(all(s.attributes.get("tool.is_error") is True for s in read_spans))

    def test_tool_is_error_false_on_success(self):
        exporter = make_exporter()
        runtime, _ = make_runtime(
            [
                {"text": "writing", "tools": [{"name": "Write", "input": {"path": "a.txt", "content": "x"}}]},
                "done",
            ],
            permission_mode="bypassPermissions",
        )
        trace_runtime(runtime, exporter)
        runtime.run("go")
        write_span = next(s for s in exporter.get_finished_spans() if s.name == "tool:Write")
        self.assertIs(write_span.attributes.get("tool.is_error"), False)


class _FakeSpan:
    def __init__(self):
        self.attributes = {}

    def set_attribute(self, key, value):
        self.attributes[key] = value

    def record_exception(self, *a, **k):
        pass

    def set_status(self, *a, **k):
        pass

    def end(self):
        pass


class NoopTracerTests(unittest.TestCase):
    """The runtime must run fine when the tracer records nothing (API-only install)."""

    class _FakeTracer:
        def __init__(self):
            self.names = []

        def start_as_current_span(self, name, context=None):
            import contextlib

            fake = self

            @contextlib.contextmanager
            def cm():
                span = _FakeSpan()
                fake.names.append(name)
                yield span

            return cm()

    def test_run_completes_with_a_nonrecording_tracer(self):
        runtime, _ = make_runtime(["done"])
        runtime.tracer = RuntimeTracer(tracer=self._FakeTracer())
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "success")

    def test_default_tracer_name(self):
        self.assertEqual(TRACER_NAME, "northstar.agent-runtime")


if __name__ == "__main__":
    unittest.main()
