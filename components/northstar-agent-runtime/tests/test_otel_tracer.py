"""Targeted tests for otel_tracer (OpenTelemetry-style trace bookkeeping)."""

import threading
import unittest

import otel_tracer
from otel_tracer import (
    OTELTracer,
    InvalidTraceparentError,
    OTEL_TRACER_VERSION,
    SCHEMA_PIN,
    Span,
    SpanClosedError,
    SpanRecord,
    TraceContext,
    TracerError,
    UnknownSpanError,
    otel_tracer_audit_event,
)


def _factory_maker():
    counter = {"n": 0}

    def factory(num_bytes: int) -> str:
        counter["n"] += 1
        return f"{counter['n']:0{num_bytes * 2}x}"

    return factory


def _tracer(service="svc-test"):
    return OTELTracer(service, id_factory=_factory_maker())


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(OTEL_TRACER_VERSION, "otel-tracer.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.otel-tracer.v1")


class TestStartSpan(unittest.TestCase):
    def test_root_span_shape(self):
        t = _tracer()
        s = t.start_span("root", seq=1)
        self.assertIsInstance(s, Span)
        self.assertEqual(len(s.trace_id), 32)
        self.assertEqual(len(s.span_id), 16)
        self.assertIsNone(s.parent_span_id)
        self.assertEqual(s.kind, "internal")
        self.assertTrue(s.digest.startswith("sha256:"))

    def test_child_inherits_trace_id(self):
        t = _tracer()
        root = t.start_span("root", seq=1)
        child = t.start_span("child", seq=2, parent=root)
        self.assertEqual(child.trace_id, root.trace_id)
        self.assertEqual(child.parent_span_id, root.span_id)
        self.assertNotEqual(child.span_id, root.span_id)

    def test_kinds(self):
        t = _tracer()
        for kind in ("internal", "server", "client", "producer", "consumer"):
            s = t.start_span("x", seq=1, kind=kind)
            self.assertEqual(s.kind, kind)

    def test_bad_kind_refused(self):
        t = _tracer()
        with self.assertRaises(TracerError):
            t.start_span("x", seq=1, kind="worker")

    def test_empty_name_refused(self):
        t = _tracer()
        for bad in ("", None, 5, True):
            with self.assertRaises(TracerError):
                t.start_span(bad, seq=1)

    def test_bad_seq_refused(self):
        t = _tracer()
        for bad in (-1, True, "1", 1.0):
            with self.assertRaises(TracerError):
                t.start_span("x", seq=bad)

    def test_explicit_trace_id(self):
        t = _tracer()
        s = t.start_span("root", seq=1, trace_id="a" * 32)
        self.assertEqual(s.trace_id, "a" * 32)

    def test_bad_trace_id_refused(self):
        t = _tracer()
        with self.assertRaises(TracerError):
            t.start_span("root", seq=1, trace_id="zzzz")
        with self.assertRaises(TracerError):
            t.start_span("root", seq=1, trace_id="0" * 32)

    def test_bad_parent_refused(self):
        t = _tracer()
        with self.assertRaises(TracerError):
            t.start_span("x", seq=1, parent="not-a-span")

    def test_parent_after_end_refused(self):
        t = _tracer()
        root = t.start_span("root", seq=1)
        t.end_span(root.span_id, seq=2)
        with self.assertRaises(SpanClosedError):
            t.start_span("child", seq=3, parent=root)

    def test_attributes_merged(self):
        t = _tracer()
        s = t.start_span("x", seq=1, attributes={"a": 1})
        upd = t.set_attributes(s.span_id, {"b": "two"}, seq=2)
        self.assertEqual(upd.attributes, {"a": 1, "b": "two"})

    def test_attributes_bad_value_refused(self):
        t = _tracer()
        s = t.start_span("x", seq=1)
        for bad in ({"k": True}, {"k": None}, {"k": float("nan")}):
            with self.assertRaises(TracerError):
                t.set_attributes(s.span_id, bad, seq=2)

    def test_events(self):
        t = _tracer()
        s = t.start_span("x", seq=1)
        upd = t.add_event(s.span_id, "retry", seq=2, attributes={"n": 1})
        self.assertEqual(len(upd.events), 1)
        self.assertEqual(upd.events[0].name, "retry")
        self.assertEqual(upd.events[0].seq, 2)


class TestEndSpan(unittest.TestCase):
    def test_end_freezes_record(self):
        t = _tracer()
        s = t.start_span("x", seq=3)
        rec = t.end_span(s.span_id, seq=8)
        self.assertIsInstance(rec, SpanRecord)
        self.assertEqual(rec.duration_seqs, 5)
        self.assertEqual(rec.status, "unset")
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_end_with_status(self):
        t = _tracer()
        s = t.start_span("x", seq=1)
        rec = t.end_span(s.span_id, seq=2, status="error", status_description="boom")
        self.assertEqual(rec.status, "error")
        self.assertEqual(rec.status_description, "boom")

    def test_end_unknown_span(self):
        t = _tracer()
        with self.assertRaises(UnknownSpanError):
            t.end_span("f" * 16, seq=1)

    def test_double_end_refused(self):
        t = _tracer()
        s = t.start_span("x", seq=1)
        t.end_span(s.span_id, seq=2)
        with self.assertRaises(SpanClosedError):
            t.end_span(s.span_id, seq=3)

    def test_end_before_start_refused(self):
        t = _tracer()
        s = t.start_span("x", seq=5)
        with self.assertRaises(TracerError):
            t.end_span(s.span_id, seq=4)

    def test_bad_status_refused(self):
        t = _tracer()
        s = t.start_span("x", seq=1)
        with self.assertRaises(TracerError):
            t.end_span(s.span_id, seq=2, status="failed")

    def test_views(self):
        t = _tracer()
        a = t.start_span("a", seq=1)
        b = t.start_span("b", seq=2)
        self.assertEqual(set(t.in_flight()), {a.span_id, b.span_id})
        t.end_span(a.span_id, seq=3)
        self.assertEqual(t.in_flight(), (b.span_id,))
        self.assertEqual(len(t.completed()), 1)
        self.assertEqual(t.completed()[0].span_id, a.span_id)

    def test_trace_view_ordered(self):
        t = _tracer()
        r1 = t.start_span("r1", seq=2)
        r2 = t.start_span("r2", seq=1, parent=r1)
        t.end_span(r2.span_id, seq=3)
        t.end_span(r1.span_id, seq=4)
        trace = t.trace(r1.trace_id)
        # Ordered by start seq: r2 (seq 1) before r1 (seq 2).
        self.assertEqual([r.span_id for r in trace], [r2.span_id, r1.span_id])

    def test_view_ended_span_refused(self):
        t = _tracer()
        s = t.start_span("x", seq=1)
        t.end_span(s.span_id, seq=2)
        with self.assertRaises(SpanClosedError):
            t.span(s.span_id)

    def test_set_attributes_after_end_refused(self):
        t = _tracer()
        s = t.start_span("x", seq=1)
        t.end_span(s.span_id, seq=2)
        with self.assertRaises(SpanClosedError):
            t.set_attributes(s.span_id, {"a": 1}, seq=3)


class TestPropagation(unittest.TestCase):
    def test_propagate_shape(self):
        t = _tracer()
        s = t.start_span("x", seq=1)
        ctx = t.propagate(s.span_id, seq=2)
        self.assertIsInstance(ctx, TraceContext)
        self.assertEqual(
            ctx.traceparent, f"00-{s.trace_id}-{s.span_id}-01"
        )
        self.assertTrue(ctx.sampled)

    def test_inject(self):
        t = _tracer()
        s = t.start_span("x", seq=1)
        out = t.inject({"x-req": "1"}, s.span_id, seq=2)
        self.assertEqual(out["x-req"], "1")
        self.assertEqual(out["traceparent"], f"00-{s.trace_id}-{s.span_id}-01")

    def test_inject_bad_headers(self):
        t = _tracer()
        s = t.start_span("x", seq=1)
        with self.assertRaises(TracerError):
            t.inject("nope", s.span_id, seq=2)
        with self.assertRaises(TracerError):
            t.inject({"k": 5}, s.span_id, seq=2)

    def test_extract_roundtrip(self):
        t = _tracer()
        s = t.start_span("x", seq=1)
        headers = t.inject({}, s.span_id, seq=2)
        ctx = t.extract(headers, seq=3)
        self.assertEqual(ctx.trace_id, s.trace_id)
        self.assertEqual(ctx.span_id, s.span_id)
        self.assertTrue(ctx.sampled)

    def test_extract_sampled_false(self):
        t = _tracer()
        ctx = t.extract({"traceparent": f"00-{'a'*32}-{'b'*16}-00"}, seq=1)
        self.assertFalse(ctx.sampled)

    def test_extract_bad_values(self):
        t = _tracer()
        bads = [
            {},
            {"traceparent": "00-abc-01"},
            {"traceparent": "01-" + "a" * 32 + "-" + "b" * 16 + "-01"},
            {"traceparent": "00-" + "zz" * 16 + "-" + "b" * 16 + "-01"},
            {"traceparent": "00-" + "a" * 32 + "-" + "b" * 16 + "-0"},
            {"traceparent": "00-" + "0" * 32 + "-" + "b" * 16 + "-01"},
        ]
        for headers in bads:
            with self.assertRaises(InvalidTraceparentError):
                t.extract(headers, seq=1)

    def test_continue_remote_trace(self):
        t = _tracer()
        s = t.start_span("x", seq=1)
        headers = t.inject({}, s.span_id, seq=2)
        other = OTELTracer("svc-b", id_factory=_factory_maker())
        ctx = other.extract(headers, seq=3)
        cont = other.start_span_from_context(ctx, "handler", seq=4, kind="server")
        self.assertEqual(cont.trace_id, s.trace_id)
        self.assertIsNone(cont.parent_span_id)

    def test_continue_bad_context(self):
        t = _tracer()
        with self.assertRaises(TracerError):
            t.start_span_from_context("nope", "x", seq=1)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        rec = otel_tracer_audit_event("span-started", 5, span_id="x")
        self.assertEqual(rec["event"], "span-started")
        self.assertEqual(rec["audit_seq"], 5)
        self.assertEqual(rec["schema"], SCHEMA_PIN)
        self.assertEqual(rec["span_id"], "x")

    def test_bad_kind_refused(self):
        with self.assertRaises(TracerError):
            otel_tracer_audit_event("nope", 1)

    def test_bad_seq_refused(self):
        with self.assertRaises(TracerError):
            otel_tracer_audit_event("span-started", -1)


class TestRecords(unittest.TestCase):
    def test_span_record_as_dict(self):
        t = _tracer()
        s = t.start_span("x", seq=1)
        rec = t.end_span(s.span_id, seq=2)
        d = rec.as_dict()
        self.assertEqual(d["version"], OTEL_TRACER_VERSION)
        self.assertEqual(d["duration_seqs"], 1)
        d2 = s.as_dict()
        self.assertEqual(d2["service"], "svc-test")

    def test_frozen_records(self):
        t = _tracer()
        s = t.start_span("x", seq=1)
        with self.assertRaises(AttributeError):
            s.name = "y"  # type: ignore[misc]


class TestConcurrency(unittest.TestCase):
    def test_concurrent_starts(self):
        t = _tracer()
        ids = []

        def worker():
            for i in range(20):
                ids.append(t.start_span("w", seq=i).span_id)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(len(set(ids)), 80)


class TestMain(unittest.TestCase):
    def test_main_selfcheck(self):
        otel_tracer.main()


class TestStdlibOnly(unittest.TestCase):
    def test_imports(self):
        import ast
        from pathlib import Path

        src = Path(otel_tracer.__file__).read_text()
        tree = ast.parse(src)
        allowed = {"hashlib", "json", "secrets", "threading", "dataclasses",
                   "typing", "__future__"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.assertIn(node.module.split(".")[0], allowed)


if __name__ == "__main__":
    unittest.main()
