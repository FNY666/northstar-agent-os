"""Tests for monitor_01 (OTel spans)."""
import importlib.util, sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


ot = _load("monitor_01")


def test_span_creation():
    t = ot.Tracer("svc")
    s = ot.Span(name="op", context=ot.new_span_context())
    assert s.status == "unset"
    assert len(s.context.trace_id) == 32


def test_parent_child():
    t = ot.Tracer("svc")
    root = t.start_span("root")
    child = t.start_span("child", parent=root.context)
    assert child.context.trace_id == root.context.trace_id
    assert child.context.parent_span_id == root.context.span_id


def test_events_and_status():
    t = ot.Tracer("svc")
    s = t.start_span("op")
    s.set_attribute("k", "v")
    s.add_event("e1")
    s.set_status("error")
    s.end()
    assert s.attributes["k"] == "v"
    assert len(s.events) == 1
    assert s.duration_ns is not None
    assert len(t.export_json()) == 1


def test_bad_context_rejected():
    import pytest

    with pytest.raises(ot.OTelError):
        ot.SpanContext(trace_id="bad", span_id="00" * 8)


def test_stdlib_only():
    assert ot.stdlib_only() is True
