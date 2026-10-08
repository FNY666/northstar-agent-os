"""Tests for monitor_02 (Prometheus metrics)."""
import importlib.util, sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


pm = _load("monitor_02")


def test_counter():
    c = pm.Counter("c1")
    c.inc()
    c.inc(4, labels={"a": "b"})
    assert c.get() == 1.0
    assert c.get({"a": "b"}) == 4.0


def test_counter_no_decrease():
    import pytest

    c = pm.Counter("c2")
    with pytest.raises(pm.MetricsError):
        c.inc(-1)


def test_gauge():
    g = pm.Gauge("g1")
    g.set(10)
    g.inc(2)
    g.dec(5)
    assert g.get() == 7.0


def test_histogram_and_render():
    reg = pm.Registry()
    h = pm.Histogram("h1")
    reg.register(h)
    h.observe(0.01)
    h.observe(99.0)
    assert h.count() == 2
    out = reg.render()
    assert "h1_bucket" in out and "h1_sum" in out and "h1_count" in out


def test_registry_unknown():
    import pytest

    reg = pm.Registry()
    with pytest.raises(pm.MetricsError):
        reg.get("nope")


def test_stdlib_only():
    assert pm.stdlib_only() is True
