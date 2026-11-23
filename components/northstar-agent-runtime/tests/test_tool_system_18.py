"""Tests for tool_system_18."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_18")
import pytest

def _ac():
    now = {"t": 0.0}
    ac = m.AnalyticsCollector(clock=lambda: now["t"])
    return ac, now

def test_stats_aggregates():
    ac, _ = _ac()
    for i in range(10):
        ac.record("search", latency_ms=float(i * 10), success=i != 3)
    st = ac.stats("search")
    assert st.count == 10
    assert st.errors == 1
    assert abs(st.error_rate - 0.1) < 1e-9
    assert st.p50_ms == 50.0
    assert st.p95_ms == 90.0
    assert abs(st.mean_ms - 45.0) < 1e-9

def test_top_tools():
    ac, _ = _ac()
    ac.record("b", latency_ms=1.0, success=True)
    ac.record("a", latency_ms=1.0, success=True)
    ac.record("a", latency_ms=2.0, success=False)
    assert ac.top_tools(2) == [("a", 2), ("b", 1)]

def test_no_events():
    ac, _ = _ac()
    with pytest.raises(m.ToolSystem18Error):
        ac.stats("nope")

def test_window_prune():
    now = {"t": 0.0}
    ac = m.AnalyticsCollector(clock=lambda: now["t"], window_seconds=10.0)
    ac.record("search", latency_ms=1.0, success=True)
    now["t"] = 11.0
    assert ac.top_tools(1) == []
    with pytest.raises(m.ToolSystem18Error):
        ac.stats("search")

def test_reset():
    ac, _ = _ac()
    ac.record("search", latency_ms=1.0, success=True)
    ac.reset()
    assert ac.top_tools(1) == []

def test_stdlib():
    assert m.stdlib_only() is True
