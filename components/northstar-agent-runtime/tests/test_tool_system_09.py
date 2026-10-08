"""Tests for tool_system_09."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_09")
import pytest

def test_memoizes():
    c = m.ToolCache(); n = {"c": 0}
    def f(): n["c"] += 1; return "v"
    assert m.cached_call(c, "t", {"a": 1}, f) == "v"
    assert m.cached_call(c, "t", {"a": 1}, f) == "v"
    assert n["c"] == 1 and c.hits == 1

def test_different_args_miss():
    c = m.ToolCache(); n = {"c": 0}
    def f(): n["c"] += 1; return "v"
    m.cached_call(c, "t", {"a": 1}, f)
    m.cached_call(c, "t", {"a": 2}, f)
    assert n["c"] == 2

def test_invalidate():
    c = m.ToolCache()
    m.cached_call(c, "t", {"a": 1}, lambda: "v")
    assert c.invalidate("t", {"a": 1}) is True
    assert c.invalidate("t", {"a": 1}) is False

def test_eviction():
    c = m.ToolCache(max_entries=2)
    c.put("t", {"a": 1}, "v1"); c.put("t", {"a": 2}, "v2"); c.put("t", {"a": 3}, "v3")
    hit, _ = c.get("t", {"a": 1})
    assert hit is False  # oldest evicted

def test_stdlib():
    assert m.stdlib_only() is True
