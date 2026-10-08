"""Tests for tool_system_06."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_06")
import pytest

def test_order_preserved():
    tools = {"f": lambda x: x + 1}
    r = m.run_parallel([m.CallSpec("f", {"x": 1}), m.CallSpec("f", {"x": 2})], tools)
    assert r.outcomes == [(True, 2), (True, 3)]

def test_error_captured():
    def boom(): raise ValueError("x")
    r = m.run_parallel([m.CallSpec("b", {})], {"b": boom})
    assert r.outcomes[0][0] is False

def test_unknown_tool():
    r = m.run_parallel([m.CallSpec("nope", {})], {})
    assert r.outcomes[0][0] is False

def test_no_calls():
    with pytest.raises(m.ToolSystem06Error):
        m.run_parallel([], {})

def test_stdlib():
    assert m.stdlib_only() is True
