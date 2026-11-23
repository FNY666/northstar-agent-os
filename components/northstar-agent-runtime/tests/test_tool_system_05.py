"""Tests for tool_system_05."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_05")
import pytest

def test_chain_placeholders():
    tools = {"d": lambda x: x * 2, "a": lambda x, y: x + y}
    steps = [m.ChainStep("d", {"x": 5}), m.ChainStep("a", {"x": "{step_0}", "y": 1})]
    r = m.run_chain(steps, tools)
    assert r.results == [10, 11] and r.failed_step == -1

def test_unknown_tool():
    r = m.run_chain([m.ChainStep("nope", {})], {})
    assert r.failed_step == 0

def test_bad_placeholder():
    r = m.run_chain([m.ChainStep("d", {"x": "{step_5}"})], {"d": lambda x: x})
    assert r.failed_step == 0

def test_no_steps():
    with pytest.raises(m.ToolSystem05Error):
        m.run_chain([], {})

def test_stdlib():
    assert m.stdlib_only() is True
