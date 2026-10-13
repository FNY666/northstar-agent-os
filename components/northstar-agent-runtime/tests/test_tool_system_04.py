"""Tests for tool_system_04."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_04")
import pytest

def test_compose_runs():
    p = m.compose("p", str.upper, len)
    assert m.run_pipeline(p, "abc") == 3

def test_order():
    p = m.compose("p", lambda x: x + 1, lambda x: x * 2)
    assert m.run_pipeline(p, 3) == 8

def test_needs_two():
    with pytest.raises(m.ToolSystem04Error):
        m.compose("p", str.upper)

def test_failure_context():
    def boom(x): raise ValueError("z")
    with pytest.raises(m.ToolSystem04Error) as e:
        m.run_pipeline(m.compose("p", str, boom), 1)
    assert "boom" in str(e.value)

def test_stdlib():
    assert m.stdlib_only() is True
