"""Tests for tool_system_10."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_10")
import pytest

def test_replay():
    s = m.IdempotencyStore(); n = {"c": 0}
    def f(): n["c"] += 1; return "r"
    assert s.execute("k", f) == "r"
    assert s.execute("k", f) == "r"
    assert n["c"] == 1

def test_failure_sticky():
    s = m.IdempotencyStore()
    def boom(): raise ValueError("x")
    with pytest.raises(ValueError): s.execute("k", boom)
    with pytest.raises(m.ToolSystem10Error): s.execute("k", lambda: "r")

def test_empty_key():
    with pytest.raises(m.ToolSystem10Error):
        m.IdempotencyStore().execute("", lambda: 1)

def test_status():
    s = m.IdempotencyStore()
    s.execute("k", lambda: 1)
    assert s.status("k") == "completed"

def test_stdlib():
    assert m.stdlib_only() is True
