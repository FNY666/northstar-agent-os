"""Tests for tool_system_08."""
import importlib.util, sys, time
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_08")
import pytest

def test_fast_succeeds():
    assert m.call_with_timeout(lambda: 7, timeout=5.0) == 7

def test_slow_times_out():
    with pytest.raises(m.ToolTimeoutError):
        m.call_with_timeout(time.sleep, 5.0, timeout=0.2)

def test_inner_exception_propagates():
    def boom(): raise ValueError("in")
    with pytest.raises(ValueError):
        m.call_with_timeout(boom, timeout=5.0)

def test_bad_timeout():
    with pytest.raises(m.ToolSystem08Error):
        m.call_with_timeout(lambda: 1, timeout=0)

def test_stdlib():
    assert m.stdlib_only() is True
