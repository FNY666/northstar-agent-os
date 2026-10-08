"""Tests for tool_system_07."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_07")
import pytest

def test_eventual_success():
    n = {"c": 0}
    def f():
        n["c"] += 1
        if n["c"] < 2: raise ValueError("flaky")
        return "ok"
    assert m.retry(f, m.RetryPolicy(max_attempts=3)) == "ok"
    assert n["c"] == 2

def test_exhausted():
    with pytest.raises(m.ToolSystem07Error):
        m.retry(lambda: 1/0, m.RetryPolicy(max_attempts=2))

def test_non_retryable_fast():
    with pytest.raises(KeyboardInterrupt):
        m.retry(lambda: (_ for _ in ()).throw(KeyboardInterrupt()),
                m.RetryPolicy(retryable=(ValueError,)))

def test_schedule_grows():
    s = m.backoff_schedule(m.RetryPolicy(max_attempts=4, base_delay=1.0))
    assert len(s) == 3 and s[0] < s[1] < s[2]

def test_stdlib():
    assert m.stdlib_only() is True
