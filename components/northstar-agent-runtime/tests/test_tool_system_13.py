"""Tests for tool_system_13."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_13")
import pytest

def _boom(): raise ValueError("x")

def test_opens_after_threshold():
    cb = m.CircuitBreaker(failure_threshold=2, reset_timeout=60.0)
    for _ in range(2):
        with pytest.raises(ValueError): cb.call(_boom)
    assert cb.state == m.State.OPEN
    with pytest.raises(m.CircuitOpenError): cb.call(lambda: 1)

def test_half_open_recovery():
    now = {"t": 0.0}
    cb = m.CircuitBreaker(failure_threshold=1, reset_timeout=10.0, clock=lambda: now["t"])
    with pytest.raises(ValueError): cb.call(_boom)
    now["t"] = 11.0
    assert cb.state == m.State.HALF_OPEN
    assert cb.call(lambda: "ok") == "ok"
    assert cb.state == m.State.CLOSED

def test_probe_failure_reopens():
    now = {"t": 0.0}
    cb = m.CircuitBreaker(failure_threshold=1, reset_timeout=10.0, clock=lambda: now["t"])
    with pytest.raises(ValueError): cb.call(_boom)
    now["t"] = 11.0
    with pytest.raises(ValueError): cb.call(_boom)
    assert cb.state == m.State.OPEN

def test_success_resets():
    cb = m.CircuitBreaker(failure_threshold=3, reset_timeout=60.0)
    with pytest.raises(ValueError): cb.call(_boom)
    cb.call(lambda: 1)
    assert cb.state == m.State.CLOSED

def test_stdlib():
    assert m.stdlib_only() is True
