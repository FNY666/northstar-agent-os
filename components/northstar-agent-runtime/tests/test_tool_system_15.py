"""Tests for tool_system_15."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_15")
import pytest

def _rl():
    now = {"t": 0.0}
    rl = m.RateLimiter(clock=lambda: now["t"])
    rl.configure("t", capacity=2, refill_per_sec=1.0)
    return rl, now

def test_consume_and_reject():
    rl, _ = _rl()
    rl.acquire("t"); rl.acquire("t")
    with pytest.raises(m.RateLimitExceeded):
        rl.acquire("t")

def test_refill():
    rl, now = _rl()
    rl.acquire("t"); rl.acquire("t")
    now["t"] = 2.0
    rl.acquire("t")  # refilled

def test_unconfigured():
    rl, _ = _rl()
    with pytest.raises(m.ToolSystem15Error):
        rl.acquire("nope")

def test_bad_config():
    rl, _ = _rl()
    with pytest.raises(m.ToolSystem15Error):
        rl.configure("x", capacity=0, refill_per_sec=1)

def test_stdlib():
    assert m.stdlib_only() is True
