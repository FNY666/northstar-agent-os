
"""Tests for state_mgmt_15."""
import importlib.util, sys
from pathlib import Path
import pytest
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
m = _load("state_mgmt_15")

def test_logical_bump():
    now = [5000]
    c = m.HybridClock("n", lambda: now[0])
    s1, s2 = c.tick(), c.tick()
    assert (s1.wall, s1.logical) == (5000, 0)
    assert (s2.wall, s2.logical) == (5000, 1)
def test_receive():
    now = [5000]
    c = m.HybridClock("n", lambda: now[0]); c.tick()
    s = c.receive(m.HLCStamp(5000, 4, "o"))
    assert s.logical == 5
def test_drift():
    now = [1000]
    c = m.HybridClock("n", lambda: now[0], max_drift_ms=100)
    c.tick(); now[0] = 5000
    with pytest.raises(m.HLCError):
        c.tick()
def test_stdlib():
    assert m.stdlib_only()
