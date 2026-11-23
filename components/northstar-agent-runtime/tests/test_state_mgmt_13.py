
"""Tests for state_mgmt_13."""
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
m = _load("state_mgmt_13")

def test_causality():
    a = m.VectorClock("a", {"a", "b"}); b = m.VectorClock("b", {"a", "b"})
    c1 = a.tick(); c2 = b.update(c1)
    assert m.VectorClock.compare(c1, c2) == "before"
def test_concurrent():
    x = m.VectorClock("x", {"x", "y"}); y = m.VectorClock("y", {"x", "y"})
    assert m.VectorClock.compare(x.tick(), y.tick()) == "concurrent"
def test_unknown_node():
    a = m.VectorClock("a")
    with pytest.raises(m.VectorClockError):
        a.update({"zzz": 1})
def test_stdlib():
    assert m.stdlib_only()
