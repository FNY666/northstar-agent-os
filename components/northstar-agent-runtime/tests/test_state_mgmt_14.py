
"""Tests for state_mgmt_14."""
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
m = _load("state_mgmt_14")

def test_monotonic():
    c = m.LamportClock("n")
    assert c.tick() < c.receive(10) < c.tick()
def test_order():
    assert m.order((1, "a"), (2, "a")) == -1
    assert m.order((2, "b"), (2, "a")) == 1
def test_bad_remote():
    with pytest.raises(m.LamportError):
        m.LamportClock("n").receive(-5)
def test_stdlib():
    assert m.stdlib_only()
