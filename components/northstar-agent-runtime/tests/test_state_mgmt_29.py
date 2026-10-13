"""Tests for state_mgmt_29."""
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
m = _load("state_mgmt_29")

def test_gcounter():
    a, b = m.GCounter("a", {"a", "b"}), m.GCounter("b", {"a", "b"})
    a.increment(2); b.increment(3)
    a.merge(b); b.merge(a)
    assert a.value() == b.value() == 5
def test_gcounter_idempotent():
    a, b = m.GCounter("a", {"a", "b"}), m.GCounter("b", {"a", "b"})
    a.increment(); a.merge(b); a.merge(b)
    assert a.value() == 1
def test_pncounter():
    a, b = m.PNCounter("a", {"a", "b"}), m.PNCounter("b", {"a", "b"})
    a.increment(10); a.decrement(3); b.decrement(2)
    a.merge(b); b.merge(a)
    assert a.value() == b.value() == 5
def test_peer_mismatch():
    with pytest.raises(m.CounterError):
        m.GCounter("a", {"a", "b"}).merge(m.GCounter("a", {"a"}))
def test_bad_amount():
    with pytest.raises(m.CounterError):
        m.GCounter("a", {"a"}).increment(0)
def test_stdlib():
    assert m.stdlib_only()
