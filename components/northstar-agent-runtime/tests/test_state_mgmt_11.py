
"""Tests for state_mgmt_11."""
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
m = _load("state_mgmt_11")

def test_converge():
    a, b = m.GCounter("a", {"a", "b"}), m.GCounter("b", {"a", "b"})
    a.increment(2); b.increment(3); a.merge(b); b.merge(a)
    assert a.value() == b.value() == 5
def test_idempotent():
    a, b = m.GCounter("a", {"a", "b"}), m.GCounter("b", {"a", "b"})
    a.increment(); a.merge(b); a.merge(b)
    assert a.value() == 1
def test_mismatch():
    with pytest.raises(m.CRDTError):
        m.GCounter("a").merge(m.GCounter("b"))
def test_stdlib():
    assert m.stdlib_only()
