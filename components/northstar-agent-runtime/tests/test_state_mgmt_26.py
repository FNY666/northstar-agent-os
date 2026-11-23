"""Tests for state_mgmt_26."""
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
m = _load("state_mgmt_26")

def test_add_contains():
    s = m.ORSet("n")
    s.add("x")
    assert "x" in s and "y" not in s
def test_remove():
    s = m.ORSet("n")
    s.add("x"); s.remove("x")
    assert "x" not in s
def test_add_wins():
    a, b = m.ORSet("n1"), m.ORSet("n2")
    a.add("z")
    b.remove("z")
    a.merge(b); b.merge(a)
    assert "z" in a.elements()
def test_converge():
    a, b = m.ORSet("n1"), m.ORSet("n2")
    a.add("x"); b.add("y"); a.remove("x")
    a.merge(b); b.merge(a)
    assert a.elements() == b.elements() == {"y"}
def test_empty_elem():
    with pytest.raises(m.ORSetError):
        m.ORSet("n").add("")
def test_stdlib():
    assert m.stdlib_only()
