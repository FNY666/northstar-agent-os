"""Tests for state_mgmt_27."""
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
m = _load("state_mgmt_27")

def test_add_lookup():
    s = m.TwoPSet()
    s.add("x")
    assert "x" in s
def test_remove():
    s = m.TwoPSet()
    s.add("x"); s.remove("x")
    assert "x" not in s
def test_no_readd():
    s = m.TwoPSet()
    s.add("x"); s.remove("x"); s.add("x")
    assert "x" not in s
def test_merge():
    a, b = m.TwoPSet(), m.TwoPSet()
    a.add("x"); b.add("y")
    a.merge(b)
    assert a.elements() == {"x", "y"}
def test_remove_never_added():
    with pytest.raises(m.TwoPSetError):
        m.TwoPSet().remove("ghost")
def test_stdlib():
    assert m.stdlib_only()
