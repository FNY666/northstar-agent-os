"""Tests for state_mgmt_24."""
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
m = _load("state_mgmt_24")

def test_newer_wins():
    r = m.LWWRegister("x")
    r.set("a", 1, "n1"); r.set("b", 2, "n1")
    assert r.get() == "b"
def test_older_rejected():
    r = m.LWWRegister("x")
    r.set("a", 5, "n1")
    assert r.set("b", 4, "n2") is False
    assert r.get() == "a"
def test_merge():
    a, b = m.LWWRegister("x"), m.LWWRegister("x")
    a.set("A", 1, "n1"); b.set("B", 9, "n2")
    a.merge(b)
    assert a.get() == "B"
def test_empty_get():
    with pytest.raises(m.LWWError):
        m.LWWRegister("e").get()
def test_name_mismatch():
    with pytest.raises(m.LWWError):
        m.LWWRegister("a").merge(m.LWWRegister("b"))
def test_stdlib():
    assert m.stdlib_only()
