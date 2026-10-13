"""Tests for state_mgmt_18."""
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
m = _load("state_mgmt_18")

def test_stable():
    r = m.HashRing(replicas=20)
    r.add_node("a"); r.add_node("b")
    assert r.get_node("k") == r.get_node("k")
def test_wrap():
    r = m.HashRing(replicas=10)
    r.add_node("only")
    assert r.get_node("anything") == "only"
def test_dup_add():
    r = m.HashRing(replicas=10)
    r.add_node("a")
    with pytest.raises(m.HashRingError):
        r.add_node("a")
def test_unknown_remove():
    r = m.HashRing(replicas=10)
    with pytest.raises(m.HashRingError):
        r.remove_node("ghost")
def test_empty_lookup():
    with pytest.raises(m.HashRingError):
        m.HashRing().get_node("k")
def test_stdlib():
    assert m.stdlib_only()
