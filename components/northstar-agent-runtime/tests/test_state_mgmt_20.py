"""Tests for state_mgmt_20."""
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
m = _load("state_mgmt_20")

def test_reconcile_newer_wins():
    a = m.Replica("a", {"k": ("v1", 1)})
    b = m.Replica("b", {"k": ("v2", 2)})
    m.reconcile(a, b)
    assert a.data["k"] == ("v2", 2)
    assert b.data["k"] == ("v2", 2)
def test_noop_when_equal():
    a = m.Replica("a", {"k": ("v", 1)})
    b = m.Replica("b", {"k": ("v", 1)})
    assert m.reconcile(a, b) == 0
def test_converge():
    reps = [m.Replica(f"r{i}", {f"k{i}": ("v", 1)}) for i in range(4)]
    m.rounds_until_converged(reps, seed=1)
    assert len({r.digest() for r in reps}) == 1
def test_malformed():
    with pytest.raises(m.AntiEntropyError):
        m.Replica("z", {"k": ("v", -1)})
def test_stdlib():
    assert m.stdlib_only()
