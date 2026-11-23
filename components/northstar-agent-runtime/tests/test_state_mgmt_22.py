"""Tests for state_mgmt_22."""
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
m = _load("state_mgmt_22")

def test_plan_pure():
    a = m.Store({"k": ("v1", 1)})
    b = m.Store({"k": ("v2", 2)})
    p = m.plan(a, b)
    assert a.data["k"] == ("v1", 1)
    assert len(p.ops) == 1 and p.ops[0].action == "a_pull"
def test_converge():
    a = m.Store({"x": ("1", 1)})
    b = m.Store({"y": ("2", 1)})
    m.reconcile(a, b)
    assert a.data == b.data == {"x": ("1", 1), "y": ("2", 1)}
def test_conflict_surfaced():
    a = m.Store({"k": ("A", 5)})
    b = m.Store({"k": ("B", 5)})
    p = m.reconcile(a, b)
    assert len(p.conflicts) == 1
    assert a.data["k"] == ("A", 5) and b.data["k"] == ("B", 5)
def test_malformed():
    with pytest.raises(m.ReconcileError):
        m.Store({"k": ("v", -2)})
def test_stdlib():
    assert m.stdlib_only()
