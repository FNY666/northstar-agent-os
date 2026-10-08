
"""Tests for state_mgmt_08."""
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
m = _load("state_mgmt_08")

def test_additive():
    s0 = m.Schema("v1", {"a": m.Field("a", "int", 0, True)})
    s1 = m.evolve(s0, [m.Field("b", "str", "x")], [])
    assert m.apply_defaults({"a": 1}, s1) == {"a": 1, "b": "x"}
def test_type_change_forbidden():
    s0 = m.Schema("v1", {"a": m.Field("a", "int", 0)})
    with pytest.raises(m.EvolutionError):
        m.evolve(s0, [m.Field("a", "str", "")], [])
def test_deprecate():
    s0 = m.Schema("v1", {"a": m.Field("a", "int", 0)})
    s1 = m.evolve(s0, [], ["a"])
    assert s1.fields["a"].deprecated
def test_stdlib():
    assert m.stdlib_only()
