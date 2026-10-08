"""Tests for state_mgmt_23."""
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
m = _load("state_mgmt_23")

def C(v, t, n):
    return m.Candidate(v, t, n)
def test_lww():
    assert m.resolve("lww", [C("a", 1, "n1"), C("b", 3, "n2")]).winners == ("b",)
def test_lww_tie_node():
    assert m.resolve("lww", [C("a", 5, "n1"), C("b", 5, "n2")]).winners == ("b",)
def test_union():
    r = m.resolve("union", [C("b", 1, "n"), C("a", 2, "n")])
    assert r.winners == ("'a'", "'b'")
def test_unknown_strategy():
    with pytest.raises(m.ConflictError):
        m.resolve("vote", [C("a", 1, "n")])
def test_empty():
    with pytest.raises(m.ConflictError):
        m.resolve("lww", [])
def test_stdlib():
    assert m.stdlib_only()
