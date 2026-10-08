"""Tests for tree_33 (H-tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_33")
def test_insert_query():
    h = t.HTreeMock(); h.insert(1, 1, "v")
    assert h.query(1, 1) == ["v"]
def test_miss():
    h = t.HTreeMock(); h.insert(1, 1, "v")
    assert h.query(2, 2) == []
def test_multi():
    h = t.HTreeMock()
    h.insert(5, 5, "a"); h.insert(5, 5, "b")
    assert sorted(h.query(5, 5)) == ["a", "b"]
def test_level():
    h = t.HTreeMock()
    h.insert(1, 1, "a", level=2)
    assert h.query(1, 1, level=2) == ["a"]
