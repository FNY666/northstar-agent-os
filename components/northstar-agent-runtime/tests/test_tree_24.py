"""Tests for tree_24 (BK-tree)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_24")
def test_exact():
    b = t.BKTree(); b.insert("cat")
    assert b.query("cat", 0) == [("cat", 0)]
def test_fuzzy():
    b = t.BKTree()
    for w in ["cat", "car", "dog"]: b.insert(w)
    got = [w for w, _ in b.query("cat", 1)]
    assert "cat" in got and "car" in got and "dog" not in got
def test_empty():
    assert t.BKTree().query("a", 2) == []
def test_edit_distance():
    assert t.edit_distance("kitten", "sitting") == 3
