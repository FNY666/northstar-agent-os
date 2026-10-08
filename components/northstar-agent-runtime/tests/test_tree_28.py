"""Tests for tree_28 (X-tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_28")
def test_supernode():
    x = t.XTreeMock(cap=1)
    for i in range(5): x.insert((0, 0, 9, 9), i)
    assert x.supernode is True
def test_query():
    x = t.XTreeMock()
    x.insert((0, 0, 1, 1), "a")
    assert x.query((0, 0, 1, 1)) == ["a"]
def test_miss():
    x = t.XTreeMock()
    x.insert((0, 0, 1, 1), "a")
    assert x.query((5, 5, 6, 6)) == []
def test_split_clean():
    x = t.XTreeMock(cap=2)
    for i in range(3): x.insert((i * 10, 0, i * 10 + 1, 1), i)
    assert sorted(x.query((0, 0, 100, 1))) == [0, 1, 2]
