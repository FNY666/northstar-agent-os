"""Tests for tree_46 (Scapegoat mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_46")
def test_inorder():
    s = t.ScapegoatMock()
    for k in [3, 1, 2]: s.insert(k)
    assert s.inorder() == [1, 2, 3]
def test_count():
    s = t.ScapegoatMock()
    for k in range(10): s.insert(k)
    assert s.n == 10
def test_dupe():
    s = t.ScapegoatMock()
    s.insert(1); s.insert(1)
    assert s.n == 1
def test_rebuild_keeps_order():
    s = t.ScapegoatMock()
    for k in reversed(range(30)): s.insert(k)
    assert s.inorder() == list(range(30))
