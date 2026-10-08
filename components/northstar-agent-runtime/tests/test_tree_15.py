"""Tests for tree_15 (Link-cut mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_15")
def test_path_sum():
    lc = t.LinkCutMock()
    lc.make(0, 5); lc.make(1, 7); lc.link(1, 0)
    assert lc.path_sum(1) == 12
def test_root_of():
    lc = t.LinkCutMock()
    lc.make(0); lc.make(1); lc.link(1, 0)
    assert lc.root_of(1) == 0
def test_cut():
    lc = t.LinkCutMock()
    lc.make(0, 1); lc.make(1, 2); lc.link(1, 0); lc.cut(1)
    assert lc.root_of(1) == 1 and lc.path_sum(1) == 2
def test_single():
    lc = t.LinkCutMock()
    lc.make(9, 3)
    assert lc.path_sum(9) == 3
