"""Tests for tree_35 (Suffix array)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_35")
def test_sa_banana():
    assert t.build_sa("banana") == [5, 3, 1, 0, 4, 2]
def test_sa_sorted():
    sa = t.build_sa("cba")
    assert [("cba"[i:]) for i in sa] == ["a", "ba", "cba"]
def test_lcp():
    sa = t.build_sa("aaaa")
    assert t.build_lcp("aaaa", sa) == [0, 1, 2, 3]
def test_single():
    assert t.build_sa("z") == [0]
