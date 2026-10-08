"""Tests for tree_14 (Splay mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_14")
def test_access_moves_to_root():
    r = None
    for k in [5, 3, 7]: r = t.splay_insert(r, k)
    r, found = t.splay_search(r, 3)
    assert found and r.key == 3
def test_miss():
    r = t.splay_insert(None, 1)
    r, found = t.splay_search(r, 2)
    assert not found
def test_insert_dupe():
    r = t.splay_insert(None, 1)
    r = t.splay_insert(r, 1)
    assert r.key == 1
def test_empty():
    r, found = t.splay_search(None, 1)
    assert r is None and not found
