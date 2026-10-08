"""Tests for tree_49 (Paged BST mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_49")
def test_keys_sorted():
    b = t.PagedBSTMock()
    for k in [4, 2, 6, 1]: b.insert(k)
    assert b.all_keys() == [1, 2, 4, 6]
def test_search():
    b = t.PagedBSTMock()
    b.insert(7)
    assert b.search(7) and not b.search(8)
def test_page_loads():
    b = t.PagedBSTMock()
    for k in range(10): b.insert(k)
    assert b.page_loads > 0
def test_dupe():
    b = t.PagedBSTMock()
    b.insert(1); b.insert(1)
    assert b.all_keys() == [1]
