"""Tests for tree_05 (B+ tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_05")
def test_scan_sorted():
    b = t.BPlusTree()
    for k in [3, 1, 2]: b.insert(k, str(k))
    assert [k for k, _ in b.scan()] == [1, 2, 3]
def test_get():
    b = t.BPlusTree()
    b.insert(5, "five")
    assert b.get(5) == "five"
    assert b.get(6) is None
def test_overwrite():
    b = t.BPlusTree()
    b.insert(1, "a"); b.insert(1, "b")
    assert b.get(1) == "b"
def test_many_splits():
    b = t.BPlusTree(order=3)
    for k in range(20): b.insert(k, str(k))
    assert len(b.scan()) == 20
