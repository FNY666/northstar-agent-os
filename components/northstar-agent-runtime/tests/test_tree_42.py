"""Tests for tree_42 (TST)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_42")
def test_insert_search():
    s = t.TST(); s.insert("hi")
    assert s.search("hi") and not s.search("h")
def test_shared_prefix():
    s = t.TST()
    for w in ["ab", "abc"]: s.insert(w)
    assert s.search("ab") and s.search("abc")
def test_words():
    s = t.TST()
    for w in ["b", "a"]: s.insert(w)
    assert s.words() == ["a", "b"]
def test_miss():
    s = t.TST(); s.insert("x")
    assert not s.search("y")
