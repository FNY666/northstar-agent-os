"""Tests for tree_07 (Patricia trie mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_07")
def test_insert_search():
    p = t.PatriciaTrie(); p.insert("hello")
    assert p.search("hello") and not p.search("hell")
def test_shared_prefix():
    p = t.PatriciaTrie()
    for w in ["ab", "abc"]: p.insert(w)
    assert p.search("ab") and p.search("abc")
def test_words():
    p = t.PatriciaTrie()
    for w in ["x", "y"]: p.insert(w)
    assert sorted(p.words()) == ["x", "y"]
def test_count():
    p = t.PatriciaTrie()
    p.insert("a"); p.insert("a")
    assert p.count == 1
