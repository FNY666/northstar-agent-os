"""Tests for tree_06 (Trie)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_06")
def test_insert_search():
    tr = t.Trie(); tr.insert("cat")
    assert tr.search("cat") and not tr.search("ca")
def test_prefix():
    tr = t.Trie(); tr.insert("dog")
    assert tr.starts_with("d") and not tr.starts_with("x")
def test_words_with_prefix():
    tr = t.Trie()
    for w in ["car", "card", "dog"]: tr.insert(w)
    assert tr.words_with_prefix("car") == ["car", "card"]
def test_empty_prefix_all():
    tr = t.Trie()
    for w in ["a", "b"]: tr.insert(w)
    assert tr.words_with_prefix("") == ["a", "b"]
