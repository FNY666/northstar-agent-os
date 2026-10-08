"""Tests for tree_08 (Suffix trie mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_08")
def test_contains():
    s = t.SuffixTrie("ababa")
    assert s.contains("bab") and not s.contains("abb")
def test_occurrences():
    s = t.SuffixTrie("aaaa")
    assert s.occurrences("aa") == 3
def test_full_text():
    s = t.SuffixTrie("xyz")
    assert s.contains("xyz")
def test_missing():
    s = t.SuffixTrie("abc")
    assert s.occurrences("d") == 0
