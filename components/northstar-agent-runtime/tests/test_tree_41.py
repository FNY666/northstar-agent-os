"""Tests for tree_41 (Rope mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_41")
def test_concat():
    assert t.Rope("ab").concat(t.Rope("cd")).to_str() == "abcd"
def test_len():
    assert len(t.Rope("abc")) == 3
def test_char_at():
    assert t.Rope("xy").concat(t.Rope("z")).char_at(2) == "z"
def test_split():
    a, b = t.Rope("hello").split(2)
    assert (a.to_str(), b.to_str()) == ("he", "llo")
