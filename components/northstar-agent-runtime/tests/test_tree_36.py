"""Tests for tree_36 (Huffman)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_36")
def test_roundtrip():
    r = t.build({"x": 3, "y": 1})
    c = t.codes(r)
    assert t.decode(t.encode("xxy", c), r) == "xxy"
def test_prefix_free():
    r = t.build({"a": 4, "b": 2, "c": 1, "d": 1})
    c = t.codes(r)
    vals = list(c.values())
    assert all(not (a != b and b.startswith(a)) for a in vals for b in vals)
def test_freq_order():
    r = t.build({"a": 10, "b": 1})
    c = t.codes(r)
    assert len(c["a"]) <= len(c["b"])
def test_single_symbol():
    r = t.build({"q": 5})
    assert t.decode(t.encode("qq", t.codes(r)), r) == "qq"
