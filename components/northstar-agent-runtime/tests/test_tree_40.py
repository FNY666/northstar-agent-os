"""Tests for tree_40 (Merkle tree)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_40")
def test_verify():
    m = t.MerkleTree([b"a", b"b"])
    assert t.MerkleTree.verify(b"a", m.proof(0), m.root)
def test_tamper():
    m = t.MerkleTree([b"a", b"b"])
    assert not t.MerkleTree.verify(b"z", m.proof(0), m.root)
def test_odd_leaves():
    m = t.MerkleTree([b"a", b"b", b"c"])
    assert t.MerkleTree.verify(b"c", m.proof(2), m.root)
def test_root_stable():
    m1 = t.MerkleTree([b"x"]); m2 = t.MerkleTree([b"x"])
    assert m1.root == m2.root
