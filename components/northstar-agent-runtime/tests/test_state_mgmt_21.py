"""Tests for state_mgmt_21."""
import importlib.util, sys
from pathlib import Path
import pytest
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
m = _load("state_mgmt_21")

def test_equal_roots():
    a = m.MerkleTree({"x": "1", "y": "2"})
    b = m.MerkleTree({"y": "2", "x": "1"})
    assert a.root() == b.root()
    assert a.diff(b) == []
def test_diff_finds_key():
    a = m.MerkleTree({"x": "1", "y": "2", "z": "3"})
    b = m.MerkleTree({"x": "1", "y": "CHANGED", "z": "3"})
    assert a.diff(b) == ["y"]
def test_empty():
    assert m.MerkleTree({}).diff(m.MerkleTree({})) == []
def test_non_str():
    with pytest.raises(m.MerkleError):
        m.MerkleTree({"k": 1})
def test_stdlib():
    assert m.stdlib_only()
