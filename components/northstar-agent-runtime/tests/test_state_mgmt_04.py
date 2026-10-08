
"""Tests for state_mgmt_04."""
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
m = _load("state_mgmt_04")

def test_roundtrip():
    s = {"k": "v" * 100}
    assert m.decompress(m.compress(s)) == s
def test_corrupt():
    b = m.compress({"a": 1})[:-6] + b"000000"
    with pytest.raises(m.CompressionError):
        m.decompress(b)
def test_bad_level():
    with pytest.raises(m.CompressionError):
        m.compress({"a": 1}, level=10)
def test_stdlib():
    assert m.stdlib_only()
