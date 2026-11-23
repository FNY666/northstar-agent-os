"""Tests for state_mgmt_19."""
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
m = _load("state_mgmt_19")

def nodes(n=10):
    return [f"n{i}" for i in range(n)]
def test_converges():
    assert 1 <= m.GossipSim(nodes(), 2, 7).disseminate("n0") < 1000
def test_deterministic():
    a = m.GossipSim(nodes(), 2, 7).disseminate("n0")
    b = m.GossipSim(nodes(), 2, 7).disseminate("n0")
    assert a == b
def test_bad_fanout():
    with pytest.raises(m.GossipError):
        m.GossipSim(nodes(3), 3, 0)
def test_bad_origin():
    with pytest.raises(m.GossipError):
        m.GossipSim(nodes(), 2, 0).disseminate("ghost")
def test_single_node():
    with pytest.raises(m.GossipError):
        m.GossipSim(["a"], 1, 0)
def test_stdlib():
    assert m.stdlib_only()
