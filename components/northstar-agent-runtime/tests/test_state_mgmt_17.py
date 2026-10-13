"""Tests for state_mgmt_17."""
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
m = _load("state_mgmt_17")

def test_initiate_records():
    n = m.CLNode("a", "S")
    n.add_channel("c1")
    n.initiate()
    assert n.recorded_state == "S"
    assert n.channels["c1"].recording is True
def test_first_marker_records():
    n = m.CLNode("b", "SB")
    n.add_channel("in")
    assert n.receive_marker("in") is True
    assert n.recorded_state == "SB"
def test_second_marker_stops():
    n = m.CLNode("b", "SB")
    n.add_channel("in")
    n.receive_marker("in")
    assert n.receive_marker("in") is False
def test_unknown_channel():
    n = m.CLNode("b")
    with pytest.raises(m.ChandyLamportError):
        n.receive_marker("nope")
def test_double_initiate():
    n = m.CLNode("a")
    n.add_channel("c")
    n.initiate()
    with pytest.raises(m.ChandyLamportError):
        n.initiate()
def test_stdlib():
    assert m.stdlib_only()
