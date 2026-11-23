"""Tests for state_mgmt_25."""
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
m = _load("state_mgmt_25")

def regs():
    peers = {"a", "b"}
    return m.MVRegister("a", peers), m.MVRegister("b", peers)
def test_concurrent_kept():
    ra, rb = regs()
    ra.set("A"); rb.set("B")
    ra.merge(rb)
    assert sorted(ra.get()) == ["A", "B"]
def test_later_dominates():
    ra, _ = regs()
    ra.set("A"); ra.set("A2")
    assert ra.get() == ["A2"]
def test_merge_converges():
    ra, rb = regs()
    ra.set("A"); rb.set("B")
    ra.merge(rb); rb.merge(ra)
    assert sorted(ra.get()) == sorted(rb.get())
def test_peer_mismatch():
    ra, _ = regs()
    with pytest.raises(m.MVError):
        ra.merge(m.MVRegister("a", {"a", "c"}))
def test_stdlib():
    assert m.stdlib_only()
