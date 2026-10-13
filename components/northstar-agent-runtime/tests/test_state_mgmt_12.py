
"""Tests for state_mgmt_12."""
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
m = _load("state_mgmt_12")

def test_concurrent_inserts_converge():
    a = m.Op("insert", 1, "X", site=1); b = m.Op("insert", 1, "Y", site=2)
    r1 = m.apply(m.apply("ab", [a]), [m.transform(b, a)])
    r2 = m.apply(m.apply("ab", [b]), [m.transform(a, b)])
    assert r1 == r2
def test_delete_clamp():
    d1 = m.Op("delete", 0, length=2); d2 = m.Op("delete", 1, length=2)
    assert m.apply(m.apply("abcd", [d1]), [m.transform(d2, d1)]) == "d"
def test_bad_pos():
    with pytest.raises(m.OTError):
        m.apply("ab", [m.Op("insert", 9, "x")])
def test_stdlib():
    assert m.stdlib_only()
