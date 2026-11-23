
"""Tests for state_mgmt_02."""
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
m = _load("state_mgmt_02")

def test_diff_apply():
    old, new = {"a": 1, "b": 2}, {"a": 1, "b": 3, "c": 4}
    assert m.apply(old, m.diff(old, new)) == new
def test_delete():
    assert m.apply({"x": 1}, m.diff({"x": 1}, {})) == {}
def test_bad_op():
    with pytest.raises(m.IncrementalError):
        m.apply({}, [m.Diff("zap", "a")])
def test_stdlib():
    assert m.stdlib_only()
