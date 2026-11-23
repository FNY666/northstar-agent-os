"""Tests for tool_system_02."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_02")
import pytest

def test_parse():
    v = m.parse_version("2.3.4")
    assert (v.major, v.minor, v.patch) == (2, 3, 4)

def test_compatible():
    assert m.is_compatible(m.parse_version("1.5.0"), m.parse_version("1.2.0"))
    assert not m.is_compatible(m.parse_version("2.0.0"), m.parse_version("1.0.0"))

def test_satisfies():
    assert m.satisfies(m.parse_version("1.2.3"), ">=1.2.0")
    assert not m.satisfies(m.parse_version("1.2.3"), ">1.2.3")

def test_bad_version():
    with pytest.raises(m.ToolSystem02Error):
        m.parse_version("1.2")

def test_stdlib():
    assert m.stdlib_only() is True
