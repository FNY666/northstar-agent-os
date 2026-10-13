"""Tests for tool_system_01."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_01")
import pytest

def _reg():
    r = m.ToolRegistry()
    r.register(m.ToolInfo("read_file", "Read a file", ("fs",), ("read",)))
    r.register(m.ToolInfo("write_file", "Write a file", ("fs",), ("write",)))
    return r

def test_search_name():
    assert _reg().search("read")[0].name == "read_file"

def test_search_ranked():
    hits = _reg().search("file")
    assert {h.name for h in hits} == {"read_file", "write_file"}

def test_search_empty_query():
    assert _reg().search("") == []

def test_unknown_get():
    with pytest.raises(m.ToolSystem01Error):
        _reg().get("nope")

def test_stdlib():
    assert m.stdlib_only() is True
