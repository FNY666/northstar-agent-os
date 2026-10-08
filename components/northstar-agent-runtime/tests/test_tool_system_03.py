"""Tests for tool_system_03."""
import importlib.util, sys, warnings
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_03")
import pytest

def _reg():
    r = m.DeprecationRegistry()
    r.register(m.ToolEntry("new"))
    r.register(m.ToolEntry("old"))
    return r

def test_active_ok():
    assert _reg().check("new") == "ok"

def test_deprecated_warns():
    r = _reg(); r.deprecate("old", replacement="new")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        assert r.check("old") == "deprecated"
        assert any("new" in str(x.message) for x in w)

def test_removed_raises():
    r = _reg(); r.remove("old")
    with pytest.raises(m.ToolSystem03Error):
        r.check("old")

def test_unknown_raises():
    with pytest.raises(m.ToolSystem03Error):
        _reg().check("nope")

def test_stdlib():
    assert m.stdlib_only() is True
