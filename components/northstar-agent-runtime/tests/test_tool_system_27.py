"""Tests for tool_system_27."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_27")
import pytest

def _reg():
    reg = m.Registry()
    reg.register(m.ToolEntry(name="search", version="1.0",
                             description="Web search", capabilities=["web"]))
    reg.register(m.ToolEntry(name="calc", version="0.1",
                             description="Calculator tool", capabilities=["math"]))
    return reg

def test_register_and_list():
    reg = _reg()
    names = [(e.name, e.version) for e in reg.list()]
    assert ("search", "1.0") in names and ("calc", "0.1") in names

def test_duplicate_version_conflict():
    reg = _reg()
    with pytest.raises(m.DuplicateVersion):
        reg.register(m.ToolEntry(name="search", version="1.0",
                                 description="dup"))
    # same name, new version is fine
    reg.register(m.ToolEntry(name="search", version="2.0",
                             description="v2"))
    assert len(reg.list()) == 3

def test_search():
    reg = _reg()
    assert len(reg.search("calcul")) == 1
    assert len(reg.search("SEARCH")) == 1  # case-insensitive
    assert reg.search("zzz") == []

def test_install_and_list_installed():
    reg = _reg()
    reg.install("calc", "0.1")
    inst = reg.list_installed()
    assert len(inst) == 1 and inst[0].name == "calc"
    with pytest.raises(m.UnknownEntry):
        reg.install("ghost", "9.9")

def test_unregister():
    reg = _reg()
    reg.unregister("calc", "0.1")
    assert len(reg.list()) == 1
    with pytest.raises(m.UnknownEntry):
        reg.unregister("calc", "0.1")

def test_stdlib():
    assert m.stdlib_only() is True
