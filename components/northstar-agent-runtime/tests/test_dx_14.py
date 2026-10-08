"""Tests for dx_14 go to definition."""
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

dx = _load("dx_14")


def _idx():
    i = dx.DefinitionIndex()
    i.index("allow", dx.Location(file="gates.py", line=42, column=4))
    return i


def test_lookup():
    loc = _idx().definition("allow")
    assert (loc.file, loc.line, loc.column) == ("gates.py", 42, 4)


def test_unknown_raises():
    with pytest.raises(dx.DefinitionError):
        _idx().definition("deny")


def test_empty_symbol_raises():
    with pytest.raises(dx.DefinitionError):
        _idx().definition("")


def test_bad_line_raises():
    i = dx.DefinitionIndex()
    with pytest.raises(dx.DefinitionError):
        i.index("x", dx.Location(file="a.py", line=0))


def test_has_and_symbols():
    i = _idx()
    assert i.has("allow") and not i.has("deny")
    assert i.symbols == ["allow"]


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX14_DEFINITION_VERSION == "dx-goto-def.v1"
