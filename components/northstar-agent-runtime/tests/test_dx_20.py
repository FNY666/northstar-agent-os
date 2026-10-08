"""Tests for dx_20. type checkers."""
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

dx = _load("dx_20")

def _reg():
    r = dx.TypeRegistry()
    r.declare("count", "int")
    r.declare("name", "str")
    return r


def test_check_pass():
    r = _reg().check("count", 3)
    assert r.ok is True and r.expected == "int"


def test_check_fail():
    assert _reg().check("count", "x").ok is False


def test_bool_not_int():
    assert _reg().check("count", True).ok is False


def test_unknown_symbol_raises():
    with pytest.raises(dx.TypeCheckError):
        _reg().check("missing", 1)


def test_unknown_type_raises():
    with pytest.raises(dx.TypeCheckError):
        _reg().declare("x", "datetime")


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX20_TYPECHECK_VERSION == "dx-typecheck.v1"
