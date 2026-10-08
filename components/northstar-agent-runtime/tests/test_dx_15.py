"""Tests for dx_15 find references."""
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

dx = _load("dx_15")


def _idx():
    i = dx.ReferenceIndex()
    i.index("allow", [dx.RefLocation("a.py", 10), dx.RefLocation("b.py", 3),
                      dx.RefLocation("a.py", 10)])
    return i


def test_references_deduped():
    refs = _idx().references("allow")
    assert len(refs) == 2
    assert refs[0] == dx.RefLocation("a.py", 10)


def test_count():
    assert _idx().count("allow") == 2


def test_empty_refs_allowed():
    i = dx.ReferenceIndex()
    i.index("unused", [])
    assert i.references("unused") == []


def test_unknown_raises():
    with pytest.raises(dx.ReferencesError):
        _idx().references("nope")


def test_bad_ref_raises():
    i = dx.ReferenceIndex()
    with pytest.raises(dx.ReferencesError):
        i.index("x", [dx.RefLocation("a.py", 0)])


def test_symbols_listed():
    assert _idx().symbols == ["allow"]


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX15_REFERENCES_VERSION == "dx-find-refs.v1"
