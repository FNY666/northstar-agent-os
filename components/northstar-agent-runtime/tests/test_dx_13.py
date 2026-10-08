"""Tests for dx_13 hover docs."""
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

dx = _load("dx_13")


def _h():
    h = dx.HoverDocs()
    h.add(dx.HoverDoc(symbol="allow", signature="allow(tool, args) -> bool",
                      docs="Gate allow."))
    return h


def test_lookup():
    doc = _h().hover("allow")
    assert doc is not None and doc.signature.startswith("allow(")


def test_unknown_returns_none():
    assert _h().hover("nope") is None
    assert _h().render_markdown("nope") is None


def test_markdown_render():
    md = _h().render_markdown("allow")
    assert md is not None and "```" in md and "Gate allow." in md


def test_empty_symbol_raises():
    with pytest.raises(dx.HoverError):
        _h().hover("")


def test_bad_add_raises():
    h = dx.HoverDocs()
    with pytest.raises(dx.HoverError):
        h.add(dx.HoverDoc(symbol="", signature="s", docs="d"))


def test_symbols_listed():
    assert _h().symbols == ["allow"]


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX13_HOVER_VERSION == "dx-hover.v1"
