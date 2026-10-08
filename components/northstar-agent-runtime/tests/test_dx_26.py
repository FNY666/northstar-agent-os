"""Tests for dx_26. api docs."""
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

dx = _load("dx_26")

def _cat():
    c = dx.DocCatalog()
    c.document(dx.DocEntry("allow", "(tool, args)", "Allow a tool call."))
    c.document(dx.DocEntry("todo", "(x)", ""))
    return c


def test_markdown_render():
    md = _cat().render("allow")
    assert md.startswith("## `allow(tool, args)`")
    assert "Allow a tool call." in md


def test_plain_render():
    assert _cat().render("allow", fmt="plain").startswith("allow(tool, args)")


def test_undocumented():
    assert _cat().undocumented() == ["todo"]


def test_render_undocumented_raises():
    with pytest.raises(dx.ApiDocsError):
        _cat().render("todo")


def test_unknown_format_raises():
    with pytest.raises(dx.ApiDocsError):
        _cat().render("allow", fmt="html")


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX26_APIDOCS_VERSION == "dx-apidocs.v1"
