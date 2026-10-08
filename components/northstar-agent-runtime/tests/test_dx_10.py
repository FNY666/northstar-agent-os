"""Tests for dx_10 snippets."""
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

dx = _load("dx_10")


def _store():
    s = dx.SnippetStore()
    s.add(dx.Snippet("for", "for ${1:i} in ${2:items}:\n    ${0:pass}"))
    return s


def test_expand():
    assert _store().expand("for", {"1": "k", "2": "rows"}) == "for k in rows:\n    pass"


def test_defaults_used():
    s = dx.SnippetStore()
    s.add(dx.Snippet("x", "a=${1:1}"))
    assert s.expand("x", {"1": "2"}) == "a=2"
    assert s.expand("x", {"1": "1"}) == "a=1"


def test_missing_tabstop_raises():
    with pytest.raises(dx.SnippetError):
        _store().expand("for", {"1": "k"})


def test_unknown_snippet_raises():
    with pytest.raises(dx.SnippetError):
        _store().expand("nope", {})


def test_conflicting_defaults_raise():
    s = dx.SnippetStore()
    with pytest.raises(dx.SnippetError):
        s.add(dx.Snippet("bad", "${1:a} ${1:b}"))


def test_tab_stops_listed():
    assert dx.SnippetStore.tab_stops("a ${1:x} b ${2} c ${0}") == {"1", "2"}


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX10_SNIPPETS_VERSION == "dx-snippets.v1"
