"""Tests for dx_19. linters."""
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

dx = _load("dx_19")

def _reg():
    r = dx.LintRegistry()
    r.register(dx.LintRule("no-todo", "warning", r"\bTODO\b", "TODO left"))
    r.register(dx.LintRule("no-trail", "info", r" +$", "trailing ws"))
    return r


def test_lint_order():
    out = _reg().lint("x = 1  \n# TODO fix\n")
    assert [(v.line, v.rule_id) for v in out] == [(1, "no-trail"), (2, "no-todo")]


def test_clean_no_violations():
    assert _reg().lint("clean = 1\n") == []


def test_bad_regex_raises():
    r = dx.LintRegistry()
    with pytest.raises(dx.LintersError):
        r.register(dx.LintRule("bad", "warning", r"(unclosed", "x"))


def test_bad_severity_raises():
    r = dx.LintRegistry()
    with pytest.raises(dx.LintersError):
        r.register(dx.LintRule("s", "fatal", r"x", "x"))


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX19_LINTERS_VERSION == "dx-linters.v1"
