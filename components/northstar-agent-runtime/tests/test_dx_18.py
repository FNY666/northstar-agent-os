"""Tests for dx_18. formatters."""
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

dx = _load("dx_18")

def _reg():
    r = dx.FormatterRegistry()
    r.register("collapse", lambda s: " ".join(s.split()))
    return r


def test_format():
    assert _reg().format_text("collapse", "a   b\n") == "a b"


def test_unknown_formatter_raises():
    with pytest.raises(dx.FormattersError):
        _reg().format_text("nope", "x")


def test_non_idempotent_rejected():
    r = dx.FormatterRegistry()
    with pytest.raises(dx.FormattersError):
        r.register("grow", lambda s: s + " ")


def test_duplicate_rejected():
    r = _reg()
    with pytest.raises(dx.FormattersError):
        r.register("collapse", str.strip)


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX18_FORMATTERS_VERSION == "dx-formatters.v1"
