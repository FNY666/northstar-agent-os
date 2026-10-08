"""Tests for dx_07 code generation."""
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

dx = _load("dx_07")


def _gen():
    g = dx.CodeGenerator()
    g.add(dx.Template("fn", "def {{name}}():\n    return {{value}}\n"))
    return g


def test_renders():
    out = _gen().generate("fn", {"name": "f", "value": "1"})
    assert out == "def f():\n    return 1\n"


def test_missing_placeholder_raises():
    with pytest.raises(dx.CodegenError):
        _gen().generate("fn", {"name": "f"})


def test_unknown_key_raises():
    with pytest.raises(dx.CodegenError):
        _gen().generate("fn", {"name": "f", "value": "1", "extra": "x"})


def test_unknown_template_raises():
    with pytest.raises(dx.CodegenError):
        _gen().generate("nope", {})


def test_placeholders_listed():
    assert dx.CodeGenerator.placeholders("a {{x}} b {{ y }}") == {"x", "y"}


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX07_CODEGEN_VERSION == "dx-codegen.v1"
