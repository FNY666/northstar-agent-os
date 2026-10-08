"""Tests for dx_09 templates."""
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

dx = _load("dx_09")


def test_render():
    s = dx.TemplateStore()
    s.add("g", "hi {{name}}")
    assert s.render("g", {"name": "ada"}) == "hi ada"


def test_validate_lists_placeholders():
    s = dx.TemplateStore()
    s.add("g", "{{a}} and {{b}}")
    assert s.validate("g") == {"a", "b"}


def test_missing_key_raises():
    s = dx.TemplateStore()
    s.add("g", "{{a}} {{b}}")
    with pytest.raises(dx.TemplateError):
        s.render("g", {"a": "1"})


def test_unknown_key_raises():
    s = dx.TemplateStore()
    s.add("g", "{{a}}")
    with pytest.raises(dx.TemplateError):
        s.render("g", {"a": "1", "z": "2"})


def test_unknown_template_raises():
    with pytest.raises(dx.TemplateError):
        dx.TemplateStore().render("nope", {})


def test_remove():
    s = dx.TemplateStore()
    s.add("g", "x")
    s.remove("g")
    assert s.names == []
    with pytest.raises(dx.TemplateError):
        s.remove("g")


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX09_TEMPLATES_VERSION == "dx-templates.v1"
