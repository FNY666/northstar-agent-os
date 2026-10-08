"""Tests for proto_10 (URI)."""

import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("proto_10")

def test_mailto():
    u = m.parse_uri("mailto:a@b.com")
    assert u["scheme"] == "mailto"


def test_relative():
    u = m.parse_uri("/p?q=1#f")
    assert u["absolute"] is False and u["path"] == "/p"


def test_empty_rejected():
    with pytest.raises(m.Proto10Error):
        m.parse_uri("")


def test_space_rejected():
    ok, _ = m.validate_uri("http://x/a b")
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

