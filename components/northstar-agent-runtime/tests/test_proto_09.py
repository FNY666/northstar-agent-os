"""Tests for proto_09 (URL)."""

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


m = _load("proto_09")

def test_components():
    u = m.parse_url("https://user@h.com/p?q=1")
    assert (u["scheme"], u["host"], u["path"]) == ("https", "h.com", "/p")


def test_query_dict():
    assert m.parse_url("http://h/?a=1&a=2")["query"] == {"a": "2"}


def test_no_host_rejected():
    ok, _ = m.validate_url("notaurl")
    assert ok is False


def test_require_https():
    ok, _ = m.validate_url("http://h/", require_https=True)
    assert ok is False
    ok, _ = m.validate_url("https://h/", require_https=True)
    assert ok is True


def test_stdlib_only():
    assert m.stdlib_only() is True

