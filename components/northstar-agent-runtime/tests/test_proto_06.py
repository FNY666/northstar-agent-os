"""Tests for proto_06 (INI)."""

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


m = _load("proto_06")

def test_sections():
    assert m.parse_ini("[a]\nx=1\n") == {"a": {"x": "1"}}


def test_required_sections():
    ok, _ = m.validate_ini("[a]\nx=1\n", ["a"])
    assert ok is True
    ok, reason = m.validate_ini("[a]\nx=1\n", ["b"])
    assert ok is False and "missing" in reason


def test_bad_ini_rejected():
    ok, _ = m.validate_ini("[unclosed\n")
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

