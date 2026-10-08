"""Tests for proto_05 (CSV)."""

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


m = _load("proto_05")

def test_quoted_comma():
    rows = m.parse_csv('a\n"x,y"\n')
    assert rows == [["a"], ["x,y"]]


def test_records():
    assert m.csv_records("k,v\n1,2\n") == [{"k": "1", "v": "2"}]


def test_ragged_rejected():
    ok, reason = m.validate_csv("a,b\n1\n")
    assert ok is False and "cols" in reason


def test_header_check():
    ok, _ = m.validate_csv("a,b\n1,2\n", ["a", "b"])
    assert ok is True
    ok, _ = m.validate_csv("a,b\n1,2\n", ["x", "y"])
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

