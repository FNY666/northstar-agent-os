"""Tests for proto_23 (POP3 (mock))."""

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


m = _load("proto_23")

def test_parse():
    assert m.parse_pop3_line("RETR 1") == ("RETR", "1")


def test_unknown():
    with pytest.raises(m.Proto23Error):
        m.parse_pop3_line("HACK")


def test_multiline_dot_stuffing():
    assert m.parse_multiline(["..x", "."]) == [".x"]


def test_unterminated():
    with pytest.raises(m.Proto23Error):
        m.parse_multiline(["a", "b"])


def test_stdlib_only():
    assert m.stdlib_only() is True

