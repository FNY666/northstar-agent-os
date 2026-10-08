"""Tests for proto_24 (FTP (mock))."""

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


m = _load("proto_24")

def test_single_line():
    r = m.parse_reply("200 OK\n")
    assert r["code"] == 200 and r["lines"] == ["OK"]


def test_multiline():
    r = m.parse_reply("220-a\n220-b\n220 c\n")
    assert r["lines"] == ["a", "220-b", "220 c"]


def test_unterminated():
    with pytest.raises(m.Proto24Error):
        m.parse_reply("220-a\n220-b\n")


def test_bad_code():
    with pytest.raises(m.Proto24Error):
        m.parse_reply("OK no code\n")


def test_stdlib_only():
    assert m.stdlib_only() is True

