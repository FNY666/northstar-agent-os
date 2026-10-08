"""Tests for proto_22 (IMAP (mock))."""

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


m = _load("proto_22")

def test_parse():
    p = m.parse_imap_line("t1 FETCH 1 BODY[]")
    assert p["tag"] == "t1" and p["command"] == "FETCH"


def test_unknown_command():
    with pytest.raises(m.Proto22Error):
        m.parse_imap_line("t1 HACK")


def test_duplicate_tag():
    ok, reason = m.validate_tags(["a NOOP", "a NOOP"])
    assert ok is False and "duplicate" in reason


def test_star_tag_allowed_twice():
    ok, _ = m.validate_tags(["* NOOP", "* NOOP"])
    assert ok is True


def test_stdlib_only():
    assert m.stdlib_only() is True

