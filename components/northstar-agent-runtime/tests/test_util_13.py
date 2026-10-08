"""util_13 tests."""

import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("util_13")

def test_email():
    assert m.is_email("a@b.com") is True
    assert m.is_email("bad@") is False
    assert m.is_email("") is False


def test_url():
    assert m.is_url("https://x.com/p") is True
    assert m.is_url("notaurl") is False


def test_e164():
    assert m.is_e164("+14155552671") is True
    assert m.is_e164("123") is False


def test_uuid_hex():
    assert m.is_uuid("12345678-1234-5678-1234-567812345678") is True
    assert m.is_uuid("nope") is False
    assert m.is_hex("deadbeef", length=8) is True
    assert m.is_hex("zz") is False


def test_stdlib_only():
    assert m.stdlib_only() is True
