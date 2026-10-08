"""Tests for proto_07 (ENV/dotenv)."""

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


m = _load("proto_07")

def test_quotes_and_export():
    assert m.parse_env('export A="1 2"\nB=\'3\'\n') == {"A": "1 2", "B": "3"}


def test_comments_skipped():
    assert m.parse_env("# hi\nA=1\n") == {"A": "1"}


def test_bad_key_rejected():
    with pytest.raises(m.Proto07Error):
        m.parse_env("9LIVES=x\n")


def test_required():
    ok, reason = m.validate_env("A=1\n", ["A", "B"])
    assert ok is False and "B" in reason


def test_stdlib_only():
    assert m.stdlib_only() is True

