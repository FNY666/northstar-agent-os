"""Tests for proto_21 (SMTP (mock))."""

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


m = _load("proto_21")

def test_parse_line():
    assert m.parse_smtp_line("rcpt to:<x@y>") == ("RCPT", "to:<x@y>")


def test_unknown_command():
    with pytest.raises(m.Proto21Error):
        m.parse_smtp_line("HACK x")


def test_valid_sequence():
    ok, _ = m.validate_sequence(["HELO h", "MAIL FROM:<a>", "RCPT TO:<b>",
                                 "RCPT TO:<c>", "DATA", "body", "QUIT"])
    assert ok is True


def test_out_of_order():
    ok, reason = m.validate_sequence(["RCPT TO:<b>"])
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

