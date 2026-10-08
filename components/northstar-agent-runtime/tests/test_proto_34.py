"""Tests for proto_34 (STOMP (mock))."""

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


m = _load("proto_34")

def test_frame():
    f = m.parse_stomp("CONNECT\nlogin:u\npass:p\n\n\x00")
    assert f["command"] == "CONNECT"
    assert f["headers"] == {"login": "u", "pass": "p"}


def test_missing_nul():
    with pytest.raises(m.Proto34Error):
        m.parse_stomp("SEND\n\nbody")


def test_bad_header_line():
    with pytest.raises(m.Proto34Error):
        m.parse_stomp("SEND\nno-colon\n\n\x00")


def test_command_allowlist():
    ok, _ = m.validate_stomp("SEND\n\nx\x00", ["SEND"])
    assert ok is True
    ok, _ = m.validate_stomp("SEND\n\nx\x00", ["ACK"])
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

