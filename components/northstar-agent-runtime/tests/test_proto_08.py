"""Tests for proto_08 (HTTP headers)."""

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


m = _load("proto_08")

def test_request():
    msg = m.parse_http_message("POST /p HTTP/1.1\nHost: h\n\n")
    assert msg["start_line"] == "POST /p HTTP/1.1"
    assert msg["headers"]["host"] == "h"


def test_response():
    msg = m.parse_http_message("HTTP/1.1 404 Not Found\n\n")
    assert msg["kind"] == "response"


def test_bad_header_rejected():
    with pytest.raises(m.Proto08Error):
        m.parse_http_message("GET / HTTP/1.1\nNoColonHere\n\n")


def test_required_headers():
    ok, reason = m.validate_headers({"host": "x"}, ["host", "authorization"])
    assert ok is False and "authorization" in reason


def test_stdlib_only():
    assert m.stdlib_only() is True

