"""HTTP header smuggling detection tests."""

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


m = _load("exfil_03")

def test_benign():
    ok, _ = m.detect_header_smuggling({"Content-Type": "text/html"})
    assert ok is False


def test_sensitive_in_custom():
    ok, reason = m.detect_header_smuggling({"X-Data": "api_key=sk-abc123"})
    assert ok is True
    assert "sensitive" in reason


def test_crlf():
    ok, _ = m.detect_header_smuggling({"X-A": "a\r\nB: b"})
    assert ok is True


def test_duplicate():
    ok, _ = m.detect_header_smuggling({"X-A": "1", "x-a": "2"})
    assert ok is True


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_03_VERSION == "exfil-03.v1"
