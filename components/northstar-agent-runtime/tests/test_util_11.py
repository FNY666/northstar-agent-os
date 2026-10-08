"""util_11 tests."""

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


m = _load("util_11")

def test_parse_url():
    info = m.parse_url("https://example.com:8080/a?x=1")
    assert info["host"] == "example.com"
    assert info["port"] == 8080
    assert info["query"] == {"x": "1"}


def test_is_http_url():
    assert m.is_http_url("https://x.com") is True
    assert m.is_http_url("http://x.com/p") is True
    assert m.is_http_url("ftp://x.com") is False
    assert m.is_http_url("not a url") is False


def test_join_and_domain():
    assert m.join_url("https://x.com/a", "b") == "https://x.com/a/b"
    assert m.get_domain("https://sub.x.com/p") == "sub.x.com"


def test_with_query():
    out = m.with_query("https://x.com/?y=1", {"y": 2, "z": 3})
    assert "y=2" in out and "z=3" in out


def test_stdlib_only():
    assert m.stdlib_only() is True
