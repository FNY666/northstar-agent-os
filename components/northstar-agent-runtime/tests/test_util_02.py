"""util_02 tests."""

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


m = _load("util_02")

def test_b64_roundtrip():
    assert m.b64decode_text(m.b64encode_text("hello world")) == "hello world"


def test_b64_known():
    assert m.b64encode_text("hello") == "aGVsbG8="


def test_b64_bad():
    import pytest
    with pytest.raises(m.EncodingError):
        m.b64decode_text("!!!")


def test_hex_url_roundtrip():
    assert m.hex_decode(m.hex_encode(b"abc")) == b"abc"
    assert m.url_decode(m.url_encode("a b/c?d=e")) == "a b/c?d=e"


def test_stdlib_only():
    assert m.stdlib_only() is True
