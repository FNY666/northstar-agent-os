"""util_29 tests."""

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


m = _load("util_29")

def test_xor_roundtrip():
    assert m.xor_bytes(m.xor_bytes(b"hello", b"key"), b"key") == b"hello"


def test_concat_split():
    assert m.concat(b"a", b"b", b"c") == b"abc"
    assert m.split_at(b"abcd", 2) == (b"ab", b"cd")


def test_pkcs7():
    assert m.unpad_pkcs7(m.pad_pkcs7(b"hi", 8)) == b"hi"
    assert len(m.pad_pkcs7(b"12345678", 8)) == 16


def test_bad_padding():
    import pytest
    with pytest.raises(m.BytesError):
        m.unpad_pkcs7(b"\x02\x03")


def test_stdlib_only():
    assert m.stdlib_only() is True
