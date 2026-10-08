"""util_30 tests."""

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


m = _load("util_30")

def test_zlib_roundtrip():
    data = b"hello " * 50
    assert m.zlib_decompress(m.zlib_compress(data)) == data


def test_gzip_roundtrip():
    data = b"world " * 50
    assert m.gunzip_bytes(m.gzip_bytes(data)) == data


def test_ratio():
    data = b"a" * 1000
    assert m.compression_ratio(data, m.zlib_compress(data)) < 0.1
    assert m.compression_ratio(b"", b"") == 0.0


def test_bad_data():
    import pytest
    with pytest.raises(m.CompressionError):
        m.zlib_decompress(b"junk")


def test_stdlib_only():
    assert m.stdlib_only() is True
