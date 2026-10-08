"""util_31 tests."""

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


m = _load("util_31")

def test_crc32_vector():
    assert m.crc32_hex(b"123456789") == "cbf43926"


def test_adler32_vector():
    assert m.adler32_hex(b"123456789") == "091e10f5"


def test_verify():
    assert m.verify_crc32(b"abc", m.crc32_hex(b"abc")) is True
    assert m.verify_crc32(b"abc", "00000000") is False
    assert m.verify_crc32(b"abc", m.crc32_hex(b"abc").upper()) is True


def test_stdlib_only():
    assert m.stdlib_only() is True
