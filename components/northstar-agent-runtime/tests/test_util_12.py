"""util_12 tests."""

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


m = _load("util_12")

def test_hmac_vector():
    assert m.hmac_sha256_hex(b"key", b"The quick brown fox jumps over the lazy dog") == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"


def test_verify_hmac():
    mac = m.hmac_sha256_hex(b"k", b"m")
    assert m.verify_hmac(b"k", b"m", mac) is True
    assert m.verify_hmac(b"k", b"m", "00" * 32) is False


def test_pbkdf2():
    h1 = m.pbkdf2_hex("pw", b"salt", iterations=1000)
    assert len(h1) == 64
    assert m.pbkdf2_hex("pw", b"salt", iterations=1000) == h1
    assert m.pbkdf2_hex("pw", b"other", iterations=1000) != h1


def test_new_salt():
    assert len(m.new_salt(16)) == 16
    assert m.new_salt(16) != m.new_salt(16)


def test_stdlib_only():
    assert m.stdlib_only() is True
