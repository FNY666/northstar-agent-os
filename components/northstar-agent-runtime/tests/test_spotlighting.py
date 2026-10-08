"""Spotlighting tests."""

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


sl = _load("spotlighting")


def test_generate_nonce():
    n1 = sl.generate_nonce()
    n2 = sl.generate_nonce()
    assert n1 != n2  # unguessable, unique
    assert len(n1) == 16


def test_generate_nonce_rejects_short():
    with pytest.raises(sl.SpotlightingError):
        sl.generate_nonce(nbytes=4)


def test_delimit():
    marked = sl.delimit("data", "abc123")
    assert "<untrusted_data nonce=abc123>" in marked
    assert "data" in marked
    assert "</untrusted_data>" in marked


def test_delimit_rejects_empty_nonce():
    with pytest.raises(sl.SpotlightingError):
        sl.delimit("data", "")


def test_datamark():
    marked = sl.datamark("hello world", "n1")
    assert "[n1]" in marked
    assert "hello" in marked


def test_encode_b64():
    marked = sl.encode_b64("secret data", "n1")
    assert "encoding=base64" in marked
    assert "secret data" not in marked  # not plaintext
    # But decodable.
    import base64

    b64_part = marked.split("\n")[1]
    assert base64.b64decode(b64_part).decode() == "secret data"


def test_spotlight_levels():
    for level in ("delimit", "datamark", "base64"):
        marked, nonce = sl.spotlight("test", level=level)
        assert nonce
        assert "untrusted_data" in marked


def test_spotlight_rejects_bad_level():
    with pytest.raises(sl.SpotlightingError):
        sl.spotlight("test", level="invalid")


def test_spotlight_accepts_nonce():
    marked, nonce = sl.spotlight("test", nonce="fixed123")
    assert nonce == "fixed123"
    assert "fixed123" in marked


def test_stdlib_only():
    assert sl.stdlib_only() is True


def test_version_pin():
    assert sl.SPOTLIGHTING_VERSION == "spotlighting.v1"
