"""Steganography detection (mock) tests."""

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


m = _load("exfil_05")

def test_clean_jpeg():
    ok, _ = m.detect_stego_appended(b"\xff\xd8\xff\xd9", "jpeg")
    assert ok is False


def test_appended_jpeg():
    ok, reason = m.detect_stego_appended(b"\xff\xd8\xff\xd9" + b"X" * 20, "jpeg")
    assert ok is True
    assert "after JPEG EOI" in reason


def test_appended_png():
    png = b"\x89PNG" + b"\x49\x45\x4E\x44\xAE\x42\x60\x82" + b"Y" * 5
    ok, _ = m.detect_stego_appended(png, "png")
    assert ok is True


def test_bad_fmt():
    import pytest
    with pytest.raises(m.Exfil05Error):
        m.detect_stego_appended(b"data", "gif")


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_05_VERSION == "exfil-05.v1"
