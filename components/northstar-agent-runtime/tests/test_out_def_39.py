"""EXIF data stripping defense tests (D-OUT-039)."""

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


m = _load("out_def_39")


def _segment(marker, payload):
    length = len(payload) + 2
    return bytes([0xFF, marker]) + length.to_bytes(2, "big") + payload


def _fake_jpeg():
    exif_app1 = _segment(0xE1, b"Exif\x00\x00" + b"II*\x00fake-ifd")
    jfif_app0 = _segment(0xE0, b"JFIF\x00" + b"\x01\x02")
    return (
        b"\xff\xd8"
        + exif_app1
        + jfif_app0
        + bytes([0xFF, 0xDA])
        + b"\x00\x3f\x00"
        + bytes([0xFF, 0xD9])
    )


def test_exif_segment_stripped():
    cleaned, removed = m.strip_exif(_fake_jpeg())
    assert removed == 1
    assert b"Exif\x00\x00" not in cleaned
    assert b"JFIF" in cleaned  # non-EXIF APPn preserved


def test_no_exif_untouched():
    plain = b"\xff\xd8" + _segment(0xE0, b"JFIF\x00") + bytes([0xFF, 0xD9])
    cleaned, removed = m.strip_exif(plain)
    assert removed == 0
    assert cleaned == plain


def test_truncated_fail_closed():
    truncated = b"\xff\xd8" + bytes([0xFF, 0xE1, 0x00])
    cleaned, removed = m.strip_exif(truncated)
    assert removed == 0
    assert cleaned == truncated


def test_bad_length_fail_closed():
    bad = b"\xff\xd8" + bytes([0xFF, 0xE1, 0x00, 0x01]) + b"\xff\xd9"
    cleaned, removed = m.strip_exif(bad)
    assert removed == 0
    assert cleaned == bad


def test_non_jpeg_passthrough():
    cleaned, removed = m.strip_exif(b"hello world")
    assert removed == 0
    assert cleaned == b"hello world"


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.OUT_DEF_39_VERSION == "out-def-39.v1"
    assert m.SCHEMA_PIN == "northstar.out-def-39.v1"
