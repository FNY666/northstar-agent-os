"""Image metadata scrubber tests."""

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


m42 = _load("out_def_42")


def _chunk(ctype, payload):
    return len(payload).to_bytes(4, "big") + ctype + payload + b"\x00" * 4


def _seg(marker, payload):
    return b"\xFF" + bytes([marker]) + (2 + len(payload)).to_bytes(2, "big") + payload


def test_png_text_chunks_removed():
    png = (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", b"\x00" * 13)
        + _chunk(b"tEXt", b"Title\x00hello")
        + _chunk(b"zTXt", b"Comment\x00\x01\x02")
        + _chunk(b"IEND", b"")
    )
    cleaned, removed = m42.clean_image_metadata(png)
    assert removed == 2
    assert b"tEXt" not in cleaned
    assert b"zTXt" not in cleaned
    assert b"IHDR" in cleaned
    assert b"IEND" in cleaned
    assert cleaned.startswith(b"\x89PNG\r\n\x1a\n")


def test_jpeg_com_removed():
    jpeg = (
        b"\xFF\xD8"
        + _seg(0xE0, b"JFIF\x00")
        + _seg(0xFE, b"secret comment")
        + b"\xFF\xD9"
    )
    cleaned, removed = m42.clean_image_metadata(jpeg)
    assert removed == 1
    assert b"secret comment" not in cleaned
    assert b"JFIF" in cleaned
    assert cleaned.startswith(b"\xFF\xD8")
    assert cleaned.endswith(b"\xFF\xD9")


def test_clean_input_unchanged():
    png = b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", b"\x00" * 13) + _chunk(b"IEND", b"")
    out, removed = m42.clean_image_metadata(png)
    assert out == png and removed == 0
    out, removed = m42.clean_image_metadata(b"not an image")
    assert out == b"not an image" and removed == 0


def test_malformed_does_not_raise():
    bad_png = b"\x89PNG\r\n\x1a\n" + (1000).to_bytes(4, "big") + b"tEXt" + b"short"
    out, removed = m42.clean_image_metadata(bad_png)
    assert out == bad_png and removed == 0
    out, removed = m42.clean_image_metadata(b"\xFF\xD8\x00")
    assert out == b"\xFF\xD8\x00" and removed == 0
    out, removed = m42.clean_image_metadata(b"")
    assert out == b"" and removed == 0


def test_stdlib_only():
    assert m42.stdlib_only() is True


def test_version_pin():
    assert m42.OUT_DEF_42_VERSION == "out-def-42.v1"
    assert m42.SCHEMA_PIN == "northstar.out-def-42.v1"
