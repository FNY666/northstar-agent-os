"""Video metadata scrubber tests."""

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


m44 = _load("out_def_44")


def _box(btype, payload):
    return (8 + len(payload)).to_bytes(4, "big") + btype + payload


def test_meta_boxes_removed():
    inner = _box(b"uuid", b"1" * 8) + _box(b"mvhd", b"\x00" * 8)
    mp4 = _box(b"moov", inner) + _box(b"mdat", b"PAYLOAD")
    cleaned, removed = m44.clean_video_metadata(mp4)
    assert removed == 1
    assert b"uuid" not in cleaned
    assert b"mvhd" in cleaned
    assert b"PAYLOAD" in cleaned


def test_xmp_box_removed():
    mp4 = _box(b"XMP_", b"xx") + _box(b"ftyp", b"isom")
    cleaned, removed = m44.clean_video_metadata(mp4)
    assert removed == 1
    assert b"XMP_" not in cleaned
    assert b"ftyp" in cleaned


def test_clean_input_unchanged():
    mp4 = _box(b"ftyp", b"isom") + _box(b"mdat", b"DATA")
    out, removed = m44.clean_video_metadata(mp4)
    assert out == mp4 and removed == 0


def test_malformed_does_not_raise():
    bad = b"\x00\x00\x00\x05ABCDrest"  # size < 8
    out, removed = m44.clean_video_metadata(bad)
    assert out == bad and removed == 0
    bad = b"\x00\x00\x01\x00ABCD"  # size > remaining
    out, removed = m44.clean_video_metadata(bad)
    assert out == bad and removed == 0
    out, removed = m44.clean_video_metadata(b"")
    assert out == b"" and removed == 0


def test_stdlib_only():
    assert m44.stdlib_only() is True


def test_version_pin():
    assert m44.OUT_DEF_44_VERSION == "out-def-44.v1"
    assert m44.SCHEMA_PIN == "northstar.out-def-44.v1"
