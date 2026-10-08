"""Audio metadata scrubber tests."""

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


m43 = _load("out_def_43")

_ID3V2 = b"ID3\x04\x00\x00" + bytes([0, 0, 0, 10]) + b"X" * 10
_ID3V1 = b"TAG" + b"Y" * 125


def test_id3v2_and_v1_removed():
    data = _ID3V2 + b"AUDIOBYTES" + _ID3V1
    cleaned, removed = m43.clean_audio_metadata(data)
    assert removed == 2
    assert cleaned == b"AUDIOBYTES"


def test_id3v2_only():
    cleaned, removed = m43.clean_audio_metadata(_ID3V2 + b"DATA")
    assert removed == 1
    assert cleaned == b"DATA"


def test_id3v1_only():
    cleaned, removed = m43.clean_audio_metadata(b"DATA" + _ID3V1)
    assert removed == 1
    assert cleaned == b"DATA"


def test_clean_input_unchanged():
    data = b"RIFF....WAVEfmt "
    out, removed = m43.clean_audio_metadata(data)
    assert out == data and removed == 0


def test_malformed_does_not_raise():
    bads = [
        b"",
        b"ID3",
        b"ID3\x04\x00",
        b"ID3\x04\x00\x00\xff\x00\x00\x00rest",  # invalid syncsafe byte
        b"ID3\x04\x00\x00" + bytes([0, 0, 7, 0]),  # body longer than buffer
    ]
    for bad in bads:
        out, removed = m43.clean_audio_metadata(bad)
        assert out == bad and removed == 0, bad


def test_stdlib_only():
    assert m43.stdlib_only() is True


def test_version_pin():
    assert m43.OUT_DEF_43_VERSION == "out-def-43.v1"
    assert m43.SCHEMA_PIN == "northstar.out-def-43.v1"
