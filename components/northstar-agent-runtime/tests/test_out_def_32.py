"""LSB steganography detection tests."""

import importlib.util
import random
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


d32 = _load("out_def_32")


def test_uniform_lsb_plane_flagged():
    # Exactly 50/50 bit mix -> chi2 ~ 0 -> flagged.
    data = bytes([0x00, 0x01] * 64)
    ok, reason = d32.detect_lsb_stego(data)
    assert ok is False
    assert "uniform" in reason


def test_repeating_pattern_flagged():
    # Non-uniform but repeating packed byte (0xF8) -> pattern flag.
    data = bytes([0x01] * 5 + [0x00] * 3) * 16
    ok, reason = d32.detect_lsb_stego(data)
    assert ok is False
    assert "run" in reason


def test_random_noise_clean():
    rnd = random.Random(20261009)
    data = bytes(rnd.randrange(256) for _ in range(512))
    ok, _ = d32.detect_lsb_stego(data)
    assert ok is True


def test_lsb_plane_extraction():
    packed = d32.lsb_plane(bytes([0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00]))
    assert packed == bytes([0b10101010])


def test_short_data_passes():
    ok, reason = d32.detect_lsb_stego(b"\x00\x01")
    assert ok is True
    assert "insufficient" in reason


def test_non_bytes_fail_closed():
    try:
        d32.detect_lsb_stego("not bytes")
    except d32.OutDef32Error:
        pass
    else:
        raise AssertionError("non-bytes input should fail closed")


def test_stdlib_only():
    assert d32.stdlib_only() is True


def test_version_pin():
    assert d32.OUT_DEF_32_VERSION == "out-def-32.v1"
    assert d32.SCHEMA_PIN == "northstar.out-def-32.v1"
