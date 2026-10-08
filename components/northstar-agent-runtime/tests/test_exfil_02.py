"""ICMP exfiltration detection tests."""

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


m = _load("exfil_02")

def test_benign():
    ok, _ = m.detect_icmp_exfil(8, b"\x00" * 32)
    assert ok is False


def test_oversized():
    ok, reason = m.detect_icmp_exfil(8, b"A" * 200)
    assert ok is True
    assert "oversized" in reason


def test_high_entropy():
    import os
    ok, _ = m.detect_icmp_exfil(8, os.urandom(48))
    assert ok is True


def test_bad_payload_raises():
    import pytest
    with pytest.raises(m.Exfil02Error):
        m.detect_icmp_exfil(8, "not-bytes")


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_02_VERSION == "exfil-02.v1"
