"""DNS tunneling detection tests."""

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


m = _load("exfil_01")

def test_benign():
    ok, _ = m.detect_dns_tunnel("www.example.com")
    assert ok is False


def test_long_label():
    ok, reason = m.detect_dns_tunnel("a" * 60 + ".example.com")
    assert ok is True
    assert "long" in reason


def test_high_entropy():
    ok, _ = m.detect_dns_tunnel("x8f2k9q1m4n7b3v6c0p5s2d9f4g7h1j3k5.example.com")
    assert ok is True


def test_empty_raises():
    import pytest
    with pytest.raises(m.Exfil01Error):
        m.detect_dns_tunnel("")


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_01_VERSION == "exfil-01.v1"
