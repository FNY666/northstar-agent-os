"""QR code exfiltration detection (mock) tests."""

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


m = _load("exfil_15")

def test_benign():
    ok, _ = m.detect_qr_exfil("https://example.com/menu")
    assert ok is False


def test_oversized():
    ok, reason = m.detect_qr_exfil("x" * 600)
    assert ok is True
    assert "oversized" in reason


def test_sensitive():
    ok, _ = m.detect_qr_exfil("key sk-abcdefghijklmnopqrst")
    assert ok is True


def test_bad_type():
    import pytest
    with pytest.raises(m.Exfil15Error):
        m.detect_qr_exfil(123)


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_15_VERSION == "exfil-15.v1"
