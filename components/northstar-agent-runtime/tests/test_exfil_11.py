"""Autocomplete leakage detection tests."""

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


m = _load("exfil_11")

def test_benign():
    ok, _ = m.detect_autocomplete_leak("john smith", "john sm")
    assert ok is False


def test_leaks_phone():
    ok, reason = m.detect_autocomplete_leak("john 555-123-4567", "john ")
    assert ok is True
    assert "phone" in reason


def test_prefix_pii_not_flagged():
    ok, _ = m.detect_autocomplete_leak("555-123-4567 ext", "555-123-4567 ")
    assert ok is False


def test_bad_types():
    import pytest
    with pytest.raises(m.Exfil11Error):
        m.detect_autocomplete_leak(None, "x")


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_11_VERSION == "exfil-11.v1"
