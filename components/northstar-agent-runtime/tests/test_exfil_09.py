"""Cache poisoning detection tests."""

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


m = _load("exfil_09")

def test_benign():
    ok, _ = m.detect_cache_poisoning("k", {"utm": "x"}, "<html></html>")
    assert ok is False


def test_reflected():
    ok, reason = m.detect_cache_poisoning("k", {"x": "EVIL"}, "body EVIL")
    assert ok is True
    assert "reflected" in reason


def test_delimiter():
    ok, _ = m.detect_cache_poisoning("k;bad", {}, "body")
    assert ok is True


def test_bad_types():
    import pytest
    with pytest.raises(m.Exfil09Error):
        m.detect_cache_poisoning(1, {}, "")


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_09_VERSION == "exfil-09.v1"
