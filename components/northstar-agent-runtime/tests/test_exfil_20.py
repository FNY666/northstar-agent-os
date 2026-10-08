"""Cookie tossing detection tests."""

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


m = _load("exfil_20")

def test_benign():
    ok, _ = m.detect_cookie_tossing({"name": "s", "domain": "sub.example.com", "set_by": "sub.example.com"})
    assert ok is False


def test_tossing():
    ok, reason = m.detect_cookie_tossing({"name": "sid", "domain": "example.com", "set_by": "evil.example.com"})
    assert ok is True
    assert "tossing" in reason


def test_host_prefix_exempt():
    ok, _ = m.detect_cookie_tossing({"name": "__Host-s", "domain": "example.com", "set_by": "sub.example.com"})
    assert ok is False


def test_missing_fields():
    import pytest
    with pytest.raises(m.Exfil20Error):
        m.detect_cookie_tossing({"name": "s"})


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_20_VERSION == "exfil-20.v1"
