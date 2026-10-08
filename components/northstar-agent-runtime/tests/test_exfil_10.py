"""Search query exfiltration detection tests."""

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


m = _load("exfil_10")

def test_benign():
    ok, _ = m.detect_search_exfil("best pizza near me")
    assert ok is False


def test_ssn():
    ok, reason = m.detect_search_exfil("lookup 123-45-6789")
    assert ok is True
    assert "SSN" in reason


def test_api_key():
    ok, _ = m.detect_search_exfil("key sk-abcdefghijklmnopqrst")
    assert ok is True


def test_bad_type():
    import pytest
    with pytest.raises(m.Exfil10Error):
        m.detect_search_exfil(None)


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_10_VERSION == "exfil-10.v1"
