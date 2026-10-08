"""Social media exfiltration detection tests."""

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


m = _load("exfil_17")

def test_benign():
    ok, _ = m.detect_social_exfil("Had a great lunch!")
    assert ok is False


def test_ssn():
    ok, reason = m.detect_social_exfil("ssn 123-45-6789 here")
    assert ok is True
    assert "SSN" in reason


def test_internal_host():
    ok, _ = m.detect_social_exfil("see api.internal.corp")
    assert ok is True


def test_bad_type():
    import pytest
    with pytest.raises(m.Exfil17Error):
        m.detect_social_exfil(42)


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_17_VERSION == "exfil-17.v1"
