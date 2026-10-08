"""Email header injection detection tests."""

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


m = _load("exfil_18")

def test_benign():
    ok, _ = m.detect_email_header_injection({"Subject": "hello"})
    assert ok is False


def test_bcc_injection():
    ok, reason = m.detect_email_header_injection({"Subject": "hi\r\nBcc: e@x.com"})
    assert ok is True
    assert "injection" in reason


def test_bare_crlf():
    ok, _ = m.detect_email_header_injection({"X-Note": "a\nb"})
    assert ok is True


def test_bad_type():
    import pytest
    with pytest.raises(m.Exfil18Error):
        m.detect_email_header_injection("nope")


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_18_VERSION == "exfil-18.v1"
