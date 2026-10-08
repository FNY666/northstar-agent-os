"""Log injection exfiltration detection tests."""

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


m = _load("exfil_08")

def test_benign():
    ok, _ = m.detect_log_injection("2024-01-01 INFO ok")
    assert ok is False


def test_newline():
    ok, reason = m.detect_log_injection("a\nb")
    assert ok is True
    assert "newline" in reason


def test_ansi():
    ok, _ = m.detect_log_injection("x \x1b[2K y")
    assert ok is True


def test_bad_type():
    import pytest
    with pytest.raises(m.Exfil08Error):
        m.detect_log_injection(123)


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_08_VERSION == "exfil-08.v1"
