"""Error message leakage detection tests."""

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


m = _load("exfil_07")

def test_benign():
    ok, _ = m.detect_error_leakage("Something went wrong, try again.")
    assert ok is False


def test_traceback():
    ok, reason = m.detect_error_leakage('Traceback (most recent call last):\n  File "a.py", line 1')
    assert ok is True
    assert "traceback" in reason


def test_db_error():
    ok, _ = m.detect_error_leakage("ORA-00942: table or view does not exist")
    assert ok is True


def test_internal_ip():
    ok, _ = m.detect_error_leakage("connection to 192.168.1.10 refused")
    assert ok is True


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_07_VERSION == "exfil-07.v1"
