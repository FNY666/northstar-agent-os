"""Clipboard hijacking detection (mock) tests."""

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


m = _load("exfil_12")

def test_benign():
    ok, _ = m.detect_clipboard_hijack([{"action": "write", "user_gesture": True}])
    assert ok is False


def test_write_no_gesture():
    ok, reason = m.detect_clipboard_hijack([{"action": "write", "user_gesture": False}])
    assert ok is True
    assert "without gesture" in reason


def test_many_reads():
    evs = [{"action": "read", "user_gesture": False}] * 4
    ok, _ = m.detect_clipboard_hijack(evs)
    assert ok is True


def test_bad_input():
    import pytest
    with pytest.raises(m.Exfil12Error):
        m.detect_clipboard_hijack("nope")


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_12_VERSION == "exfil-12.v1"
