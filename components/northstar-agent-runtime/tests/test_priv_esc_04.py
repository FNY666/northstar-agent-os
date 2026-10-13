"""Priv-esc 04 tests (toctou-race)."""
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


pe = _load("priv_esc_04")


def test_detect_positive():
    found, _ = pe.detect('toctou race on /tmp/f')
    assert found is True


def test_detect_negative():
    found, _ = pe.detect('normal file access')
    assert found is False


def test_fail_closed():
    import pytest

    with pytest.raises(pe.PrivEscError):
        pe.detect(12345)  # type: ignore


def test_scan_args():
    blocked, _ = pe.scan_args("some_tool", {"cmd": 'toctou race on /tmp/f'})
    assert blocked is True
    blocked, _ = pe.scan_args("some_tool", {"cmd": 'normal file access'})
    assert blocked is False

def test_mock_race():
    f = pe.MockCheckedFile()
    f.check()
    raced, _ = f.use()
    assert raced is False
    f.check()
    f.attacker_swap("sig-evil")
    raced, reason = f.use()
    assert raced is True
    assert "TOCTOU" in reason




def test_stdlib_only():
    assert pe.stdlib_only() is True


def test_version_pin():
    assert pe.PRIV_ESC_04_VERSION == "priv-esc-04.v1"
