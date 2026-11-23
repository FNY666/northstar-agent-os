"""Priv-esc 09 tests (capabilities-escalation)."""
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


pe = _load("priv_esc_09")


def test_detect_positive():
    found, _ = pe.detect('setcap cap_sys_admin+ep /tmp/x')
    assert found is True


def test_detect_negative():
    found, _ = pe.detect('capacity planning document')
    assert found is False


def test_fail_closed():
    import pytest

    with pytest.raises(pe.PrivEscError):
        pe.detect(12345)  # type: ignore


def test_scan_args():
    blocked, _ = pe.scan_args("some_tool", {"cmd": 'setcap cap_sys_admin+ep /tmp/x'})
    assert blocked is True
    blocked, _ = pe.scan_args("some_tool", {"cmd": 'capacity planning document'})
    assert blocked is False



def test_stdlib_only():
    assert pe.stdlib_only() is True


def test_version_pin():
    assert pe.PRIV_ESC_09_VERSION == "priv-esc-09.v1"
