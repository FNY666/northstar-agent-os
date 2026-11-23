"""Priv-esc 15 tests (seccomp-bypass)."""
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


pe = _load("priv_esc_15")


def test_detect_positive():
    found, _ = pe.detect('prctl(PR_SET_SECCOMP, SECCOMP_MODE_DISABLED)')
    assert found is True


def test_detect_negative():
    found, _ = pe.detect('second component installed')
    assert found is False


def test_fail_closed():
    import pytest

    with pytest.raises(pe.PrivEscError):
        pe.detect(12345)  # type: ignore


def test_scan_args():
    blocked, _ = pe.scan_args("some_tool", {"cmd": 'prctl(PR_SET_SECCOMP, SECCOMP_MODE_DISABLED)'})
    assert blocked is True
    blocked, _ = pe.scan_args("some_tool", {"cmd": 'second component installed'})
    assert blocked is False



def test_stdlib_only():
    assert pe.stdlib_only() is True


def test_version_pin():
    assert pe.PRIV_ESC_15_VERSION == "priv-esc-15.v1"
