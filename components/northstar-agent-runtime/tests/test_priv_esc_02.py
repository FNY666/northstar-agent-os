"""Priv-esc 02 tests (path-traversal)."""
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


pe = _load("priv_esc_02")


def test_detect_positive():
    found, _ = pe.detect('../../etc/passwd')
    assert found is True


def test_detect_negative():
    found, _ = pe.detect('/var/data/report.txt')
    assert found is False


def test_fail_closed():
    import pytest

    with pytest.raises(pe.PrivEscError):
        pe.detect(12345)  # type: ignore


def test_scan_args():
    blocked, _ = pe.scan_args("some_tool", {"cmd": '../../etc/passwd'})
    assert blocked is True
    blocked, _ = pe.scan_args("some_tool", {"cmd": '/var/data/report.txt'})
    assert blocked is False



def test_stdlib_only():
    assert pe.stdlib_only() is True


def test_version_pin():
    assert pe.PRIV_ESC_02_VERSION == "priv-esc-02.v1"
