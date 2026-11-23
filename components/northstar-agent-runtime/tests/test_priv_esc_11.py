"""Priv-esc 11 tests (cgroup-escape)."""
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


pe = _load("priv_esc_11")


def test_detect_positive():
    found, _ = pe.detect('echo payload > /sys/fs/cgroup/x/release_agent')
    assert found is True


def test_detect_negative():
    found, _ = pe.detect('cgroup documentation page')
    assert found is False


def test_fail_closed():
    import pytest

    with pytest.raises(pe.PrivEscError):
        pe.detect(12345)  # type: ignore


def test_scan_args():
    blocked, _ = pe.scan_args("some_tool", {"cmd": 'echo payload > /sys/fs/cgroup/x/release_agent'})
    assert blocked is True
    blocked, _ = pe.scan_args("some_tool", {"cmd": 'cgroup documentation page'})
    assert blocked is False



def test_stdlib_only():
    assert pe.stdlib_only() is True


def test_version_pin():
    assert pe.PRIV_ESC_11_VERSION == "priv-esc-11.v1"
