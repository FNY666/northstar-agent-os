"""Priv-esc 03 tests (symlink-attack)."""
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


pe = _load("priv_esc_03")


def test_detect_positive():
    found, _ = pe.detect('ln -s /etc/passwd /tmp/x')
    assert found is True


def test_detect_negative():
    found, _ = pe.detect('ln /a /b')
    assert found is False


def test_fail_closed():
    import pytest

    with pytest.raises(pe.PrivEscError):
        pe.detect(12345)  # type: ignore


def test_scan_args():
    blocked, _ = pe.scan_args("some_tool", {"cmd": 'ln -s /etc/passwd /tmp/x'})
    assert blocked is True
    blocked, _ = pe.scan_args("some_tool", {"cmd": 'ln /a /b'})
    assert blocked is False

def test_is_symlink(tmp_path):
    target = tmp_path / "t"
    target.write_text("x")
    link = tmp_path / "l"
    link.symlink_to(target)
    assert pe.is_symlink(str(link)) is True
    assert pe.is_symlink(str(target)) is False




def test_stdlib_only():
    assert pe.stdlib_only() is True


def test_version_pin():
    assert pe.PRIV_ESC_03_VERSION == "priv-esc-03.v1"
