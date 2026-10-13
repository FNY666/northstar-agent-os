"""Priv-esc 08 tests (suid-binary)."""
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


pe = _load("priv_esc_08")


def test_detect_positive():
    found, _ = pe.detect('chmod u+s /tmp/x')
    assert found is True


def test_detect_negative():
    found, _ = pe.detect('chmod 644 /tmp/x')
    assert found is False


def test_fail_closed():
    import pytest

    with pytest.raises(pe.PrivEscError):
        pe.detect(12345)  # type: ignore


def test_scan_args():
    blocked, _ = pe.scan_args("some_tool", {"cmd": 'chmod u+s /tmp/x'})
    assert blocked is True
    blocked, _ = pe.scan_args("some_tool", {"cmd": 'chmod 644 /tmp/x'})
    assert blocked is False

def test_suid_bit(tmp_path):
    import os

    p = tmp_path / "f"
    p.write_text("x")
    os.chmod(p, 0o4755)
    assert pe.has_suid_bit(str(p)) is True
    os.chmod(p, 0o755)
    assert pe.has_suid_bit(str(p)) is False




def test_stdlib_only():
    assert pe.stdlib_only() is True


def test_version_pin():
    assert pe.PRIV_ESC_08_VERSION == "priv-esc-08.v1"
