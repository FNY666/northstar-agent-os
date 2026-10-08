"""Blockchain exfiltration detection (mock) tests."""

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


m = _load("exfil_16")

def test_benign():
    ok, _ = m.detect_blockchain_exfil({"op_return": b"hi"})
    assert ok is False


def test_big_opreturn():
    ok, reason = m.detect_blockchain_exfil({"op_return": b"x" * 100})
    assert ok is True
    assert "OP_RETURN" in reason


def test_memo_ssn():
    ok, _ = m.detect_blockchain_exfil({"memo": "123-45-6789"})
    assert ok is True


def test_bad_type():
    import pytest
    with pytest.raises(m.Exfil16Error):
        m.detect_blockchain_exfil("nope")


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_16_VERSION == "exfil-16.v1"
