"""WebSocket exfiltration detection tests."""

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


m = _load("exfil_04")

def test_benign():
    msgs = [{"opcode": 1, "size": 100}] * 12
    ok, _ = m.detect_ws_exfil(msgs)
    assert ok is False


def test_large_binary_burst():
    msgs = [{"opcode": 2, "size": 20000}] * 12
    ok, reason = m.detect_ws_exfil(msgs)
    assert ok is True
    assert "binary" in reason


def test_too_few():
    ok, _ = m.detect_ws_exfil([{"opcode": 2, "size": 99999}])
    assert ok is False


def test_bad_input():
    import pytest
    with pytest.raises(m.Exfil04Error):
        m.detect_ws_exfil("nope")


def test_stdlib_only():
    assert m.stdlib_only() is True


def test_version_pin():
    assert m.EXFIL_04_VERSION == "exfil-04.v1"
