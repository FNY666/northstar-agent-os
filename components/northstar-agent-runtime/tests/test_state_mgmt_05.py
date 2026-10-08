
"""Tests for state_mgmt_05."""
import importlib.util, sys
from pathlib import Path
import pytest
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
m = _load("state_mgmt_05")

def test_roundtrip():
    k = m.generate_key()
    s = {"secret": 1}
    assert m.unseal(k, m.seal(k, s)) == s
def test_tamper():
    import base64
    k = m.generate_key()
    t = m.seal(k, {"a": 1})
    raw = bytearray(base64.urlsafe_b64decode(t.encode())); raw[-1] ^= 1
    bad = base64.urlsafe_b64encode(bytes(raw)).decode()
    with pytest.raises(m.SealError):
        m.unseal(k, bad)
def test_bad_key():
    with pytest.raises(m.SealError):
        m.seal("not-a-key", {"a": 1})
def test_stdlib():
    assert m.stdlib_only()
