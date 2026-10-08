
"""Tests for state_mgmt_06."""
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
m = _load("state_mgmt_06")

def test_encrypt_decrypt():
    k = m.MockKMS(); k.create_key("a")
    t = k.encrypt("a", b"hi")
    assert k.decrypt(t) == b"hi"
def test_rotate_keeps_old():
    k = m.MockKMS(); k.create_key("a")
    t1 = k.encrypt("a", b"one"); k.rotate("a")
    assert k.decrypt(t1) == b"one"
def test_revoke():
    k = m.MockKMS(); k.create_key("a"); k.revoke("a")
    with pytest.raises(m.KMSError):
        k.encrypt("a", b"x")
def test_stdlib():
    assert m.stdlib_only()
