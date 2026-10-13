
"""Tests for state_mgmt_01."""
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
m = _load("state_mgmt_01")

def test_roundtrip():
    s = {"a": 1}
    assert m.decode(m.encode(s)) == s
def test_tamper():
    import json
    d = json.loads(m.encode({"a": 1}))
    d["state"]["a"] = 2
    with pytest.raises(m.CheckpointError):
        m.decode(json.dumps(d))
def test_bad_version():
    with pytest.raises(m.CheckpointError):
        m.decode('{"format_version":"v0","state":{},"checksum":"x"}')
def test_stdlib():
    assert m.stdlib_only()
