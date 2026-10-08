
"""Tests for state_mgmt_07."""
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
m = _load("state_mgmt_07")

def test_migrate():
    v2 = m.migrate({"format_version": m.V1, "state": {"seq": 1, "tool": "r"}})
    assert v2["format_version"] == m.V2
    assert v2["state"]["tags"] == []
def test_idempotent():
    v2 = m.migrate({"format_version": m.V1, "state": {"seq": 1, "tool": "r"}})
    assert m.migrate(v2) is v2
def test_bad_version():
    with pytest.raises(m.MigrationError):
        m.migrate({"format_version": "v3", "state": {}})
def test_stdlib():
    assert m.stdlib_only()
