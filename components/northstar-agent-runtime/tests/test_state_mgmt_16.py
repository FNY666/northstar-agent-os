"""Tests for state_mgmt_16."""
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
m = _load("state_mgmt_16")

def test_quorum():
    nodes = [m.MockNode("a", {"x": 1}), m.MockNode("b", {"x": 2})]
    recs = m.SnapshotCoordinator(["a", "b"]).run(nodes)
    assert set(recs) == {"a", "b"}
    assert recs["a"].seq == 1
def test_missing_fails():
    with pytest.raises(m.SnapshotError):
        m.SnapshotCoordinator(["a", "b"]).run([m.MockNode("a")])
def test_bad_digest():
    with pytest.raises(m.SnapshotError):
        m.SnapshotRecord("a", 0, "nope")
def test_digest_stable():
    assert m.digest_state({"b": 2, "a": 1}) == m.digest_state({"a": 1, "b": 2})
def test_stdlib():
    assert m.stdlib_only()
