
"""Tests for state_mgmt_03."""
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
m = _load("state_mgmt_03")

def test_reconstruct_all():
    log = m.SnapshotLog(snapshot_every=2)
    ss = [{"i": i} for i in range(5)]
    for s in ss: log.append(s)
    for i, s in enumerate(ss, 1):
        assert log.reconstruct(i) == s
def test_out_of_range():
    log = m.SnapshotLog()
    log.append({"a": 1})
    with pytest.raises(m.SnapshotError):
        log.reconstruct(5)
def test_bad_every():
    with pytest.raises(m.SnapshotError):
        m.SnapshotLog(snapshot_every=0)
def test_stdlib():
    assert m.stdlib_only()
