"""Tests for tool_system_14."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_14")
import pytest

def test_isolated_submit():
    mgr = m.BulkheadManager()
    mgr.add(m.Bulkhead("a", max_workers=2, queue_size=4))
    try:
        f = mgr.submit("a", lambda: 5)
        assert f.result(timeout=5) == 5
    finally:
        mgr.shutdown_all()

def test_queue_full():
    mgr = m.BulkheadManager()
    mgr.add(m.Bulkhead("a", max_workers=1, queue_size=1))
    import threading
    gate = threading.Event()
    futs = []
    try:
        futs.append(mgr.submit("a", lambda: gate.wait(timeout=5)))
        with pytest.raises(m.BulkheadFullError):
            mgr.submit("a", lambda: 1)
    finally:
        gate.set()
        mgr.shutdown_all()

def test_unknown_bulkhead():
    mgr = m.BulkheadManager()
    with pytest.raises(m.ToolSystem14Error):
        mgr.submit("nope", lambda: 1)
    mgr.shutdown_all()

def test_duplicate():
    mgr = m.BulkheadManager()
    mgr.add(m.Bulkhead("a"))
    with pytest.raises(m.ToolSystem14Error):
        mgr.add(m.Bulkhead("a"))
    mgr.shutdown_all()

def test_stdlib():
    assert m.stdlib_only() is True
