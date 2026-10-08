"""Task snapshot tests."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
ts = _load("task_snapshot")
def test_add():
    s = ts.TaskSnapshot("s1", "p", {})
    s.add_tool_call("t", {"a": 1}, "r", "allow")
    assert len(s.tool_calls) == 1
def test_hash():
    s = ts.TaskSnapshot("s1", "p", {})
    assert s.snapshot_hash().startswith("sha256:")
def test_stdlib():
    assert ts.stdlib_only() is True
