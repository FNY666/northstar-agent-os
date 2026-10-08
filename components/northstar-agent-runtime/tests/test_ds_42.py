"""DS tests: VP-Tree (ds_42)."""
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


m = _load("ds_42")


def _tree():
    t = m.VPTree(lambda a, b: abs(a - b))
    t.build([10, 20, 30])
    return t


def test_nearest():
    assert _tree().nearest(22) == 20


def test_insert():
    t = _tree()
    t.insert(25)
    assert t.nearest(24) == 25


def test_empty():
    t = m.VPTree(lambda a, b: abs(a - b))
    assert t.nearest(5) is None
