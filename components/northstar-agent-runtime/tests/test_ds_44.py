"""DS tests: Cover Tree (ds_44)."""
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


m = _load("ds_44")


def _tree():
    t = m.CoverTree(lambda a, b: abs(a - b))
    for p in (5, 15, 25):
        t.insert(p)
    return t


def test_nearest():
    assert _tree().nearest(17) == 15


def test_k_nearest():
    assert _tree().k_nearest(17, 2) == [15, 25]


def test_bad_k():
    t = _tree()
    try:
        t.k_nearest(0, 0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
