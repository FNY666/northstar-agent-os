"""DS tests: KD-Tree (ds_37)."""
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


m = _load("ds_37")


def test_nearest():
    t = m.KDTree([(0, 0), (10, 0), (0, 10)])
    assert t.nearest((1, 1)) == (0, 0)
    assert t.nearest((9, 1)) == (10, 0)


def test_exact_point():
    t = m.KDTree([(3, 4), (1, 1)])
    assert t.nearest((3, 4)) == (3, 4)


def test_empty():
    t = m.KDTree([])
    assert t.nearest((0, 0)) is None


def test_3d():
    t = m.KDTree([(0, 0, 0), (5, 5, 5)], k=3)
    assert t.nearest((1, 1, 1)) == (0, 0, 0)
