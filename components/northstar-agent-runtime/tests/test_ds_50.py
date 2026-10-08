"""DS tests: TV-Tree (ds_50)."""
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


m = _load("ds_50")


def test_active_dims_ignored_tail():
    t = m.TVTree(3, active_dims=2)
    t.insert((0, 0, 1000)); t.insert((9, 9, 0))
    assert t.nearest((1, 1, 0)) == (0, 0, 1000)


def test_dim_mismatch():
    t = m.TVTree(2)
    try:
        t.insert((1, 2, 3))
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_empty():
    t = m.TVTree(2)
    assert t.nearest((0, 0)) is None


def test_bad_active():
    try:
        m.TVTree(2, active_dims=5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
