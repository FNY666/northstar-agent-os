"""DS tests: Euler Tour Tree (ds_34)."""
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


m = _load("ds_34")


def test_component_size():
    t = m.EulerTourTree()
    t.link(1, 2); t.link(2, 3)
    assert t.component_size(1) == 3


def test_split():
    t = m.EulerTourTree()
    t.link(1, 2); t.link(2, 3)
    t.cut(2, 3)
    assert t.component_size(1) == 2
    assert t.component_size(3) == 1


def test_cycle_rejected():
    t = m.EulerTourTree()
    t.link(1, 2)
    try:
        t.link(2, 1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
