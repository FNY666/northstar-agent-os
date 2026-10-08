"""DS tests: Sqrt Decomposition (ds_30)."""
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


m = _load("ds_30")


def test_full_range():
    sd = m.SqrtDecomp([1, 2, 3, 4])
    assert sd.query(0, 4) == 10


def test_partial():
    sd = m.SqrtDecomp(list(range(1, 17)))
    assert sd.query(4, 12) == sum(range(5, 13))


def test_update():
    sd = m.SqrtDecomp([1, 1, 1, 1])
    sd.update(2, 5)
    assert sd.query(0, 4) == 8


def test_empty_range():
    sd = m.SqrtDecomp([1, 2, 3])
    assert sd.query(1, 1) == 0
