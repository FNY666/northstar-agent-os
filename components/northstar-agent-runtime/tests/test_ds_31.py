"""DS tests: Mo's Algorithm (ds_31)."""
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


m = _load("ds_31")


def test_solve_sum():
    mo = m.MoSolver()
    mo.add_query(0, 2)
    assert mo.solve([5, 6, 7], sum) == [11]


def test_multiple_queries():
    mo = m.MoSolver()
    mo.add_query(0, 1); mo.add_query(0, 3)
    assert mo.solve([1, 2, 3], sum) == [1, 6]


def test_custom_fn():
    mo = m.MoSolver()
    mo.add_query(0, 3)
    assert mo.solve([3, 1, 2], min) == [1]


def test_bad_range():
    mo = m.MoSolver()
    try:
        mo.add_query(3, 1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
