"""DS tests: Hash Set (ds_18)."""
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


m = _load("ds_18")


def test_add_contains():
    s = m.HashSet()
    s.add("x")
    assert s.contains("x") is True
    assert s.contains("y") is False


def test_dedup():
    s = m.HashSet([1, 1, 2])
    assert len(s) == 2


def test_union_intersection():
    s = m.HashSet([1, 2])
    assert s.union([2, 3]).to_set() == {1, 2, 3}
    assert s.intersection([2, 3]).to_set() == {2}


def test_discard():
    s = m.HashSet([1])
    s.discard(1); s.discard(1)
    assert len(s) == 0
