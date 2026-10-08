"""Floyd-Warshall tests."""

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


mod = _load("search_25")

def test_paths():
    import math
    d = mod.floyd_warshall(["a", "b"], [("a", "b", 5)])
    assert d[("a", "b")] == 5
    assert d[("b", "a")] == math.inf


def test_self_zero():
    d = mod.floyd_warshall(["a"], [])
    assert d[("a", "a")] == 0


def test_indirect():
    d = mod.floyd_warshall(["a", "b", "c"],
                           [("a", "b", 1), ("b", "c", 1), ("a", "c", 10)])
    assert d[("a", "c")] == 2


def test_none_nodes():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.floyd_warshall(None, [])
