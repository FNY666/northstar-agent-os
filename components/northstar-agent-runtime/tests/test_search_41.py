"""Alpha-beta pruning (mock) tests."""

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


mod = _load("search_41")

def _setup():
    kids = {"r": ["a", "b"], "a": ["a1", "a2"], "b": ["b1", "b2"]}
    vals = {"a1": 3, "a2": 5, "b1": 2, "b2": 9}
    return kids.get, vals.__getitem__


def test_same_as_minimax():
    k, v = _setup()
    got = mod.alpha_beta("r", 2, float("-inf"), float("inf"), True, k, v)
    assert got == 3


def test_prunes():
    k, v = _setup()
    c = [0]
    mod.alpha_beta("r", 2, float("-inf"), float("inf"), True, k, v, c)
    assert c[0] < 4


def test_leaf():
    k, v = _setup()
    assert mod.alpha_beta("a1", 0, float("-inf"), float("inf"), True, k, v) == 3


def test_none_args():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.alpha_beta("r", 2, 0, 0, True, None, lambda n: 0)
