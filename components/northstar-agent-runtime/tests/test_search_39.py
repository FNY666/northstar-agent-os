"""MCTS (mock) tests."""

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


mod = _load("search_39")

def _setup():
    acts = lambda: ["a", "b", "c"]
    roll = {"a": 0.1, "b": 0.9, "c": 0.5}.__getitem__
    return acts, roll


def test_picks_best():
    acts, roll = _setup()
    assert mod.mcts_search(acts, roll, iters=60, seed=0) == "b"


def test_deterministic():
    acts, roll = _setup()
    a = mod.mcts_search(acts, roll, iters=60, seed=5)
    b = mod.mcts_search(acts, roll, iters=60, seed=5)
    assert a == b


def test_no_actions():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.mcts_search(lambda: [], lambda a: 0.0)


def test_none_args():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.mcts_search(None, lambda a: 0.0)
