"""Beam search (mock) tests."""

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


mod = _load("search_33")

def _setup():
    exp = {"s": ["a", "b"], "a": ["G"], "b": ["c"], "c": ["d"]}
    score = {"s": 9, "a": 10, "b": 0, "G": 0, "c": 5, "d": 6}.__getitem__
    return exp.__getitem__, lambda x: x == "G", score


def test_wide_beam_finds():
    exp, goal, score = _setup()
    assert mod.beam_search("s", exp, goal, score, 4, 2) == "G"


def test_narrow_beam_misses():
    exp, goal, score = _setup()
    assert mod.beam_search("s", exp, goal, score, 4, 1) is None


def test_start_is_goal():
    assert mod.beam_search("G", lambda s: [], lambda x: x == "G",
                           lambda x: 0, 3, 1) == "G"


def test_bad_width():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.beam_search("s", lambda s: [], lambda x: False, lambda x: 0, 3, 0)
