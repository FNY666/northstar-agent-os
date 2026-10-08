"""N-queens backtracking tests."""

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


mod = _load("search_43")

def test_n4():
    assert len(mod.nqueens(4)) == 2


def test_n1():
    assert mod.nqueens(1) == [[0]]


def test_n2_none():
    assert mod.nqueens(2) == []


def test_negative():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.nqueens(-1)
