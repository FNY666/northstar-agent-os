"""Linear search tests."""

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


mod = _load("search_01")

def test_found():
    assert mod.linear_search([5, 3, 8], 3) == 1


def test_not_found():
    assert mod.linear_search([5, 3, 8], 7) == -1


def test_empty():
    assert mod.linear_search([], 1) == -1


def test_none_raises():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.linear_search(None, 1)
