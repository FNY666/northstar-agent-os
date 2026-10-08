"""Union-find components tests."""

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


mod = _load("search_48")

def test_two_components():
    comps = mod.connected_components([1, 2, 3, 4], [(1, 2), (3, 4)])
    assert len(comps) == 2
    assert sorted(map(sorted, comps)) == [[1, 2], [3, 4]]


def test_all_isolated():
    assert len(mod.connected_components([1, 2, 3], [])) == 3


def test_one_component():
    comps = mod.connected_components([1, 2, 3], [(1, 2), (2, 3)])
    assert len(comps) == 1


def test_none_nodes():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.connected_components(None, [])
