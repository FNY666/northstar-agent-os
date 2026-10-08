"""Map coloring (mock constraint) tests."""

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


mod = _load("search_45")

def _valid(adj, coloring):
    if coloring is None or set(coloring) != set(adj):
        return False
    return all(coloring[n] != coloring[nb] for n in adj for nb in adj[n])


def test_triangle_3_colors():
    tri = {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]}
    assert _valid(tri, mod.map_coloring(tri, ["R", "G", "B"]))


def test_triangle_2_colors_unsat():
    tri = {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]}
    assert mod.map_coloring(tri, ["R", "G"]) is None


def test_square_2_colors():
    sq = {"a": ["b", "d"], "b": ["a", "c"], "c": ["b", "d"], "d": ["a", "c"]}
    assert _valid(sq, mod.map_coloring(sq, ["R", "G"]))


def test_none_args():
    import pytest
    with pytest.raises(mod.SearchError):
        mod.map_coloring(None, ["R"])
