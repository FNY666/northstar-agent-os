"""Tests for math_39 (graph)."""
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


m = _load("math_39")


def test_bfs():
    adj = {"a": ["b", "c"], "b": ["d"], "c": [], "d": []}
    assert m.bfs_distances(adj, "a") == {"a": 0, "b": 1, "c": 1, "d": 2}


def test_has_path():
    adj = {1: [2], 2: [3], 3: [], 4: []}
    assert m.has_path(adj, 1, 3) is True
    assert m.has_path(adj, 1, 4) is False
    assert m.has_path(adj, 3, 1) is False  # directed


def test_components():
    adj = {"a": ["b"], "b": ["a"], "c": []}
    comps = m.connected_components(adj)
    assert len(comps) == 2
    assert {"a", "b"} in comps


def test_single_node():
    assert m.bfs_distances({}, "x") == {"x": 0}
    assert m.has_path({}, "x", "x") is True
