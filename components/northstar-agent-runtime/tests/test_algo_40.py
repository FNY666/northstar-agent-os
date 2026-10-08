"""Tests for algo_40: lowest common ancestor (simplified)."""

import importlib.util
from pathlib import Path

import pytest

from algo_40 import lca


def _load(name):
    path = Path(__file__).resolve().parent.parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


algo_40 = _load("algo_40")


def test_version_stdlib_and_simplified_docstring():
    assert algo_40.ALGO_40_VERSION == "algo-40.v1"
    assert algo_40.stdlib_only() is True
    assert "simplified" in algo_40.__doc__.lower()


def test_lca_normal():
    #        1
    #      /   \
    #     2     3
    #    / \   / \
    #   4   5 6   7
    parent = {1: None, 2: 1, 3: 1, 4: 2, 5: 2, 6: 3, 7: 3}
    assert lca(parent, 4, 5) == 2
    assert lca(parent, 4, 6) == 1
    assert lca(parent, 6, 7) == 3
    assert lca(parent, 2, 7) == 1
    assert lca(parent, 1, 7) == 1


def test_lca_against_brute_force_paths():
    import random

    def ancestors(parent, u):
        path = []
        while u is not None:
            path.append(u)
            u = parent[u]
        return path

    rng = random.Random(40)
    n = 60
    parent = {0: None}
    for i in range(1, n):
        parent[i] = rng.randint(0, i - 1)
    for _ in range(200):
        u = rng.randint(0, n - 1)
        v = rng.randint(0, n - 1)
        au = ancestors(parent, u)
        set_au = set(au)
        expected = next(x for x in ancestors(parent, v) if x in set_au)
        assert lca(parent, u, v) == expected


def test_edge_cases():
    # Single node.
    assert lca({1: None}, 1, 1) == 1
    # Empty map.
    assert lca({}, 1, 1) is None
    # Unknown nodes.
    parent = {1: None, 2: 1}
    assert lca(parent, 2, 99) is None
    assert lca(parent, 99, 2) is None
    # Node with itself (non-root).
    assert lca(parent, 2, 2) == 2
    # Ancestor of the other.
    assert lca(parent, 1, 2) == 1
    assert lca(parent, 2, 1) == 1
    # Disjoint trees.
    assert lca({1: None, 2: None}, 1, 2) is None


def test_string_nodes():
    parent = {"root": None, "a": "root", "b": "root", "a1": "a", "a2": "a"}
    assert lca(parent, "a1", "a2") == "a"
    assert lca(parent, "a1", "b") == "root"
    assert lca(parent, "root", "a1") == "root"
