"""Tests for algo_39: suffix array (simplified)."""

import importlib.util
from pathlib import Path

import pytest

from algo_39 import suffix_array


def _load(name):
    path = Path(__file__).resolve().parent.parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


algo_39 = _load("algo_39")


def test_version_stdlib_and_simplified_docstring():
    assert algo_39.ALGO_39_VERSION == "algo-39.v1"
    assert algo_39.stdlib_only() is True
    assert "simplified" in algo_39.__doc__.lower()


def test_known_values():
    assert suffix_array("banana") == [5, 3, 1, 0, 4, 2]
    assert suffix_array("mississippi") == [10, 7, 4, 1, 0, 9, 8, 6, 3, 5, 2]


def test_sorted_suffix_invariant():
    import random

    rng = random.Random(39)
    for _ in range(20):
        s = "".join(rng.choice("abcd") for _ in range(rng.randint(0, 30)))
        sa = suffix_array(s)
        assert sorted(sa) == list(range(len(s)))
        assert [s[i:] for i in sa] == sorted(s[i:] for i in range(len(s)))


def test_edge_cases_empty_single_repeated():
    assert suffix_array("") == []
    assert suffix_array("x") == [0]
    assert suffix_array("aaaa") == [3, 2, 1, 0]
    assert suffix_array("abc") == [0, 1, 2]
    assert suffix_array("cba") == [2, 1, 0]
