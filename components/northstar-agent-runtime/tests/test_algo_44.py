"""Tests for algo_44: longest increasing subsequence (strictly increasing)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import algo_44 as a44
from algo_44 import lis, lis_length


def _valid_lis(sub, arr) -> bool:
    if not all(b > a for a, b in zip(sub, sub[1:])):
        return False
    it = iter(arr)
    return all(x in it for x in sub)


def test_version_pin_and_stdlib_only():
    assert a44.ALGO_44_VERSION == "algo-44.v1"
    assert a44.stdlib_only() is True


def test_lis_classic():
    arr = [10, 9, 2, 5, 3, 7, 101, 18]
    got = lis(arr)
    assert len(got) == 4
    assert _valid_lis(got, arr)
    assert lis_length(arr) == 4


def test_lis_edge_cases():
    assert lis([]) == []
    assert lis_length([]) == 0
    assert lis([7]) == [7]
    assert lis_length([7]) == 1


def test_lis_decreasing_and_duplicates():
    assert lis_length([5, 4, 3, 2, 1]) == 1
    assert lis_length([1, 2, 3, 4]) == 4
    # strictly increasing: equal neighbours must not be chained
    assert lis_length([2, 2, 2]) == 1
    got = lis([3, 1, 2])
    assert got == [1, 2] and _valid_lis(got, [3, 1, 2])
