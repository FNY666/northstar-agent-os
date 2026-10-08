"""Tests for lis-39 (LIS by custom key function)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_39
from lis_39 import lis_by_key


def test_01_normal_case():
    assert lis_by_key([-3, -1, -2], key=abs) == 2
    assert lis_by_key(["aa", "b", "cccc"], key=len) == 2
    assert lis_by_key([3, 1, 2], key=lambda x: -x) == 2


def test_02_edge_cases():
    assert lis_by_key([], key=abs) == 0
    assert lis_by_key([5], key=abs) == 1
    assert lis_by_key([(1, 2), (0, 5), (2, 1)], key=lambda p: p[0] + p[1]) == 2


def test_03_validation():
    try:
        lis_by_key([1, 2], key=42)
        raise AssertionError('expected ValueError')
    except ValueError:
        pass
    try:
        lis_by_key('nope', key=abs)
        raise AssertionError('expected ValueError')
    except ValueError:
        pass

def test_04_version_and_stdlib_only():
    assert lis_39.LIS_39_VERSION == "lis-39.v1"
    assert lis_39.stdlib_only() is True
