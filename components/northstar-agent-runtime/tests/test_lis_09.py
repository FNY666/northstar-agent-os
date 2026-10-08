"""Tests for lis-09 (Russian doll envelopes (2D nesting))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_09
from lis_09 import max_nested_envelopes


def test_01_normal_case():
    assert max_nested_envelopes([[5, 4], [6, 4], [6, 7], [2, 3]]) == 3
    assert max_nested_envelopes([[1, 2], [2, 3], [3, 4], [4, 5]]) == 4
    assert max_nested_envelopes([[4, 5], [4, 6], [6, 7], [2, 3], [1, 1]]) == 4


def test_02_edge_cases():
    assert max_nested_envelopes([]) == 0
    assert max_nested_envelopes([[2, 3]]) == 1
    assert max_nested_envelopes([[1, 1], [1, 1], [1, 1]]) == 1


def test_03_validation():
    try:
        max_nested_envelopes([[1, 2, 3]])
        raise AssertionError('expected ValueError')
    except ValueError:
        pass
    try:
        max_nested_envelopes('nope')
        raise AssertionError('expected ValueError')
    except ValueError:
        pass

def test_04_version_and_stdlib_only():
    assert lis_09.LIS_09_VERSION == "lis-09.v1"
    assert lis_09.stdlib_only() is True
