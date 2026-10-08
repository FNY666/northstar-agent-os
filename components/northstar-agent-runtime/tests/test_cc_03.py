"""Tests for cc_03 (Count ways (permutations, order matters))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_03
from cc_03 import count_permutations


def test_01_normal_case():
    assert count_permutations(4, [1, 2, 3]) == 7
    assert count_permutations(5, [1, 2, 5]) == 9


def test_02_edge_cases():
    assert count_permutations(0, [1, 2]) == 1
    assert count_permutations(3, [2]) == 0


def test_03_extra():
    try:
        count_permutations(-2, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    # permutations >= combinations for the same input
    assert count_permutations(5, [1, 2, 5]) >= 4


def test_04_version_and_stdlib_only():
    assert cc_03.CC_03_VERSION == "cc-03.v1"
    assert cc_03.stdlib_only() is True
