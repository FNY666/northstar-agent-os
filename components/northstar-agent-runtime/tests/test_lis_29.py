"""Tests for lis-29 (LIS over even values only)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_29
from lis_29 import lis_even_only


def test_01_normal_case():
    assert lis_even_only([1, 2, 3, 4, 5, 6]) == 3
    assert lis_even_only([6, 1, 4, 3, 2]) == 2
    assert lis_even_only([2, 4, 6, 8]) == 4


def test_02_edge_cases():
    assert lis_even_only([]) == 0
    assert lis_even_only([1, 3, 5]) == 0
    assert lis_even_only([8]) == 1
    assert lis_even_only([-4, -2, 0, 2]) == 4


def test_03_never_exceeds_full():
    from lis_01 import lis_length
    s = [5, 2, 8, 1, 4]
    assert lis_even_only(s) <= lis_length(s)

def test_04_version_and_stdlib_only():
    assert lis_29.LIS_29_VERSION == "lis-29.v1"
    assert lis_29.stdlib_only() is True
