"""Tests for greedy_44 (Minimize maximum pair sum)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_44
from greedy_44 import min_max_pair_sum


def test_01_normal_case():
    assert min_max_pair_sum([3, 5, 2, 3]) == 7
    assert min_max_pair_sum([3, 5, 4, 2, 4, 6]) == 8


def test_02_edge_cases():
    assert min_max_pair_sum([1, 2]) == 3


def test_03_extra():
    assert min_max_pair_sum([1, 100, 2, 99]) == 101
    assert min_max_pair_sum([5, 5, 5, 5]) == 10


def test_04_version_and_stdlib_only():
    assert greedy_44.GREEDY_44_VERSION == "greedy-44.v1"
    assert greedy_44.stdlib_only() is True
