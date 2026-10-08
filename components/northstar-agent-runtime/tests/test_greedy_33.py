"""Tests for greedy_33 (Patching array)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_33
from greedy_33 import min_patches


def test_01_normal_case():
    assert min_patches([1, 3], 6) == 1
    assert min_patches([1, 5, 10], 20) == 2


def test_02_edge_cases():
    assert min_patches([1, 2, 2], 5) == 0
    assert min_patches([], 1) == 1


def test_03_extra():
    assert min_patches([], 7) == 3
    assert min_patches([1, 2, 31, 33], 2147483647) == 28


def test_04_version_and_stdlib_only():
    assert greedy_33.GREEDY_33_VERSION == "greedy-33.v1"
    assert greedy_33.stdlib_only() is True
