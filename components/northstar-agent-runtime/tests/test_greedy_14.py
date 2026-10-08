"""Tests for greedy_14 (Assign cookies)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_14
from greedy_14 import assign_cookies


def test_01_normal_case():
    assert assign_cookies([1, 2, 3], [1, 1]) == 1
    assert assign_cookies([1, 2], [1, 2, 3]) == 2


def test_02_edge_cases():
    assert assign_cookies([], [1]) == 0
    assert assign_cookies([1, 2, 3], []) == 0


def test_03_extra():
    assert assign_cookies([10, 9, 8, 7], [5, 6, 7, 8]) == 2
    assert assign_cookies([1, 1, 1], [1, 1, 1]) == 3


def test_04_version_and_stdlib_only():
    assert greedy_14.GREEDY_14_VERSION == "greedy-14.v1"
    assert greedy_14.stdlib_only() is True
