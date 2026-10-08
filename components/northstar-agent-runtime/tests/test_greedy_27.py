"""Tests for greedy_27 (Split array into consecutive subsequences)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_27
from greedy_27 import can_split_consecutive


def test_01_normal_case():
    assert can_split_consecutive([1, 2, 3, 3, 4, 5]) is True
    assert can_split_consecutive([1, 2, 3, 4, 4, 5]) is False


def test_02_edge_cases():
    assert can_split_consecutive([]) is True
    assert can_split_consecutive([1, 2]) is False


def test_03_extra():
    assert can_split_consecutive([1, 2, 3, 3, 4, 4, 5, 5]) is True
    assert can_split_consecutive([1, 2, 3]) is True


def test_04_version_and_stdlib_only():
    assert greedy_27.GREEDY_27_VERSION == "greedy-27.v1"
    assert greedy_27.stdlib_only() is True
