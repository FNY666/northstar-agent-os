"""Tests for greedy_36 (Hand of straights)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_36
from greedy_36 import hand_of_straights


def test_01_normal_case():
    assert hand_of_straights([1, 2, 3, 6, 2, 3, 4, 7, 8], 3) is True
    assert hand_of_straights([1, 2, 3, 4, 5], 4) is False


def test_02_edge_cases():
    assert hand_of_straights([], 3) is True
    assert hand_of_straights([1], 2) is False


def test_03_extra():
    assert hand_of_straights([1, 1, 2, 2, 3, 3], 3) is True
    assert hand_of_straights([1, 2, 3], 1) is True


def test_04_version_and_stdlib_only():
    assert greedy_36.GREEDY_36_VERSION == "greedy-36.v1"
    assert greedy_36.stdlib_only() is True
