"""Tests for greedy_15 (Lemonade change)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_15
from greedy_15 import lemonade_change


def test_01_normal_case():
    assert lemonade_change([5, 5, 5, 10, 20]) is True
    assert lemonade_change([5, 5, 10, 10, 20]) is False


def test_02_edge_cases():
    assert lemonade_change([]) is True
    assert lemonade_change([10]) is False


def test_03_extra():
    try:
        lemonade_change([7])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert lemonade_change([5, 5, 5, 5, 10, 20, 10]) is True


def test_04_version_and_stdlib_only():
    assert greedy_15.GREEDY_15_VERSION == "greedy-15.v1"
    assert greedy_15.stdlib_only() is True
