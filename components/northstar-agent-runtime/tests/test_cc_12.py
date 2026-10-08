"""Tests for cc_12 (Minimum cost (per-denomination cost))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_12
from cc_12 import min_cost


def test_01_normal_case():
    assert min_cost(11, {1: 1, 2: 1, 5: 1}) == 3
    assert min_cost(11, {1: 10, 5: 1}) == 12


def test_02_edge_cases():
    assert min_cost(0, {1: 5}) == 0
    assert min_cost(3, {2: 5}) == -1


def test_03_extra():
    try:
        min_cost(-1, {1: 1})
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    # cheap large coins beat many expensive small ones
    assert min_cost(10, {1: 100, 10: 1}) == 1


def test_04_version_and_stdlib_only():
    assert cc_12.CC_12_VERSION == "cc-12.v1"
    assert cc_12.stdlib_only() is True
