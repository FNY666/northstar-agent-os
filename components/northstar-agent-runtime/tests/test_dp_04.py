"""Tests for dp_04 (House robber II (circular street))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_04
from dp_04 import rob_circular


def test_01_normal_case():
    assert rob_circular([2, 3, 2]) == 3
    assert rob_circular([1, 2, 3, 1]) == 4


def test_02_edge_cases():
    assert rob_circular([]) == 0
    assert rob_circular([5]) == 5
    assert rob_circular([1, 2]) == 2


def test_03_extra():
    assert rob_circular([1, 2, 3]) == 3
    assert rob_circular([200, 3, 140, 20, 10]) == 340


def test_04_version_and_stdlib_only():
    assert dp_04.DP_04_VERSION == "dp-04.v1"
    assert dp_04.stdlib_only() is True
