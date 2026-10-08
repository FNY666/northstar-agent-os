"""Tests for dp_03 (House robber)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_03
from dp_03 import rob


def test_01_normal_case():
    assert rob([1, 2, 3, 1]) == 4
    assert rob([2, 7, 9, 3, 1]) == 12


def test_02_edge_cases():
    assert rob([]) == 0
    assert rob([5]) == 5
    assert rob([0, 0, 0]) == 0


def test_03_extra():
    assert rob([2, 1, 1, 2]) == 4
    assert rob([1, 3, 1, 3, 100]) == 103


def test_04_version_and_stdlib_only():
    assert dp_03.DP_03_VERSION == "dp-03.v1"
    assert dp_03.stdlib_only() is True
