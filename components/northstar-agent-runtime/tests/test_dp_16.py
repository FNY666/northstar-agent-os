"""Tests for dp_16 (Egg drop (minimum moves))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_16
from dp_16 import egg_drop


def test_01_normal_case():
    assert egg_drop(2, 100) == 14
    assert egg_drop(1, 10) == 10


def test_02_edge_cases():
    assert egg_drop(2, 1) == 1
    assert egg_drop(3, 0) == 0


def test_03_extra():
    assert egg_drop(2, 36) == 8
    assert egg_drop(4, 500) == 11
    try:
        egg_drop(0, 1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_04_version_and_stdlib_only():
    assert dp_16.DP_16_VERSION == "dp-16.v1"
    assert dp_16.stdlib_only() is True
