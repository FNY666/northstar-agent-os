"""Tests for dp_02 (Climbing stairs)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_02
from dp_02 import climb_stairs


def test_01_normal_case():
    assert climb_stairs(5) == 8
    assert climb_stairs(10) == 89


def test_02_edge_cases():
    assert climb_stairs(0) == 1
    assert climb_stairs(1) == 1
    assert climb_stairs(2) == 2


def test_03_extra():
    assert climb_stairs(20) == 10946
    try:
        climb_stairs(-3)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_04_version_and_stdlib_only():
    assert dp_02.DP_02_VERSION == "dp-02.v1"
    assert dp_02.stdlib_only() is True
