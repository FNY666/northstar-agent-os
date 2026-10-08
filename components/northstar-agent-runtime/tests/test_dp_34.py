"""Tests for dp_34 (Jump game (reachability))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_34
from dp_34 import can_jump


def test_01_normal_case():
    assert can_jump([2, 3, 1, 1, 4]) is True
    assert can_jump([3, 2, 1, 0, 4]) is False


def test_02_edge_cases():
    assert can_jump([0]) is True
    assert can_jump([]) is True


def test_03_extra():
    assert can_jump([2, 0, 0]) is True
    assert can_jump([1, 0, 1, 0]) is False


def test_04_version_and_stdlib_only():
    assert dp_34.DP_34_VERSION == "dp-34.v1"
    assert dp_34.stdlib_only() is True
