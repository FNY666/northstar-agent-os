"""Tests for dp_29 (Unique paths in a grid)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_29
from dp_29 import unique_paths


def test_01_normal_case():
    assert unique_paths(3, 7) == 28
    assert unique_paths(3, 2) == 3


def test_02_edge_cases():
    assert unique_paths(1, 1) == 1
    assert unique_paths(1, 5) == 1


def test_03_extra():
    assert unique_paths(10, 10) == 48620
    try:
        unique_paths(-1, 2)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_04_version_and_stdlib_only():
    assert dp_29.DP_29_VERSION == "dp-29.v1"
    assert dp_29.stdlib_only() is True
