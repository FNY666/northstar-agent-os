"""Tests for dp_30 (Unique paths with obstacles)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_30
from dp_30 import unique_paths_obstacles


def test_01_normal_case():
    assert unique_paths_obstacles([[0, 0, 0], [0, 1, 0], [0, 0, 0]]) == 2
    assert unique_paths_obstacles([[0, 1], [0, 0]]) == 1


def test_02_edge_cases():
    assert unique_paths_obstacles([[1]]) == 0
    assert unique_paths_obstacles([]) == 0


def test_03_extra():
    assert unique_paths_obstacles([[0, 0, 0, 0], [0, 0, 0, 0]]) == 4
    assert unique_paths_obstacles([[0, 1, 0]]) == 0


def test_04_version_and_stdlib_only():
    assert dp_30.DP_30_VERSION == "dp-30.v1"
    assert dp_30.stdlib_only() is True
