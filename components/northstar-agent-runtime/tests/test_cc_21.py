"""Tests for cc_21 (Minimum coins via BFS)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_21
from cc_21 import min_coins_bfs


def test_01_normal_case():
    assert min_coins_bfs(11, [1, 2, 5]) == 3
    assert min_coins_bfs(6, [1, 3, 4]) == 2


def test_02_edge_cases():
    assert min_coins_bfs(0, [1, 2]) == 0
    assert min_coins_bfs(3, [2]) == -1


def test_03_extra():
    try:
        min_coins_bfs(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert min_coins_bfs(27, [1, 2, 5, 10]) == 4


def test_04_version_and_stdlib_only():
    assert cc_21.CC_21_VERSION == "cc-21.v1"
    assert cc_21.stdlib_only() is True
