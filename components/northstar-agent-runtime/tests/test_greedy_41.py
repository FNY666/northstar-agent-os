"""Tests for greedy_41 (Kruskal minimum spanning tree)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_41
from greedy_41 import kruskal_mst_weight


def test_01_normal_case():
    assert kruskal_mst_weight(4, [(0, 1, 10), (0, 2, 6), (0, 3, 5), (1, 3, 15), (2, 3, 4)]) == 19


def test_02_edge_cases():
    assert kruskal_mst_weight(1, []) == 0
    assert kruskal_mst_weight(0, []) == 0


def test_03_extra():
    assert kruskal_mst_weight(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)]) == 3
    assert kruskal_mst_weight(2, [(0, 1, 7)]) == 7


def test_04_version_and_stdlib_only():
    assert greedy_41.GREEDY_41_VERSION == "greedy-41.v1"
    assert greedy_41.stdlib_only() is True
