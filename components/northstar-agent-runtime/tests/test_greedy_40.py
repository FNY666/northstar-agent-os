"""Tests for greedy_40 (Prim minimum spanning tree (simplified))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_40
from greedy_40 import prim_mst_weight


def test_01_normal_case():
    g = {0: {1: 4, 7: 8}, 1: {0: 4, 2: 8, 7: 11}, 2: {1: 8, 3: 7, 5: 4, 8: 2}, 3: {2: 7, 4: 9, 5: 14}, 4: {3: 9, 5: 10}, 5: {2: 4, 3: 14, 4: 10, 6: 2}, 6: {5: 2, 7: 1, 8: 6}, 7: {0: 8, 1: 11, 6: 1, 8: 7}, 8: {2: 2, 6: 6, 7: 7}}
    assert prim_mst_weight(g) == 37


def test_02_edge_cases():
    assert prim_mst_weight({}) == 0
    assert prim_mst_weight({0: {}}) == 0


def test_03_extra():
    assert prim_mst_weight({0: {1: 5}, 1: {0: 5}}) == 5
    g2 = {0: {1: 1, 2: 4}, 1: {0: 1, 2: 2}, 2: {0: 4, 1: 2}}
    assert prim_mst_weight(g2) == 3


def test_04_version_and_stdlib_only():
    assert greedy_40.GREEDY_40_VERSION == "greedy-40.v1"
    assert greedy_40.stdlib_only() is True
