"""Tests for greedy_39 (Dijkstra shortest paths (simplified))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_39
from greedy_39 import dijkstra


def test_01_normal_case():
    g = {"a": {"b": 4, "c": 2}, "b": {"c": 1, "d": 5}, "c": {"d": 8, "e": 10}, "d": {"e": 2}, "e": {}}
    assert dijkstra(g, "a") == {"a": 0, "b": 4, "c": 2, "d": 9, "e": 11}


def test_02_edge_cases():
    assert dijkstra({"s": {}}, "s") == {"s": 0}


def test_03_extra():
    g2 = {"a": {"b": 1}, "b": {}, "c": {}}
    assert dijkstra(g2, "a")["c"] == float("inf")
    assert dijkstra({"a": {"b": 3}, "b": {"a": 3}}, "b") == {"a": 3, "b": 0}


def test_04_version_and_stdlib_only():
    assert greedy_39.GREEDY_39_VERSION == "greedy-39.v1"
    assert greedy_39.stdlib_only() is True
