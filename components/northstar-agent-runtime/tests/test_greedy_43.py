"""Tests for greedy_43 (Shortest job first average waiting)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_43
from greedy_43 import sjf_avg_waiting


def test_01_normal_case():
    assert sjf_avg_waiting([6, 8, 7, 3]) == 7.0


def test_02_edge_cases():
    assert sjf_avg_waiting([]) == 0.0
    assert sjf_avg_waiting([5]) == 0.0


def test_03_extra():
    assert sjf_avg_waiting([1, 2, 3]) == 4.0 / 3.0
    assert sjf_avg_waiting([4, 4, 4]) == 4.0


def test_04_version_and_stdlib_only():
    assert greedy_43.GREEDY_43_VERSION == "greedy-43.v1"
    assert greedy_43.stdlib_only() is True
