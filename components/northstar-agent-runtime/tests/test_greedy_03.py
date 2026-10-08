"""Tests for greedy_03 (Job sequencing with deadlines)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import greedy_03
from greedy_03 import job_sequencing


def test_01_normal_case():
    ids, profit = job_sequencing([("a", 2, 100), ("b", 1, 19), ("c", 2, 27), ("d", 1, 25), ("e", 3, 15)])
    assert profit == 142
    assert set(ids) == {"a", "c", "e"}


def test_02_edge_cases():
    assert job_sequencing([]) == ([], 0)
    ids, profit = job_sequencing([("x", 1, 5)])
    assert (ids, profit) == (["x"], 5)


def test_03_extra():
    ids, profit = job_sequencing([("a", 1, 10), ("b", 1, 20)])
    assert (ids, profit) == (["b"], 20)


def test_04_version_and_stdlib_only():
    assert greedy_03.GREEDY_03_VERSION == "greedy-03.v1"
    assert greedy_03.stdlib_only() is True
