"""Tests for cc_50 (Change-making summary)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_50
from cc_50 import change_summary


def test_01_normal_case():
    s = change_summary(5, [1, 2, 5])
    assert s["feasible"] is True
    assert s["min_coins"] == 1
    assert s["num_ways"] == 4


def test_02_edge_cases():
    s = change_summary(3, [2])
    assert s["feasible"] is False
    assert s["min_coins"] == -1
    assert s["num_ways"] == 0
    s = change_summary(0, [2])
    assert s["feasible"] is True and s["min_coins"] == 0


def test_03_extra():
    try:
        change_summary(-1, [1])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    s = change_summary(11, [1, 2, 5])
    assert s["min_coins"] == 3 and s["num_ways"] == 11


def test_04_version_and_stdlib_only():
    assert cc_50.CC_50_VERSION == "cc-50.v1"
    assert cc_50.stdlib_only() is True
