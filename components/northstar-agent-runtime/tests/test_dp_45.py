"""Tests for dp_45 (Integer break)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_45
from dp_45 import integer_break


def test_01_normal_case():
    assert integer_break(10) == 36
    assert integer_break(2) == 1


def test_02_edge_cases():
    assert integer_break(3) == 2
    try:
        integer_break(1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_03_extra():
    assert integer_break(7) == 12
    assert integer_break(9) == 27


def test_04_version_and_stdlib_only():
    assert dp_45.DP_45_VERSION == "dp-45.v1"
    assert dp_45.stdlib_only() is True
