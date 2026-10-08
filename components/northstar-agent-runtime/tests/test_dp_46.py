"""Tests for dp_46 (Ugly number II)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dp_46
from dp_46 import nth_ugly


def test_01_normal_case():
    assert nth_ugly(10) == 12
    assert nth_ugly(1) == 1


def test_02_edge_cases():
    assert nth_ugly(2) == 2
    try:
        nth_ugly(-3)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_03_extra():
    assert nth_ugly(100) == 1536
    assert nth_ugly(15) == 24


def test_04_version_and_stdlib_only():
    assert dp_46.DP_46_VERSION == "dp-46.v1"
    assert dp_46.stdlib_only() is True
