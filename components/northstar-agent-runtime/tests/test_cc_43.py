"""Tests for cc_43 (Frobenius number (two coprime denominations))."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_43
from cc_43 import frobenius_two


def test_01_normal_case():
    assert frobenius_two(3, 5) == 7
    assert frobenius_two(4, 7) == 17


def test_02_edge_cases():
    assert frobenius_two(1, 7) == -1
    assert frobenius_two(2, 3) == 1


def test_03_extra():
    try:
        frobenius_two(4, 6)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    try:
        frobenius_two(0, 5)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_04_version_and_stdlib_only():
    assert cc_43.CC_43_VERSION == "cc-43.v1"
    assert cc_43.stdlib_only() is True
