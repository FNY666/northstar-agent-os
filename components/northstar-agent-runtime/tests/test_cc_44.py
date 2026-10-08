"""Tests for cc_44 (Formability beyond the Frobenius number)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cc_44
from cc_44 import is_formable_beyond_frobenius


def test_01_normal_case():
    assert is_formable_beyond_frobenius(3, 5, 100) is True
    assert is_formable_beyond_frobenius(4, 7, 100) is True


def test_02_edge_cases():
    assert is_formable_beyond_frobenius(3, 5, 0) is True
    assert is_formable_beyond_frobenius(3, 5, 7) is False
    assert is_formable_beyond_frobenius(3, 5, 8) is True


def test_03_extra():
    try:
        is_formable_beyond_frobenius(4, 6, 10)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    # the Frobenius number itself is never formable
    assert is_formable_beyond_frobenius(4, 7, 17) is False
    assert is_formable_beyond_frobenius(4, 7, 18) is True


def test_04_version_and_stdlib_only():
    assert cc_44.CC_44_VERSION == "cc-44.v1"
    assert cc_44.stdlib_only() is True
