"""Tests for lis-40 (LIS over characters of a string)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_40
from lis_40 import lis_string


def test_01_normal_case():
    assert lis_string("abcde") == 5
    assert lis_string("abca") == 3
    assert lis_string("azbycx") == 3


def test_02_edge_cases():
    assert lis_string("") == 0
    assert lis_string("z") == 1
    assert lis_string("edcba") == 1
    assert lis_string("aaa") == 1


def test_03_validation():
    try:
        lis_string(123)
        raise AssertionError('expected ValueError')
    except ValueError:
        pass
    try:
        lis_string(['a'])
        raise AssertionError('expected ValueError')
    except ValueError:
        pass

def test_04_version_and_stdlib_only():
    assert lis_40.LIS_40_VERSION == "lis-40.v1"
    assert lis_40.stdlib_only() is True
