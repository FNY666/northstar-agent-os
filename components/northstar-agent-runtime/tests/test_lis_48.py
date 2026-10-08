"""Tests for lis-48 (Online streaming LIS)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import lis_48
from lis_48 import OnlineLIS


def test_01_normal_case():
    o = OnlineLIS()
    for x in [10, 9, 2, 5, 3, 7, 101, 18]:
        o.append(x)
    assert o.length() == 4
    o2 = OnlineLIS()
    for x in [1, 2, 3, 4]:
        o2.append(x)
    assert o2.length() == 4


def test_02_edge_cases():
    assert OnlineLIS().length() == 0
    o = OnlineLIS()
    o.append(5)
    assert o.length() == 1
    o3 = OnlineLIS()
    for x in [3, 2, 1]:
        o3.append(x)
    assert o3.length() == 1


def test_03_validation_and_monotone():
    o = OnlineLIS()
    try:
        o.append('x')
        raise AssertionError('expected ValueError')
    except ValueError:
        pass
    import random
    random.seed(48)
    o2 = OnlineLIS()
    prev = 0
    for _ in range(30):
        o2.append(random.randint(0, 9))
        assert o2.length() >= prev
        prev = o2.length()

def test_04_version_and_stdlib_only():
    assert lis_48.LIS_48_VERSION == "lis-48.v1"
    assert lis_48.stdlib_only() is True
