"""Tests for ll_06 (middle of linked list)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_06
from ll_06 import middle_node, from_list, to_list, LlError


def test_01_normal_case():
    assert middle_node(from_list([1, 2, 3, 4, 5])).val == 3
    assert middle_node(from_list([1, 2, 3, 4, 5, 6])).val == 4
    assert to_list(middle_node(from_list([1, 2, 3, 4, 5]))) == [3, 4, 5]


def test_02_edge_cases():
    assert middle_node(None) is None
    assert middle_node(from_list([9])).val == 9
    assert middle_node(from_list([1, 2])).val == 2


def test_03_extra():
    assert middle_node(from_list(list(range(1, 101)))).val == 51
    assert middle_node(from_list([1, 2, 3, 4])).val == 3
    try:
        middle_node(123)
        raised = False
    except LlError:
        raised = True
    assert raised is True


def test_04_version_and_stdlib_only():
    assert ll_06.LL_06_VERSION == "ll-06.v1"
    assert ll_06.SCHEMA_PIN == "northstar.ll-06.v1"
    assert ll_06.stdlib_only() is True
