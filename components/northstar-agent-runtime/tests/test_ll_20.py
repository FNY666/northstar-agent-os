"""Tests for ll_20 (delete node given only the node)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_20
from ll_20 import delete_node, from_list, to_list, LlError


def test_01_normal_case():
    head = from_list([1, 2, 3, 4])
    delete_node(head.next.next)
    assert to_list(head) == [1, 2, 4]
    head = from_list([4, 5, 1, 9])
    delete_node(head.next)
    assert to_list(head) == [4, 1, 9]


def test_02_edge_cases():
    head = from_list([1, 2, 3])
    delete_node(head)
    assert to_list(head) == [2, 3]
    head = from_list([1, 2])
    delete_node(head)
    assert to_list(head) == [2]


def test_03_extra():
    head = from_list([1, 2])
    try:
        delete_node(head.next)  # tail: must fail closed
        raised = False
    except LlError:
        raised = True
    assert raised is True
    for bad in (None, "nope", 42):
        try:
            delete_node(bad)
            raised = False
        except LlError:
            raised = True
        assert raised is True, f"{bad!r} should raise"


def test_04_version_and_stdlib_only():
    assert ll_20.LL_20_VERSION == "ll-20.v1"
    assert ll_20.SCHEMA_PIN == "northstar.ll-20.v1"
    assert ll_20.stdlib_only() is True
