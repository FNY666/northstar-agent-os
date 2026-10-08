"""Tests for ll_11 (intersection of two lists, by node reference)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_11
from ll_11 import get_intersection, from_list, Node, LlError


def _tail(head):
    cur = head
    while cur.next is not None:
        cur = cur.next
    return cur


def _shared(a_vals, b_vals, shared_vals):
    shared = from_list(shared_vals)
    a = from_list(a_vals)
    b = from_list(b_vals)
    _tail(a).next = shared
    _tail(b).next = shared
    return a, b, shared


def test_01_normal_case():
    a, b, shared = _shared([1, 2], [3, 4, 5], [7, 8, 9])
    assert get_intersection(a, b) is shared
    assert get_intersection(a, b).val == 7


def test_02_edge_cases():
    assert get_intersection(from_list([1, 2]), from_list([1, 2])) is None
    assert get_intersection(None, from_list([1])) is None
    assert get_intersection(from_list([1]), None) is None
    assert get_intersection(None, None) is None


def test_03_extra():
    head = from_list([1, 2, 3])
    assert get_intersection(head, head) is head
    a, b, shared = _shared([], [], [4, 5])
    assert get_intersection(a, b) is shared
    try:
        get_intersection([1], None)
        raised = False
    except LlError:
        raised = True
    assert raised is True


def test_04_version_and_stdlib_only():
    assert ll_11.LL_11_VERSION == "ll-11.v1"
    assert ll_11.SCHEMA_PIN == "northstar.ll-11.v1"
    assert ll_11.stdlib_only() is True
