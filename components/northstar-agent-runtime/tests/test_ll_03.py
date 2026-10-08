"""Tests for ll_03 (detect cycle, Floyd's algorithm)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_03
from ll_03 import has_cycle, from_list, Node, LlError


def _cycle(vals, pos):
    head = from_list(vals)
    if pos < 0:
        return head
    target = head
    for _ in range(pos):
        target = target.next
    tail = head
    while tail.next is not None:
        tail = tail.next
    tail.next = target
    return head


def test_01_normal_case():
    assert has_cycle(from_list([1, 2, 3])) is False
    assert has_cycle(_cycle([1, 2, 3, 4], 1)) is True
    assert has_cycle(_cycle([1, 2, 3, 4], 0)) is True


def test_02_edge_cases():
    assert has_cycle(None) is False
    assert has_cycle(from_list([1])) is False
    node = Node(5)
    node.next = node
    assert has_cycle(node) is True


def test_03_extra():
    a = Node(1)
    b = Node(2)
    a.next = b
    assert has_cycle(a) is False
    b.next = a
    assert has_cycle(a) is True
    assert has_cycle(_cycle([1, 2], 1)) is True
    try:
        has_cycle(42)
        raised = False
    except LlError:
        raised = True
    assert raised is True


def test_04_version_and_stdlib_only():
    assert ll_03.LL_03_VERSION == "ll-03.v1"
    assert ll_03.SCHEMA_PIN == "northstar.ll-03.v1"
    assert ll_03.stdlib_only() is True
