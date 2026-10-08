"""Tests for ll_23 (cycle length, 0 if no cycle)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_23
from ll_23 import cycle_length, from_list, Node, LlError


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
    assert cycle_length(_cycle([1, 2, 3, 4, 5], 2)) == 3
    assert cycle_length(_cycle([1, 2, 3], 0)) == 3
    assert cycle_length(_cycle([1, 2, 3, 4], 3)) == 1


def test_02_edge_cases():
    assert cycle_length(from_list([1, 2, 3, 4])) == 0
    assert cycle_length(None) == 0
    assert cycle_length(from_list([1])) == 0


def test_03_extra():
    node = Node(9)
    node.next = node
    assert cycle_length(node) == 1
    assert cycle_length(_cycle([1, 2], 1)) == 1
    try:
        cycle_length("bad")
        raised = False
    except LlError:
        raised = True
    assert raised is True


def test_04_version_and_stdlib_only():
    assert ll_23.LL_23_VERSION == "ll-23.v1"
    assert ll_23.SCHEMA_PIN == "northstar.ll-23.v1"
    assert ll_23.stdlib_only() is True
