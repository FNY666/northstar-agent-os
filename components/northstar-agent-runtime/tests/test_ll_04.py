"""Tests for ll_04 (find cycle start node)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_04
from ll_04 import find_cycle_start, from_list, Node, LlError


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


def _at(head, idx):
    cur = head
    for _ in range(idx):
        cur = cur.next
    return cur


def test_01_normal_case():
    head = _cycle([1, 2, 3, 4, 5], 2)
    start = find_cycle_start(head)
    assert start is _at(head, 2)
    assert start.val == 3


def test_02_edge_cases():
    assert find_cycle_start(None) is None
    assert find_cycle_start(from_list([1])) is None
    assert find_cycle_start(from_list([1, 2, 3])) is None
    node = Node(7)
    node.next = node
    assert find_cycle_start(node) is node


def test_03_extra():
    head = _cycle([1, 2, 3], 0)
    assert find_cycle_start(head) is head
    head = _cycle([10, 20, 30], 1)
    assert find_cycle_start(head).val == 20
    try:
        find_cycle_start("bad")
        raised = False
    except LlError:
        raised = True
    assert raised is True


def test_04_version_and_stdlib_only():
    assert ll_04.LL_04_VERSION == "ll-04.v1"
    assert ll_04.SCHEMA_PIN == "northstar.ll-04.v1"
    assert ll_04.stdlib_only() is True
