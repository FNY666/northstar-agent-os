"""ll-39: Compare two singly linked lists for equality.

Walks both lists in lockstep; equal means same values in the same order.
Different lengths or any value mismatch yields False; cycles fail closed.

What this IS: a lockstep structural-and-value equality check.
What this IS NOT: an identity (is) comparison or a set-based comparison.
"""

from __future__ import annotations

import ast
import pathlib

LL_39_VERSION = "ll-39.v1"
SCHEMA_PIN = "northstar.ll-39.v1"


class LlError(Exception):
    """Fail-closed: raised on any invalid input or invariant violation."""


class Node:
    """Singly linked-list node; the value must never be None."""

    __slots__ = ("val", "next")

    def __init__(self, val):
        if val is None:
            raise LlError("node value must not be None")
        self.val = val
        self.next = None


def from_list(values):
    """Build a singly linked list from a sequence; fail-closed on bad input."""
    if values is None:
        raise LlError("values must not be None")
    head = None
    tail = None
    for v in values:
        node = Node(v)
        if head is None:
            head = node
        else:
            tail.next = node
        tail = node
    return head


def to_list(head):
    """Materialise a linked list as a Python list; fail-closed on cycles."""
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    out = []
    seen = set()
    cur = head
    while cur is not None:
        if id(cur) in seen:
            raise LlError("cycle detected while traversing")
        seen.add(id(cur))
        out.append(cur.val)
        cur = cur.next
    return out


_ALLOWED_IMPORTS = {"__future__", "ast", "pathlib"}


def stdlib_only():
    """AST check: this module may only import whitelisted stdlib modules."""
    src = pathlib.Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [(node.module or "").split(".")[0]]
        else:
            continue
        for name in names:
            if name not in _ALLOWED_IMPORTS:
                raise LlError("disallowed import: %r" % (name,))
    return True


def lists_equal(a, b):
    """Return True when a and b hold the same values in the same order."""
    for name, h in (("a", a), ("b", b)):
        if h is not None and not isinstance(h, Node):
            raise LlError(name + " must be a Node or None")
    pa, pb = a, b
    seen_a, seen_b = set(), set()
    while pa is not None and pb is not None:
        if id(pa) in seen_a or id(pb) in seen_b:
            raise LlError("cycle detected while comparing")
        seen_a.add(id(pa))
        seen_b.add(id(pb))
        if pa.val != pb.val:
            return False
        pa = pa.next
        pb = pb.next
    return pa is None and pb is None

def test_equal_lists():
    assert lists_equal(from_list([1, 2, 3]), from_list([1, 2, 3])) is True


def test_different_values():
    assert lists_equal(from_list([1, 2, 3]), from_list([1, 2, 4])) is False


def test_different_lengths():
    assert lists_equal(from_list([1, 2]), from_list([1, 2, 3])) is False


def test_both_empty():
    assert lists_equal(None, None) is True


def test_one_empty():
    assert lists_equal(None, from_list([1])) is False


def test_bad_input_raises():
    try:
        lists_equal(from_list([1]), 'x')
    except LlError:
        return
    raise AssertionError('expected LlError')

def main():
    test_equal_lists()
    test_different_values()
    test_different_lengths()
    test_both_empty()
    test_one_empty()
    test_bad_input_raises()
    assert stdlib_only()
    print("ll-39 OK")


if __name__ == "__main__":
    main()
