"""ll-48: Intersection of two lists by value (common values).

Collects the values present in both lists, deduplicated, in first-list order.
Values must be hashable; cyclic input fails closed with LlError.

What this IS: a value-level set intersection preserving first-list order.
What this IS NOT: a node-identity intersection of two lists sharing tail nodes.
"""

from __future__ import annotations

import ast
import pathlib

LL_48_VERSION = "ll-48.v1"
SCHEMA_PIN = "northstar.ll-48.v1"


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


def intersect_values(a, b):
    """Return the deduplicated values present in both lists, in a's order."""
    for name, h in (("a", a), ("b", b)):
        if h is not None and not isinstance(h, Node):
            raise LlError(name + " must be a Node or None")
    b_vals = set()
    seen = set()
    cur = b
    while cur is not None:
        if id(cur) in seen:
            raise LlError("cycle detected in b")
        seen.add(id(cur))
        try:
            b_vals.add(cur.val)
        except TypeError:
            raise LlError("values must be hashable")
        cur = cur.next
    out = []
    seen_out = set()
    seen = set()
    cur = a
    while cur is not None:
        if id(cur) in seen:
            raise LlError("cycle detected in a")
        seen.add(id(cur))
        try:
            key = cur.val
            hit = key in b_vals and key not in seen_out
        except TypeError:
            raise LlError("values must be hashable")
        if hit:
            seen_out.add(key)
            out.append(key)
        cur = cur.next
    return out

def test_intersect_some():
    assert intersect_values(from_list([1, 2, 3, 4]), from_list([3, 4, 5])) == [3, 4]


def test_intersect_none():
    assert intersect_values(from_list([1, 2]), from_list([3, 4])) == []


def test_intersect_dedup():
    assert intersect_values(from_list([1, 1, 2, 2]), from_list([2, 2, 3])) == [2]


def test_intersect_a_empty():
    assert intersect_values(None, from_list([1])) == []


def test_intersect_both_empty():
    assert intersect_values(None, None) == []


def test_intersect_order_of_a():
    assert intersect_values(from_list([4, 3, 2, 1]), from_list([1, 2, 3, 4])) == [4, 3, 2, 1]

def main():
    test_intersect_some()
    test_intersect_none()
    test_intersect_dedup()
    test_intersect_a_empty()
    test_intersect_both_empty()
    test_intersect_order_of_a()
    assert stdlib_only()
    print("ll-48 OK")


if __name__ == "__main__":
    main()
