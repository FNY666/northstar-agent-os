"""ll-47: Remove all nodes with a value greater than x.

A single scan unlinks every node whose value exceeds the threshold x.
Values must be numeric and comparable with x; anything else fails closed.

What this IS: a threshold filter that unlinks all nodes with value > x.
What this IS NOT: a first-occurrence deletion (see ll-35) or a keep-greater filter.
"""

from __future__ import annotations

import ast
import pathlib

LL_47_VERSION = "ll-47.v1"
SCHEMA_PIN = "northstar.ll-47.v1"


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


def remove_greater(head, x):
    """Unlink every node with value > x; return the new head."""
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        raise LlError("x must be a number")
    dummy = Node(0)
    dummy.next = head
    prev = dummy
    cur = head
    seen = set()
    while cur is not None:
        if id(cur) in seen:
            raise LlError("cycle detected while filtering")
        seen.add(id(cur))
        try:
            too_big = cur.val > x
        except TypeError:
            raise LlError("values must be comparable with x")
        if too_big:
            prev.next = cur.next
            cur.next = None
            cur = prev.next
        else:
            prev = cur
            cur = cur.next
    return dummy.next

def test_remove_greater_some():
    assert to_list(remove_greater(from_list([1, 5, 2, 8, 3]), 4)) == [1, 2, 3]


def test_remove_greater_all():
    assert to_list(remove_greater(from_list([5, 6, 7]), 4)) == []


def test_remove_greater_none():
    assert to_list(remove_greater(from_list([1, 2, 3]), 4)) == [1, 2, 3]


def test_remove_greater_head():
    assert to_list(remove_greater(from_list([9, 1, 2]), 4)) == [1, 2]


def test_remove_greater_empty():
    assert to_list(remove_greater(None, 4)) == []


def test_remove_greater_bad_x_raises():
    try:
        remove_greater(from_list([1, 2]), 'x')
    except LlError:
        return
    raise AssertionError('expected LlError')

def main():
    test_remove_greater_some()
    test_remove_greater_all()
    test_remove_greater_none()
    test_remove_greater_head()
    test_remove_greater_empty()
    test_remove_greater_bad_x_raises()
    assert stdlib_only()
    print("ll-47 OK")


if __name__ == "__main__":
    main()
