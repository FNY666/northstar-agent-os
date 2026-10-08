"""ll-30: Find the kth node from the end of the list.

A lead pointer runs k steps ahead, then both advance together: one pass, O(1) space.
k is 1-based, so k=1 is the last node; out-of-range k fails closed with LlError.

What this IS: a two-pointer kth-from-end lookup returning the node's value.
What this IS NOT: a length-first two-pass scan or an index-from-head lookup.
"""

from __future__ import annotations

import ast
import pathlib

LL_30_VERSION = "ll-30.v1"
SCHEMA_PIN = "northstar.ll-30.v1"


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


def kth_from_end(head, k):
    """Return the value k nodes from the end (k=1 is the last node)."""
    if head is None or not isinstance(head, Node):
        raise LlError("head must be a non-empty Node chain")
    if not isinstance(k, int) or isinstance(k, bool) or k < 1:
        raise LlError("k must be a positive integer")
    lead = head
    for _ in range(k):
        if lead is None:
            raise LlError("k exceeds the list length")
        lead = lead.next
    cur = head
    while lead is not None:
        lead = lead.next
        cur = cur.next
    return cur.val

def test_kth_two_from_end():
    assert kth_from_end(from_list([1, 2, 3, 4, 5]), 2) == 4


def test_kth_last():
    assert kth_from_end(from_list([1, 2, 3, 4, 5]), 1) == 5


def test_kth_first():
    assert kth_from_end(from_list([1, 2, 3, 4, 5]), 5) == 1


def test_kth_too_large_raises():
    try:
        kth_from_end(from_list([1, 2, 3]), 6)
    except LlError:
        return
    raise AssertionError('expected LlError')


def test_kth_zero_raises():
    try:
        kth_from_end(from_list([1, 2, 3]), 0)
    except LlError:
        return
    raise AssertionError('expected LlError')


def test_kth_empty_raises():
    try:
        kth_from_end(None, 1)
    except LlError:
        return
    raise AssertionError('expected LlError')

def main():
    test_kth_two_from_end()
    test_kth_last()
    test_kth_first()
    test_kth_too_large_raises()
    test_kth_zero_raises()
    test_kth_empty_raises()
    assert stdlib_only()
    print("ll-30 OK")


if __name__ == "__main__":
    main()
