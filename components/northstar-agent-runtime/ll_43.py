"""ll-43: Reverse a doubly linked list.

Swaps next/prev on every node in a single pass, returning the new head.
Both directions are verified after reversal: forward is reversed, backward is original.

What this IS: an in-place reversal that keeps every prev link consistent.
What this IS NOT: a singly linked list reversal or a copy-based reversal.
"""

from __future__ import annotations

import ast
import pathlib

LL_43_VERSION = "ll-43.v1"
SCHEMA_PIN = "northstar.ll-43.v1"


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


class DNode:
    """Doubly linked-list node; the value must never be None."""

    __slots__ = ("val", "next", "prev")

    def __init__(self, val):
        if val is None:
            raise LlError("node value must not be None")
        self.val = val
        self.next = None
        self.prev = None


def d_from_list(values):
    """Build a doubly linked list from a sequence; fail-closed on bad input."""
    if values is None:
        raise LlError("values must not be None")
    head = None
    tail = None
    for v in values:
        node = DNode(v)
        node.prev = tail
        if head is None:
            head = node
        else:
            tail.next = node
        tail = node
    return head


def d_to_list(head):
    """Materialise a doubly linked list (forward) as a Python list."""
    if head is not None and not isinstance(head, DNode):
        raise LlError("head must be a DNode or None")
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


def d_to_list_backward(head):
    """Materialise a doubly linked list from tail to head via prev links."""
    if head is not None and not isinstance(head, DNode):
        raise LlError("head must be a DNode or None")
    if head is None:
        return []
    cur = head
    seen = set()
    while cur.next is not None:
        if id(cur) in seen:
            raise LlError("cycle detected while traversing")
        seen.add(id(cur))
        cur = cur.next
    out = []
    while cur is not None:
        out.append(cur.val)
        cur = cur.prev
    return out

def d_reverse(head):
    """Reverse a doubly linked list in place; return the new head."""
    if head is not None and not isinstance(head, DNode):
        raise LlError("head must be a DNode or None")
    cur = head
    new_head = None
    while cur is not None:
        nxt = cur.next
        cur.next = cur.prev
        cur.prev = nxt
        new_head = cur
        cur = nxt
    return new_head

def test_reverse_doubly():
    h = d_reverse(d_from_list([1, 2, 3]))
    assert d_to_list(h) == [3, 2, 1]
    assert d_to_list_backward(h) == [1, 2, 3]


def test_reverse_doubly_single():
    h = d_reverse(d_from_list([7]))
    assert d_to_list(h) == [7]


def test_reverse_doubly_empty():
    assert d_reverse(None) is None


def test_reverse_doubly_prev_consistent():
    h = d_reverse(d_from_list([1, 2, 3, 4]))
    cur = h
    prev = None
    while cur is not None:
        assert cur.prev is prev
        prev = cur
        cur = cur.next
    assert d_to_list(h) == [4, 3, 2, 1]

def main():
    test_reverse_doubly()
    test_reverse_doubly_single()
    test_reverse_doubly_empty()
    test_reverse_doubly_prev_consistent()
    assert stdlib_only()
    print("ll-43 OK")


if __name__ == "__main__":
    main()
