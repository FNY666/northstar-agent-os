"""ll-44: Doubly linked list to array roundtrip.

Array -> doubly list -> array must reproduce the input exactly.
The roundtrip also asserts every prev link points at the true predecessor.

What this IS: a lossless array/doubly-list conversion pair with prev-link verification.
What this IS NOT: a singly linked list roundtrip (see ll-50).
"""

from __future__ import annotations

import ast
import pathlib

LL_44_VERSION = "ll-44.v1"
SCHEMA_PIN = "northstar.ll-44.v1"


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

def d_to_array(head):
    """Materialise a doubly linked list as a Python list (forward)."""
    return d_to_list(head)


def d_from_array(values):
    """Build a doubly linked list from a Python list."""
    return d_from_list(values)


def d_roundtrip(values):
    """Array -> doubly list -> array, verifying prev links on the way."""
    head = d_from_array(values)
    cur = head
    prev = None
    while cur is not None:
        if cur.prev is not prev:
            raise LlError("prev-link invariant broken")
        prev = cur
        cur = cur.next
    return d_to_array(head)

def test_doubly_roundtrip():
    assert d_roundtrip([1, 2, 3, 4]) == [1, 2, 3, 4]


def test_doubly_roundtrip_empty():
    assert d_roundtrip([]) == []


def test_doubly_roundtrip_single():
    assert d_roundtrip([9]) == [9]


def test_doubly_backward_values():
    h = d_from_array([1, 2, 3])
    assert d_to_list_backward(h) == [3, 2, 1]


def test_doubly_from_none_raises():
    try:
        d_from_array(None)
    except LlError:
        return
    raise AssertionError('expected LlError')

def main():
    test_doubly_roundtrip()
    test_doubly_roundtrip_empty()
    test_doubly_roundtrip_single()
    test_doubly_backward_values()
    test_doubly_from_none_raises()
    assert stdlib_only()
    print("ll-44 OK")


if __name__ == "__main__":
    main()
