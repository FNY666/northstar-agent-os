"""ll-36: Doubly linked list: insert, delete, and traverse.

DNode carries prev/next links; every mutation keeps both directions consistent.
Forward and backward traversals are both provided and cross-checked in tests.

What this IS: a doubly linked list with head/tail insert, first-match delete, and both traversals.
What this IS NOT: a singly linked list with a prev attribute bolted on afterwards.
"""

from __future__ import annotations

import ast
import pathlib

LL_36_VERSION = "ll-36.v1"
SCHEMA_PIN = "northstar.ll-36.v1"


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

def d_insert_head(head, val):
    """Prepend val to a doubly linked list; return the new head."""
    if head is not None and not isinstance(head, DNode):
        raise LlError("head must be a DNode or None")
    node = DNode(val)
    node.next = head
    if head is not None:
        head.prev = node
    return node


def d_insert_tail(head, val):
    """Append val to a doubly linked list; return the (possibly new) head."""
    if head is not None and not isinstance(head, DNode):
        raise LlError("head must be a DNode or None")
    node = DNode(val)
    if head is None:
        return node
    cur = head
    while cur.next is not None:
        cur = cur.next
    cur.next = node
    node.prev = cur
    return head


def d_delete_first(head, target):
    """Delete the first DNode with value == target; return (head, deleted)."""
    if head is not None and not isinstance(head, DNode):
        raise LlError("head must be a DNode or None")
    cur = head
    while cur is not None:
        if cur.val == target:
            if cur.prev is not None:
                cur.prev.next = cur.next
            else:
                head = cur.next
            if cur.next is not None:
                cur.next.prev = cur.prev
            cur.next = None
            cur.prev = None
            return head, True
        cur = cur.next
    return head, False

def test_doubly_roundtrip():
    h = d_from_list([1, 2, 3])
    assert d_to_list(h) == [1, 2, 3]
    assert d_to_list_backward(h) == [3, 2, 1]


def test_doubly_insert_head():
    h = d_insert_head(d_from_list([1, 2]), 0)
    assert d_to_list(h) == [0, 1, 2]
    assert d_to_list_backward(h) == [2, 1, 0]


def test_doubly_insert_tail():
    h = d_insert_tail(d_from_list([1, 2]), 3)
    assert d_to_list(h) == [1, 2, 3]
    assert d_to_list_backward(h) == [3, 2, 1]


def test_doubly_delete_middle():
    h, ok = d_delete_first(d_from_list([1, 2, 3]), 2)
    assert ok is True
    assert d_to_list(h) == [1, 3]
    assert d_to_list_backward(h) == [3, 1]


def test_doubly_delete_head():
    h, ok = d_delete_first(d_from_list([1, 2, 3]), 1)
    assert ok is True
    assert d_to_list(h) == [2, 3]
    assert h.prev is None


def test_doubly_delete_missing():
    h, ok = d_delete_first(d_from_list([1, 2]), 99)
    assert ok is False
    assert d_to_list(h) == [1, 2]

def main():
    test_doubly_roundtrip()
    test_doubly_insert_head()
    test_doubly_insert_tail()
    test_doubly_delete_middle()
    test_doubly_delete_head()
    test_doubly_delete_missing()
    assert stdlib_only()
    print("ll-36 OK")


if __name__ == "__main__":
    main()
