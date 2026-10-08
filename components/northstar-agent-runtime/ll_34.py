"""ll-34: Insert a value at the head and at the tail.

Two primitive builders: insert_head prepends in O(1), insert_tail appends in O(n).
Both return the (possibly new) head; a None value fails closed with LlError.

What this IS: pure functions returning the new head after head/tail insertion.
What this IS NOT: a wrapper class with hidden mutable state.
"""

from __future__ import annotations

import ast
import pathlib

LL_34_VERSION = "ll-34.v1"
SCHEMA_PIN = "northstar.ll-34.v1"


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


def insert_head(head, val):
    """Prepend val; return the new head."""
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    node = Node(val)
    node.next = head
    return node


def insert_tail(head, val):
    """Append val; return the (possibly new) head."""
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    node = Node(val)
    if head is None:
        return node
    cur = head
    seen = {id(head)}
    while cur.next is not None:
        if id(cur.next) in seen:
            raise LlError("cycle detected while appending")
        seen.add(id(cur.next))
        cur = cur.next
    cur.next = node
    return head

def test_insert_head_nonempty():
    assert to_list(insert_head(from_list([2, 3]), 1)) == [1, 2, 3]


def test_insert_head_empty():
    assert to_list(insert_head(None, 9)) == [9]


def test_insert_tail_nonempty():
    assert to_list(insert_tail(from_list([1, 2]), 3)) == [1, 2, 3]


def test_insert_tail_empty():
    assert to_list(insert_tail(None, 5)) == [5]


def test_insert_none_value_raises():
    try:
        insert_head(None, None)
    except LlError:
        return
    raise AssertionError('expected LlError')

def main():
    test_insert_head_nonempty()
    test_insert_head_empty()
    test_insert_tail_nonempty()
    test_insert_tail_empty()
    test_insert_none_value_raises()
    assert stdlib_only()
    print("ll-34 OK")


if __name__ == "__main__":
    main()
