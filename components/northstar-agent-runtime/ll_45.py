"""ll-45: Delete the second half of a singly linked list.

Keeps ceil(n/2) nodes: on odd length the middle node survives.
The list is measured once (cycle-guarded), then cut in place after the midpoint.

What this IS: an in-place truncation that keeps the first ceil(n/2) nodes.
What this IS NOT: a halving split returning two lists (see ll-27).
"""

from __future__ import annotations

import ast
import pathlib

LL_45_VERSION = "ll-45.v1"
SCHEMA_PIN = "northstar.ll-45.v1"


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


def delete_second_half(head):
    """Delete every node after the midpoint (middle survives on odd length)."""
    if head is None or not isinstance(head, Node):
        raise LlError("head must be a non-empty Node chain")
    n = 0
    seen = set()
    cur = head
    while cur is not None:
        if id(cur) in seen:
            raise LlError("cycle detected while measuring")
        seen.add(id(cur))
        n += 1
        cur = cur.next
    keep = (n + 1) // 2
    cur = head
    for _ in range(keep - 1):
        cur = cur.next
    rest = cur.next
    cur.next = None
    while rest is not None:
        nxt = rest.next
        rest.next = None
        rest = nxt
    return head

def test_delete_second_half_odd():
    assert to_list(delete_second_half(from_list([1, 2, 3, 4, 5]))) == [1, 2, 3]


def test_delete_second_half_even():
    assert to_list(delete_second_half(from_list([1, 2, 3, 4]))) == [1, 2]


def test_delete_second_half_two():
    assert to_list(delete_second_half(from_list([1, 2]))) == [1]


def test_delete_second_half_single():
    assert to_list(delete_second_half(from_list([1]))) == [1]


def test_delete_second_half_empty_raises():
    try:
        delete_second_half(None)
    except LlError:
        return
    raise AssertionError('expected LlError')

def main():
    test_delete_second_half_odd()
    test_delete_second_half_even()
    test_delete_second_half_two()
    test_delete_second_half_single()
    test_delete_second_half_empty_raises()
    assert stdlib_only()
    print("ll-45 OK")


if __name__ == "__main__":
    main()
