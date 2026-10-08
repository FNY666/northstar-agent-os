"""ll-27: Split a list into two halves.

Slow/fast pointers find the midpoint in one pass with O(1) extra space.
The list is cut in place; on odd length the second half takes the extra node.

What this IS: an in-place bisection of a singly linked list into (first, second).
What this IS NOT: a copy-based split or an index-based array operation.
"""

from __future__ import annotations

import ast
import pathlib

LL_27_VERSION = "ll-27.v1"
SCHEMA_PIN = "northstar.ll-27.v1"


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


def split_halves(head):
    """Split into (first_half, second_half); second half takes the odd extra node."""
    if head is None or not isinstance(head, Node):
        raise LlError("head must be a non-empty Node chain")
    if head.next is None:
        return head, None
    slow = head
    fast = head
    prev = None
    while fast is not None and fast.next is not None:
        prev = slow
        slow = slow.next
        fast = fast.next.next
    prev.next = None
    return head, slow

def test_split_even():
    a, b = split_halves(from_list([1, 2, 3, 4, 5, 6]))
    assert to_list(a) == [1, 2, 3]
    assert to_list(b) == [4, 5, 6]


def test_split_odd():
    a, b = split_halves(from_list([1, 2, 3, 4, 5]))
    assert to_list(a) == [1, 2]
    assert to_list(b) == [3, 4, 5]


def test_split_two():
    a, b = split_halves(from_list([1, 2]))
    assert to_list(a) == [1]
    assert to_list(b) == [2]


def test_split_single():
    a, b = split_halves(from_list([7]))
    assert to_list(a) == [7]
    assert b is None


def test_split_none_raises():
    try:
        split_halves(None)
    except LlError:
        return
    raise AssertionError('expected LlError')

def main():
    test_split_even()
    test_split_odd()
    test_split_two()
    test_split_single()
    test_split_none_raises()
    assert stdlib_only()
    print("ll-27 OK")


if __name__ == "__main__":
    main()
