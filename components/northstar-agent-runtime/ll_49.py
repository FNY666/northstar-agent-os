"""ll-49: Collect node values in reverse order (reverse print).

Materialises the list, then reverses the collected values.
The list itself is never mutated; the empty list yields an empty collection.

What this IS: a non-destructive reverse-order collection of node values.
What this IS NOT: a reversal of the list's links (the structure is untouched).
"""

from __future__ import annotations

import ast
import pathlib

LL_49_VERSION = "ll-49.v1"
SCHEMA_PIN = "northstar.ll-49.v1"


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


def reverse_values(head):
    """Return node values from tail to head without mutating the list."""
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    out = to_list(head)
    out.reverse()
    return out

def test_reverse_values_basic():
    assert reverse_values(from_list([1, 2, 3])) == [3, 2, 1]


def test_reverse_values_single():
    assert reverse_values(from_list([9])) == [9]


def test_reverse_values_empty():
    assert reverse_values(None) == []


def test_reverse_values_five():
    assert reverse_values(from_list([1, 2, 3, 4, 5])) == [5, 4, 3, 2, 1]


def test_reverse_values_list_untouched():
    h = from_list([1, 2, 3])
    reverse_values(h)
    assert to_list(h) == [1, 2, 3]

def main():
    test_reverse_values_basic()
    test_reverse_values_single()
    test_reverse_values_empty()
    test_reverse_values_five()
    test_reverse_values_list_untouched()
    assert stdlib_only()
    print("ll-49 OK")


if __name__ == "__main__":
    main()
