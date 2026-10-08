"""ll-33: Search a singly linked list for a value.

A linear scan returns the 0-based index of the first matching node.
Returns -1 when the value is absent; the empty list simply yields -1.

What this IS: a first-occurrence index search over node values.
What this IS NOT: a boolean membership test or a binary search (the list is unsorted).
"""

from __future__ import annotations

import ast
import pathlib

LL_33_VERSION = "ll-33.v1"
SCHEMA_PIN = "northstar.ll-33.v1"


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


def search(head, target):
    """Return the 0-based index of the first node equal to target, else -1."""
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    idx = 0
    seen = set()
    cur = head
    while cur is not None:
        if id(cur) in seen:
            raise LlError("cycle detected while searching")
        seen.add(id(cur))
        if cur.val == target:
            return idx
        idx += 1
        cur = cur.next
    return -1

def test_search_head():
    assert search(from_list([10, 20, 30]), 10) == 0


def test_search_tail():
    assert search(from_list([10, 20, 30]), 30) == 2


def test_search_first_occurrence():
    assert search(from_list([5, 5, 5]), 5) == 0


def test_search_missing():
    assert search(from_list([10, 20, 30]), 99) == -1


def test_search_empty():
    assert search(None, 1) == -1

def main():
    test_search_head()
    test_search_tail()
    test_search_first_occurrence()
    test_search_missing()
    test_search_empty()
    assert stdlib_only()
    print("ll-33 OK")


if __name__ == "__main__":
    main()
