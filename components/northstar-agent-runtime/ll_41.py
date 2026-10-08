"""ll-41: Insertion sort on a singly linked list.

Builds the sorted result by inserting each node into its sorted position.
Runs in place with O(1) extra space; the sort is stable for equal values.

What this IS: an in-place, stable insertion sort over linked-list nodes.
What this IS NOT: a copy into an array followed by a builtin sort.
"""

from __future__ import annotations

import ast
import pathlib

LL_41_VERSION = "ll-41.v1"
SCHEMA_PIN = "northstar.ll-41.v1"


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


def insertion_sort(head):
    """Sort the list in place with insertion sort; return the new head."""
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    dummy = Node(0)
    cur = head
    seen = set()
    while cur is not None:
        if id(cur) in seen:
            raise LlError("cycle detected while sorting")
        seen.add(id(cur))
        nxt = cur.next
        pos = dummy
        while pos.next is not None and pos.next.val < cur.val:
            pos = pos.next
        cur.next = pos.next
        pos.next = cur
        cur = nxt
    return dummy.next

def test_insertion_sort_unsorted():
    assert to_list(insertion_sort(from_list([4, 2, 1, 3]))) == [1, 2, 3, 4]


def test_insertion_sort_reversed():
    assert to_list(insertion_sort(from_list([5, 4, 3, 2, 1]))) == [1, 2, 3, 4, 5]


def test_insertion_sort_sorted():
    assert to_list(insertion_sort(from_list([1, 2, 3]))) == [1, 2, 3]


def test_insertion_sort_duplicates():
    assert to_list(insertion_sort(from_list([3, 1, 3, 2, 1]))) == [1, 1, 2, 3, 3]


def test_insertion_sort_empty():
    assert to_list(insertion_sort(None)) == []


def test_insertion_sort_single():
    assert to_list(insertion_sort(from_list([7]))) == [7]

def main():
    test_insertion_sort_unsorted()
    test_insertion_sort_reversed()
    test_insertion_sort_sorted()
    test_insertion_sort_duplicates()
    test_insertion_sort_empty()
    test_insertion_sort_single()
    assert stdlib_only()
    print("ll-41 OK")


if __name__ == "__main__":
    main()
