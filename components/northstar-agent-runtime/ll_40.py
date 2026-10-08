"""ll-40: Split a list into k parts.

Parts are as even as possible: earlier parts get the extra nodes first.
Always returns exactly k heads; trailing parts are None when k exceeds the length.

What this IS: a length-aware partition into exactly k (possibly empty) sublists.
What this IS NOT: a halving split (see ll-27) or a value-based grouping.
"""

from __future__ import annotations

import ast
import pathlib

LL_40_VERSION = "ll-40.v1"
SCHEMA_PIN = "northstar.ll-40.v1"


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


def split_k(head, k):
    """Split into k parts as evenly as possible; return a list of k heads."""
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    if not isinstance(k, int) or isinstance(k, bool) or k < 1:
        raise LlError("k must be a positive integer")
    n = 0
    seen = set()
    cur = head
    while cur is not None:
        if id(cur) in seen:
            raise LlError("cycle detected while measuring")
        seen.add(id(cur))
        n += 1
        cur = cur.next
    parts = []
    cur = head
    base, extra = divmod(n, k)
    for i in range(k):
        size = base + (1 if i < extra else 0)
        part_head = cur
        for _ in range(max(size - 1, 0)):
            cur = cur.next
        if cur is not None:
            nxt = cur.next
            cur.next = None
            cur = nxt
        parts.append(part_head)
    return parts

def test_split_k_evenish():
    parts = split_k(from_list([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]), 3)
    assert [to_list(p) for p in parts] == [[1, 2, 3, 4], [5, 6, 7], [8, 9, 10]]


def test_split_k_more_parts_than_nodes():
    parts = split_k(from_list([1, 2, 3]), 5)
    assert [to_list(p) for p in parts] == [[1], [2], [3], [], []]


def test_split_k_one():
    parts = split_k(from_list([1, 2, 3]), 1)
    assert [to_list(p) for p in parts] == [[1, 2, 3]]


def test_split_k_empty():
    parts = split_k(None, 3)
    assert parts == [None, None, None]


def test_split_k_zero_raises():
    try:
        split_k(from_list([1, 2]), 0)
    except LlError:
        return
    raise AssertionError('expected LlError')

def main():
    test_split_k_evenish()
    test_split_k_more_parts_than_nodes()
    test_split_k_one()
    test_split_k_empty()
    test_split_k_zero_raises()
    assert stdlib_only()
    print("ll-40 OK")


if __name__ == "__main__":
    main()
