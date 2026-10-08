"""ll-29: Count the nodes of a singly linked list.

A single linear traversal with an identity set, so cyclic input fails closed.
The empty list counts as zero; anything that is not a Node chain is rejected.

What this IS: a cycle-guarded O(n) node count.
What this IS NOT: a length cached on a wrapper object or a recursive count.
"""

from __future__ import annotations

import ast
import pathlib

LL_29_VERSION = "ll-29.v1"
SCHEMA_PIN = "northstar.ll-29.v1"


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


def count_nodes(head):
    """Return the number of nodes; raise LlError on cycles or bad input."""
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    n = 0
    seen = set()
    cur = head
    while cur is not None:
        if id(cur) in seen:
            raise LlError("cycle detected while counting")
        seen.add(id(cur))
        n += 1
        cur = cur.next
    return n

def test_count_empty():
    assert count_nodes(None) == 0


def test_count_single():
    assert count_nodes(from_list([1])) == 1


def test_count_ten():
    assert count_nodes(from_list(list(range(10)))) == 10


def test_count_bad_head_raises():
    try:
        count_nodes('nope')
    except LlError:
        return
    raise AssertionError('expected LlError')


def test_count_cycle_raises():
    h = from_list([1, 2, 3])
    tail = h
    while tail.next is not None:
        tail = tail.next
    tail.next = h
    try:
        count_nodes(h)
    except LlError:
        return
    raise AssertionError('expected LlError')

def main():
    test_count_empty()
    test_count_single()
    test_count_ten()
    test_count_bad_head_raises()
    test_count_cycle_raises()
    assert stdlib_only()
    print("ll-29 OK")


if __name__ == "__main__":
    main()
