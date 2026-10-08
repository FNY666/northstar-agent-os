"""ll-32: Find the maximum value node of a singly linked list.

A single traversal tracks the largest value seen so far.
Values must be mutually comparable; an empty list fails closed with LlError.

What this IS: a one-pass maximum-value lookup over node values.
What this IS NOT: a sort of the list or a node-pointer return.
"""

from __future__ import annotations

import ast
import pathlib

LL_32_VERSION = "ll-32.v1"
SCHEMA_PIN = "northstar.ll-32.v1"


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


def max_value(head):
    """Return the largest value in the list; fail-closed on empty input."""
    if head is None or not isinstance(head, Node):
        raise LlError("head must be a non-empty Node chain")
    best = head.val
    seen = {id(head)}
    cur = head.next
    while cur is not None:
        if id(cur) in seen:
            raise LlError("cycle detected while scanning")
        seen.add(id(cur))
        try:
            if cur.val > best:
                best = cur.val
        except TypeError:
            raise LlError("values must be mutually comparable")
        cur = cur.next
    return best

def test_max_mixed():
    assert max_value(from_list([3, 1, 4, 1, 5, 9, 2, 6])) == 9


def test_max_negatives():
    assert max_value(from_list([-5, -2, -9])) == -2


def test_max_single():
    assert max_value(from_list([42])) == 42


def test_max_strings():
    assert max_value(from_list(['b', 'a', 'c'])) == 'c'


def test_max_empty_raises():
    try:
        max_value(None)
    except LlError:
        return
    raise AssertionError('expected LlError')


def test_max_uncomparable_raises():
    try:
        max_value(from_list([1, 'a']))
    except LlError:
        return
    raise AssertionError('expected LlError')

def main():
    test_max_mixed()
    test_max_negatives()
    test_max_single()
    test_max_strings()
    test_max_empty_raises()
    test_max_uncomparable_raises()
    assert stdlib_only()
    print("ll-32 OK")


if __name__ == "__main__":
    main()
