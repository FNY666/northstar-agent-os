"""ll-31: Sum all values of a singly linked list.

A single traversal accumulates the total; every value must be numeric.
Booleans and non-numeric values fail closed with LlError instead of coercing.

What this IS: a cycle-guarded numeric summation over node values.
What this IS NOT: a string concatenation or a coercion of arbitrary objects.
"""

from __future__ import annotations

import ast
import pathlib

LL_31_VERSION = "ll-31.v1"
SCHEMA_PIN = "northstar.ll-31.v1"


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


def sum_values(head):
    """Return the sum of all node values; the empty list sums to 0."""
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    total = 0
    seen = set()
    cur = head
    while cur is not None:
        if id(cur) in seen:
            raise LlError("cycle detected while summing")
        seen.add(id(cur))
        if isinstance(cur.val, bool) or not isinstance(cur.val, (int, float)):
            raise LlError("all values must be numeric")
        total += cur.val
        cur = cur.next
    return total

def test_sum_ints():
    assert sum_values(from_list([1, 2, 3, 4])) == 10


def test_sum_empty():
    assert sum_values(None) == 0


def test_sum_floats():
    assert sum_values(from_list([1.5, 2.5])) == 4.0


def test_sum_negative():
    assert sum_values(from_list([-3, 5, -2])) == 0


def test_sum_non_numeric_raises():
    try:
        sum_values(from_list(['a', 'b']))
    except LlError:
        return
    raise AssertionError('expected LlError')


def test_sum_bool_raises():
    try:
        sum_values(from_list([True, 1]))
    except LlError:
        return
    raise AssertionError('expected LlError')

def main():
    test_sum_ints()
    test_sum_empty()
    test_sum_floats()
    test_sum_negative()
    test_sum_non_numeric_raises()
    test_sum_bool_raises()
    assert stdlib_only()
    print("ll-31 OK")


if __name__ == "__main__":
    main()
