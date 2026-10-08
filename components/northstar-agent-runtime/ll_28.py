"""ll-28: Zip-merge two lists alternating their nodes.

Walks both lists once, emitting one value from each in turn into a NEW list.
The inputs are never mutated; the shorter side simply runs out first.

What this IS: a copy-based alternating merge that starts with the first list.
What this IS NOT: an in-place splice (see ll-46) or a sorted merge.
"""

from __future__ import annotations

import ast
import pathlib

LL_28_VERSION = "ll-28.v1"
SCHEMA_PIN = "northstar.ll-28.v1"


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


def _check_head(head, name):
    if head is not None and not isinstance(head, Node):
        raise LlError(name + " must be a Node or None")


def zip_merge(a, b):
    """Return a NEW list alternating values from a and b, starting with a."""
    _check_head(a, "a")
    _check_head(b, "b")
    dummy = Node(0)
    tail = dummy
    pa, pb = a, b
    seen = set()
    while pa is not None or pb is not None:
        if pa is not None:
            if id(pa) in seen:
                raise LlError("cycle detected in input a")
            seen.add(id(pa))
            tail.next = Node(pa.val)
            tail = tail.next
            pa = pa.next
        if pb is not None:
            if id(pb) in seen:
                raise LlError("cycle detected in input b")
            seen.add(id(pb))
            tail.next = Node(pb.val)
            tail = tail.next
            pb = pb.next
    return dummy.next

def test_zip_even():
    assert to_list(zip_merge(from_list([1, 3, 5]), from_list([2, 4, 6]))) == [1, 2, 3, 4, 5, 6]


def test_zip_uneven():
    assert to_list(zip_merge(from_list([1, 2]), from_list([3]))) == [1, 3, 2]


def test_zip_a_empty():
    assert to_list(zip_merge(None, from_list([7, 8]))) == [7, 8]


def test_zip_b_empty():
    assert to_list(zip_merge(from_list([1, 2, 3]), None)) == [1, 2, 3]


def test_zip_both_empty():
    assert to_list(zip_merge(None, None)) == []


def test_zip_inputs_not_mutated():
    a = from_list([1, 2])
    b = from_list([3])
    zip_merge(a, b)
    assert to_list(a) == [1, 2]
    assert to_list(b) == [3]

def main():
    test_zip_even()
    test_zip_uneven()
    test_zip_a_empty()
    test_zip_b_empty()
    test_zip_both_empty()
    test_zip_inputs_not_mutated()
    assert stdlib_only()
    print("ll-28 OK")


if __name__ == "__main__":
    main()
