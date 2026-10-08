"""ll-50: Array to linked list roundtrip.

Array -> linked list -> array must reproduce the input exactly.
The roundtrip also asserts the node count matches the array length.

What this IS: a lossless array/list conversion pair with a length-consistency check.
What this IS NOT: a doubly linked list roundtrip (see ll-44).
"""

from __future__ import annotations

import ast
import pathlib

LL_50_VERSION = "ll-50.v1"
SCHEMA_PIN = "northstar.ll-50.v1"


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


def array_to_list(values):
    """Build a singly linked list from a Python list."""
    return from_list(values)


def list_to_array(head):
    """Materialise a singly linked list as a Python list."""
    return to_list(head)


def array_roundtrip(values):
    """Array -> list -> array; raise LlError when the length does not match."""
    head = array_to_list(values)
    result = list_to_array(head)
    if len(result) != len(values):
        raise LlError("roundtrip length mismatch")
    return result

def test_roundtrip_ints():
    assert array_roundtrip([1, 2, 3, 4, 5]) == [1, 2, 3, 4, 5]


def test_roundtrip_empty():
    assert array_roundtrip([]) == []


def test_roundtrip_strings():
    assert array_roundtrip(['a', 'b', 'c']) == ['a', 'b', 'c']


def test_roundtrip_large():
    vals = list(range(1000))
    assert array_roundtrip(vals) == vals


def test_roundtrip_none_raises():
    try:
        array_roundtrip(None)
    except LlError:
        return
    raise AssertionError('expected LlError')

def main():
    test_roundtrip_ints()
    test_roundtrip_empty()
    test_roundtrip_strings()
    test_roundtrip_large()
    test_roundtrip_none_raises()
    assert stdlib_only()
    print("ll-50 OK")


if __name__ == "__main__":
    main()
