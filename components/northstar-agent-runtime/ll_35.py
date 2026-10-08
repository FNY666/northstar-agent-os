"""ll-35: Delete the first occurrence of a value.

A single scan unlinks the first node whose value equals the target.
Returns (new_head, deleted); a missing value leaves the list untouched.

What this IS: a first-match unlink returning the new head and a deletion flag.
What this IS NOT: a remove-all-values filter (see ll-47).
"""

from __future__ import annotations

import ast
import pathlib

LL_35_VERSION = "ll-35.v1"
SCHEMA_PIN = "northstar.ll-35.v1"


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


def delete_first(head, target):
    """Delete the first node with value == target; return (head, deleted)."""
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    if head is None:
        return None, False
    if head.val == target:
        nxt = head.next
        head.next = None
        return nxt, True
    prev = head
    cur = head.next
    while cur is not None:
        if cur.val == target:
            prev.next = cur.next
            cur.next = None
            return head, True
        prev = cur
        cur = cur.next
    return head, False

def test_delete_first_middle():
    head, ok = delete_first(from_list([1, 2, 3, 2]), 2)
    assert ok is True
    assert to_list(head) == [1, 3, 2]


def test_delete_first_head():
    head, ok = delete_first(from_list([1, 2, 3]), 1)
    assert ok is True
    assert to_list(head) == [2, 3]


def test_delete_first_tail():
    head, ok = delete_first(from_list([1, 2, 3]), 3)
    assert ok is True
    assert to_list(head) == [1, 2]


def test_delete_first_missing():
    head, ok = delete_first(from_list([1, 2, 3]), 99)
    assert ok is False
    assert to_list(head) == [1, 2, 3]


def test_delete_first_empty():
    head, ok = delete_first(None, 1)
    assert ok is False
    assert head is None

def main():
    test_delete_first_middle()
    test_delete_first_head()
    test_delete_first_tail()
    test_delete_first_missing()
    test_delete_first_empty()
    assert stdlib_only()
    print("ll-35 OK")


if __name__ == "__main__":
    main()
