"""ll-26: Delete the middle node of a singly linked list.

Slow/fast pointers locate the middle in a single pass with O(1) extra space.
The middle node is unlinked in place; the original head is returned.

What this IS: a one-pass, in-place deletion of the list's middle node.
What this IS NOT: a value-based deletion or a copy-based rebuild of the list.
"""

from __future__ import annotations

import ast
import pathlib

LL_26_VERSION = "ll-26.v1"
SCHEMA_PIN = "northstar.ll-26.v1"


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


def delete_middle(head):
    """Delete the middle node (second middle on even length); return the head."""
    if head is None or not isinstance(head, Node):
        raise LlError("head must be a non-empty Node chain")
    if head.next is None:
        raise LlError("cannot delete the middle of a single-node list")
    slow = head
    fast = head
    prev = None
    while fast is not None and fast.next is not None:
        prev = slow
        slow = slow.next
        fast = fast.next.next
    prev.next = slow.next
    slow.next = None
    return head

def test_delete_middle_odd():
    assert to_list(delete_middle(from_list([1, 2, 3, 4, 5]))) == [1, 2, 4, 5]


def test_delete_middle_even_deletes_second_middle():
    assert to_list(delete_middle(from_list([1, 2, 3, 4]))) == [1, 2, 4]


def test_delete_middle_two_nodes():
    assert to_list(delete_middle(from_list([1, 2]))) == [2]


def test_delete_middle_single_raises():
    try:
        delete_middle(from_list([1]))
    except LlError:
        return
    raise AssertionError('expected LlError')


def test_delete_middle_none_raises():
    try:
        delete_middle(None)
    except LlError:
        return
    raise AssertionError('expected LlError')

def main():
    test_delete_middle_odd()
    test_delete_middle_even_deletes_second_middle()
    test_delete_middle_two_nodes()
    test_delete_middle_single_raises()
    test_delete_middle_none_raises()
    assert stdlib_only()
    print("ll-26 OK")


if __name__ == "__main__":
    main()
