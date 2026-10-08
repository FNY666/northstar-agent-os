"""ll-38: Insert a value into a sorted circular linked list.

Keeps a sorted circular list sorted and circular after insertion.
Input circularity is verified before touching anything; linear input fails closed.

What this IS: sorted insertion into a circular list with a pre-insert circularity proof.
What this IS NOT: insertion into a linear list, or an append that ignores sort order.
"""

from __future__ import annotations

import ast
import pathlib

LL_38_VERSION = "ll-38.v1"
SCHEMA_PIN = "northstar.ll-38.v1"


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


def _cycle_length(head):
    slow = head
    fast = head
    while fast is not None and fast.next is not None:
        slow = slow.next
        fast = fast.next.next
        if slow is fast:
            n = 1
            cur = slow.next
            while cur is not slow:
                n += 1
                cur = cur.next
            return n
    return 0


def _assert_circular(head):
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    if head is None:
        raise LlError("head must be a non-empty Node chain")
    n = _cycle_length(head)
    if n == 0:
        raise LlError("list is not circular")
    cur = head
    for _ in range(n):
        cur = cur.next
    if cur is not head:
        raise LlError("head is not on the cycle")
    return n


def make_circular(values):
    """Test helper: build a circular list from a non-empty sequence."""
    head = from_list(values)
    if head is None:
        raise LlError("values must be non-empty")
    tail = head
    while tail.next is not None:
        tail = tail.next
    tail.next = head
    return head


def to_circular_list(head, limit=10000):
    """Bounded traversal of a circular list; fail-closed when not circular."""
    n = _assert_circular(head)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise LlError("limit must be a positive integer")
    if n > limit:
        raise LlError("circular list exceeds the traversal limit")
    out = []
    cur = head
    for _ in range(n):
        out.append(cur.val)
        cur = cur.next
    return out


def circular_insert(head, val):
    """Insert val into a sorted circular list, preserving circularity."""
    node = Node(val)
    if head is None:
        node.next = node
        return node
    if not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    _assert_circular(head)
    cur = head
    while True:
        nxt = cur.next
        if cur.val <= val <= nxt.val:
            break
        if cur.val > nxt.val and (val >= cur.val or val <= nxt.val):
            break
        cur = nxt
        if cur is head:
            break
    node.next = cur.next
    cur.next = node
    return head

def test_circular_insert_empty():
    h = circular_insert(None, 5)
    assert to_circular_list(h) == [5]
    assert h.next is h


def test_circular_insert_middle():
    h = circular_insert(make_circular([1, 3, 4]), 2)
    assert to_circular_list(h) == [1, 2, 3, 4]


def test_circular_insert_largest():
    h = circular_insert(make_circular([1, 3, 4]), 5)
    assert to_circular_list(h) == [1, 3, 4, 5]


def test_circular_insert_smallest():
    h = circular_insert(make_circular([1, 3, 4]), 0)
    assert to_circular_list(h) == [1, 3, 4, 0]


def test_circular_insert_all_equal():
    h = circular_insert(make_circular([2, 2, 2]), 2)
    assert to_circular_list(h) == [2, 2, 2, 2]


def test_circular_insert_linear_raises():
    try:
        circular_insert(from_list([1, 2, 3]), 4)
    except LlError:
        return
    raise AssertionError('expected LlError')

def main():
    test_circular_insert_empty()
    test_circular_insert_middle()
    test_circular_insert_largest()
    test_circular_insert_smallest()
    test_circular_insert_all_equal()
    test_circular_insert_linear_raises()
    assert stdlib_only()
    print("ll-38 OK")


if __name__ == "__main__":
    main()
