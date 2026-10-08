"""ll-37: Detect a cycle in a singly linked list.

Floyd's tortoise-and-hare runs in O(n) time with O(1) extra space.
Also exposes the cycle entry value; acyclic lists report None for the entry.

What this IS: Floyd cycle detection plus entry-point location on a singly linked list.
What this IS NOT: a visited-set traversal (used elsewhere only as a fail-closed guard).
"""

from __future__ import annotations

import ast
import pathlib

LL_37_VERSION = "ll-37.v1"
SCHEMA_PIN = "northstar.ll-37.v1"


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


def has_cycle(head):
    """Return True when the list contains a cycle; False otherwise."""
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    slow = head
    fast = head
    while fast is not None and fast.next is not None:
        slow = slow.next
        fast = fast.next.next
        if slow is fast:
            return True
    return False


def make_cycle(head, pos):
    """Test helper: link the tail to the node at 0-based index pos."""
    if head is None or not isinstance(head, Node):
        raise LlError("head must be a non-empty Node chain")
    if not isinstance(pos, int) or isinstance(pos, bool) or pos < 0:
        raise LlError("pos must be a non-negative integer")
    target = head
    for _ in range(pos):
        target = target.next
        if target is None:
            raise LlError("pos exceeds the list length")
    tail = head
    while tail.next is not None:
        tail = tail.next
    tail.next = target
    return head


def cycle_entry_value(head):
    """Return the value at the cycle entry, or None when acyclic."""
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    slow = head
    fast = head
    while fast is not None and fast.next is not None:
        slow = slow.next
        fast = fast.next.next
        if slow is fast:
            break
    else:
        return None
    slow = head
    while slow is not fast:
        slow = slow.next
        fast = fast.next
    return slow.val

def test_no_cycle():
    assert has_cycle(from_list([1, 2, 3])) is False


def test_tail_to_head_cycle():
    h = make_cycle(from_list([1, 2, 3]), 0)
    assert has_cycle(h) is True
    assert cycle_entry_value(h) == 1


def test_middle_cycle():
    h = make_cycle(from_list([1, 2, 3, 4]), 1)
    assert has_cycle(h) is True
    assert cycle_entry_value(h) == 2


def test_self_loop():
    h = make_cycle(from_list([9]), 0)
    assert has_cycle(h) is True
    assert cycle_entry_value(h) == 9


def test_empty_no_cycle():
    assert has_cycle(None) is False
    assert cycle_entry_value(None) is None


def test_bad_pos_raises():
    try:
        make_cycle(from_list([1, 2]), 5)
    except LlError:
        return
    raise AssertionError('expected LlError')

def main():
    test_no_cycle()
    test_tail_to_head_cycle()
    test_middle_cycle()
    test_self_loop()
    test_empty_no_cycle()
    test_bad_pos_raises()
    assert stdlib_only()
    print("ll-37 OK")


if __name__ == "__main__":
    main()
