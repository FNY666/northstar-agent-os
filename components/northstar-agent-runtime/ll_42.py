"""ll-42: Remove a cycle from a singly linked list (break the loop).

Floyd detection finds the meeting point, then a second walk locates the loop entry.
The back edge is cut; an acyclic list is returned untouched.

What this IS: cycle detection plus entry location followed by severing the back edge.
What this IS NOT: cycle detection alone (see ll-37) or rebuilding the list.
"""

from __future__ import annotations

import ast
import pathlib

LL_42_VERSION = "ll-42.v1"
SCHEMA_PIN = "northstar.ll-42.v1"


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


def remove_cycle(head):
    """Break any cycle in the list; return the (now linear) head."""
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    if head is None:
        return None
    slow = head
    fast = head
    while fast is not None and fast.next is not None:
        slow = slow.next
        fast = fast.next.next
        if slow is fast:
            break
    else:
        return head
    slow = head
    if slow is fast:
        while fast.next is not slow:
            fast = fast.next
        fast.next = None
        return head
    while slow.next is not fast.next:
        slow = slow.next
        fast = fast.next
    fast.next = None
    return head


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

def test_remove_tail_to_head():
    h = remove_cycle(make_cycle(from_list([1, 2, 3]), 0))
    assert to_list(h) == [1, 2, 3]


def test_remove_middle_cycle():
    h = remove_cycle(make_cycle(from_list([1, 2, 3, 4]), 1))
    assert to_list(h) == [1, 2, 3, 4]


def test_remove_self_loop():
    h = remove_cycle(make_cycle(from_list([9]), 0))
    assert to_list(h) == [9]


def test_remove_no_cycle_unchanged():
    h = from_list([1, 2, 3])
    assert to_list(remove_cycle(h)) == [1, 2, 3]


def test_remove_empty():
    assert remove_cycle(None) is None

def main():
    test_remove_tail_to_head()
    test_remove_middle_cycle()
    test_remove_self_loop()
    test_remove_no_cycle_unchanged()
    test_remove_empty()
    assert stdlib_only()
    print("ll-42 OK")


if __name__ == "__main__":
    main()
