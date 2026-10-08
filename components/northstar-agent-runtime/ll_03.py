"""Detect cycle (Floyd's algorithm): tell whether a list contains a cycle.

A slow pointer advances one step while a fast pointer advances two steps;
if the list loops, the fast pointer laps the slow one and they must meet.
Runs in O(n) time with O(1) extra space.

What this IS: a tortoise-and-hare boolean cycle test on the node graph.
What this IS NOT: a cycle locator or a visited-set walk using extra memory.
"""

from __future__ import annotations

import ast

#: Module version.
LL_03_VERSION = "ll-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-03.v1"


class LlError(Exception):
    """Fail-closed."""


class Node:
    def __init__(self, val):
        self.val = val
        self.next = None


def _check_head(head):
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")


def from_list(vals):
    """Build a list from a Python list."""
    if not isinstance(vals, (list, tuple)):
        raise LlError("vals must be a list or tuple")
    head = None
    tail = None
    for v in vals:
        node = Node(v)
        if head is None:
            head = node
        else:
            tail.next = node
        tail = node
    return head


def to_list(head):
    """Convert back to a Python list."""
    _check_head(head)
    out = []
    seen = set()
    cur = head
    while cur is not None:
        if id(cur) in seen:
            raise LlError("cycle detected; cannot linearize")
        seen.add(id(cur))
        out.append(cur.val)
        cur = cur.next
    return out


def _make_cycle(vals, pos):
    """Build a list whose tail links back to index pos (-1 means no cycle)."""
    head = from_list(vals)
    if pos < 0 or head is None:
        return head
    target = head
    for _ in range(pos):
        if target is None:
            raise LlError("cycle position out of range")
        target = target.next
    tail = head
    while tail.next is not None:
        tail = tail.next
    tail.next = target
    return head


def has_cycle(head):
    """Return True iff the list contains a cycle (Floyd's algorithm)."""
    _check_head(head)
    slow = head
    fast = head
    while fast is not None and fast.next is not None:
        slow = slow.next
        fast = fast.next.next
        if slow is fast:
            return True
    return False


def test_no_cycle():
    assert has_cycle(from_list([1, 2, 3, 4])) is False
    assert has_cycle(None) is False
    assert has_cycle(from_list([1])) is False


def test_cycle_middle():
    assert has_cycle(_make_cycle([1, 2, 3, 4, 5], 2)) is True


def test_cycle_at_head():
    assert has_cycle(_make_cycle([1, 2, 3], 0)) is True


def test_self_loop():
    node = Node(9)
    node.next = node
    assert has_cycle(node) is True


def test_two_node_cycle():
    a = Node(1)
    b = Node(2)
    a.next = b
    b.next = a
    assert has_cycle(a) is True
    b.next = None
    assert has_cycle(a) is False


def test_bad_input():
    try:
        has_cycle("nope")
    except LlError:
        pass
    else:
        raise AssertionError("expected LlError")


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    test_no_cycle()
    test_cycle_middle()
    test_cycle_at_head()
    test_self_loop()
    test_two_node_cycle()
    test_bad_input()
    assert stdlib_only()
    print("ll-03 OK")


if __name__ == "__main__":
    main()
