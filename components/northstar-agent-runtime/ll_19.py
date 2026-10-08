"""Reorder list: interleave as L0 -> Ln -> L1 -> Ln-1 ...

Finds the middle, reverses the second half, then zips the two halves
together node by node. Runs in O(n) time with O(1) extra space.

What this IS: an in-place fold that interleaves the ends toward the middle.
What this IS NOT: a sort or a rotation of the list.
"""

from __future__ import annotations

import ast

#: Module version.
LL_19_VERSION = "ll-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-19.v1"


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


def reorder_list(head):
    """Reorder to L0 -> Ln -> L1 -> Ln-1 ...; return the head."""
    _check_head(head)
    if head is None or head.next is None:
        return head
    slow = head
    fast = head
    while fast.next is not None and fast.next.next is not None:
        slow = slow.next
        fast = fast.next.next
    prev = None
    cur = slow.next
    slow.next = None
    while cur is not None:
        nxt = cur.next
        cur.next = prev
        prev = cur
        cur = nxt
    first = head
    second = prev
    while second is not None:
        f_nxt = first.next
        s_nxt = second.next
        first.next = second
        second.next = f_nxt
        first = f_nxt
        second = s_nxt
    return head


def test_reorder_even():
    assert to_list(reorder_list(from_list([1, 2, 3, 4]))) == [1, 4, 2, 3]


def test_reorder_odd():
    assert to_list(reorder_list(from_list([1, 2, 3, 4, 5]))) == [1, 5, 2, 4, 3]


def test_reorder_edge_cases():
    assert reorder_list(None) is None
    assert to_list(reorder_list(from_list([1]))) == [1]
    assert to_list(reorder_list(from_list([1, 2]))) == [1, 2]
    assert to_list(reorder_list(from_list([1, 2, 3]))) == [1, 3, 2]


def test_reorder_longer():
    assert to_list(reorder_list(from_list([1, 2, 3, 4, 5, 6]))) == [1, 6, 2, 5, 3, 4]


def test_reorder_bad_input():
    try:
        reorder_list([1, 2])
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
    test_reorder_even()
    test_reorder_odd()
    test_reorder_edge_cases()
    test_reorder_longer()
    test_reorder_bad_input()
    assert stdlib_only()
    print("ll-19 OK")


if __name__ == "__main__":
    main()
