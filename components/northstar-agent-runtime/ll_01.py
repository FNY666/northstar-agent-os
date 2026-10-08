"""Reverse linked list (iterative): reverse a singly linked list in place.

Walks the list once, rewiring each node's next pointer to its predecessor.
Runs in O(n) time with O(1) extra space and never allocates new nodes.

What this IS: an iterative in-place reversal returning the new head.
What this IS NOT: a recursive reversal or a copy that leaves the input intact.
"""

from __future__ import annotations

import ast

#: Module version.
LL_01_VERSION = "ll-01.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-01.v1"


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


def reverse_list(head):
    """Reverse the list iteratively; return the new head."""
    _check_head(head)
    prev = None
    cur = head
    while cur is not None:
        nxt = cur.next
        cur.next = prev
        prev = cur
        cur = nxt
    return prev


def test_reverse_basic():
    assert to_list(reverse_list(from_list([1, 2, 3, 4]))) == [4, 3, 2, 1]


def test_reverse_edge_cases():
    assert to_list(reverse_list(from_list([]))) == []
    assert reverse_list(None) is None
    assert to_list(reverse_list(from_list([7]))) == [7]
    assert to_list(reverse_list(from_list([1, 2]))) == [2, 1]


def test_reverse_longer():
    vals = list(range(20))
    assert to_list(reverse_list(from_list(vals))) == vals[::-1]


def test_reverse_double_reversal():
    head = from_list([1, 2, 3, 4, 5])
    assert to_list(reverse_list(reverse_list(head))) == [1, 2, 3, 4, 5]


def test_reverse_bad_input():
    for bad in ("nope", 42, [1, 2]):
        try:
            reverse_list(bad)
        except LlError:
            pass
        else:
            raise AssertionError(f"expected LlError for {bad!r}")


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
    test_reverse_basic()
    test_reverse_edge_cases()
    test_reverse_longer()
    test_reverse_double_reversal()
    test_reverse_bad_input()
    assert stdlib_only()
    print("ll-01 OK")


if __name__ == "__main__":
    main()
