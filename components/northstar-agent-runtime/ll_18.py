"""Partition list around value x: nodes < x come before nodes >= x.

Two dummy-anchored chains collect the smaller and the greater-or-equal
nodes in original order, then the chains are spliced together.
Runs in O(n) time with O(1) extra space, stable within each side.

What this IS: a stable two-chain partition returning the new head.
What this IS NOT: a quicksort-style pivot swap of node values.
"""

from __future__ import annotations

import ast

#: Module version.
LL_18_VERSION = "ll-18.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-18.v1"


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


def partition(head, x):
    """Partition around x: values < x first, then >= x; return the head."""
    _check_head(head)
    before_dummy = Node(0)
    after_dummy = Node(0)
    before = before_dummy
    after = after_dummy
    cur = head
    while cur is not None:
        nxt = cur.next
        try:
            if cur.val < x:
                before.next = cur
                before = before.next
            else:
                after.next = cur
                after = after.next
        except TypeError as e:
            raise LlError(f"values must be comparable with x: {e}")
        cur = nxt
    after.next = None
    before.next = after_dummy.next
    return before_dummy.next


def test_partition_basic():
    assert to_list(partition(from_list([1, 4, 3, 2, 5, 2]), 3)) == [1, 2, 2, 4, 3, 5]


def test_partition_edge_cases():
    assert partition(None, 3) is None
    assert to_list(partition(from_list([1, 2]), 5)) == [1, 2]
    assert to_list(partition(from_list([5, 6]), 5)) == [5, 6]
    assert to_list(partition(from_list([2, 1]), 3)) == [2, 1]


def test_partition_stable():
    assert to_list(partition(from_list([3, 1, 2, 1, 3]), 2)) == [1, 1, 3, 2, 3]


def test_partition_x_extremes():
    assert to_list(partition(from_list([1, 2, 3]), 0)) == [1, 2, 3]
    assert to_list(partition(from_list([1, 2, 3]), 10)) == [1, 2, 3]


def test_partition_uncomparable_raises():
    try:
        partition(from_list([1, "a"]), 2)
    except LlError:
        pass
    else:
        raise AssertionError("expected LlError for uncomparable values")


def test_partition_bad_input():
    try:
        partition(42, 3)
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
    test_partition_basic()
    test_partition_edge_cases()
    test_partition_stable()
    test_partition_x_extremes()
    test_partition_uncomparable_raises()
    test_partition_bad_input()
    assert stdlib_only()
    print("ll-18 OK")


if __name__ == "__main__":
    main()
