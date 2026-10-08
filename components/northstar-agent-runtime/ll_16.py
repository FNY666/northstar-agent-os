"""Sort list: merge sort directly on the linked list.

Splits the list with slow/fast pointers, sorts each half recursively,
and merges the halves with the classic two-list splice. Stable and
in-place apart from recursion depth: O(n log n) time, O(log n) stack.

What this IS: a top-down linked-list merge sort returning the new head.
What this IS NOT: a copy-to-array sort that rebuilds the list.
"""

from __future__ import annotations

import ast

#: Module version.
LL_16_VERSION = "ll-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-16.v1"


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


def _merge_two(a, b):
    dummy = Node(0)
    tail = dummy
    while a is not None and b is not None:
        try:
            take_a = a.val <= b.val
        except TypeError as e:
            raise LlError(f"values must be comparable: {e}")
        if take_a:
            tail.next = a
            a = a.next
        else:
            tail.next = b
            b = b.next
        tail = tail.next
    tail.next = a if a is not None else b
    return dummy.next


def sort_list(head):
    """Sort the list ascending via merge sort; return the new head."""
    _check_head(head)
    if head is None or head.next is None:
        return head
    slow = head
    fast = head.next
    while fast is not None and fast.next is not None:
        slow = slow.next
        fast = fast.next.next
    mid = slow.next
    slow.next = None
    left = sort_list(head)
    right = sort_list(mid)
    return _merge_two(left, right)


def test_sort_basic():
    assert to_list(sort_list(from_list([4, 2, 1, 3]))) == [1, 2, 3, 4]


def test_sort_edge_cases():
    assert sort_list(None) is None
    assert to_list(sort_list(from_list([1]))) == [1]
    assert to_list(sort_list(from_list([1, 2, 3]))) == [1, 2, 3]
    assert to_list(sort_list(from_list([3, 2, 1]))) == [1, 2, 3]


def test_sort_duplicates_negatives():
    assert to_list(sort_list(from_list([3, 1, 2, 1, 3]))) == [1, 1, 2, 3, 3]
    assert to_list(sort_list(from_list([-1, 5, 3, 0, -4]))) == [-4, -1, 0, 3, 5]


def test_sort_longer():
    vals = [9, 7, 5, 3, 1, 2, 4, 6, 8, 0]
    assert to_list(sort_list(from_list(vals))) == sorted(vals)


def test_sort_uncomparable_raises():
    try:
        sort_list(from_list([1, "a"]))
    except LlError:
        pass
    else:
        raise AssertionError("expected LlError for uncomparable values")


def test_sort_bad_input():
    try:
        sort_list({"v": 1})
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
    test_sort_basic()
    test_sort_edge_cases()
    test_sort_duplicates_negatives()
    test_sort_longer()
    test_sort_uncomparable_raises()
    test_sort_bad_input()
    assert stdlib_only()
    print("ll-16 OK")


if __name__ == "__main__":
    main()
