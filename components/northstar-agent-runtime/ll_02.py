"""Merge two sorted lists: splice two sorted lists into one sorted list.

Walks both lists with two pointers, always linking the smaller head next.
Runs in O(n + m) time and O(1) extra space, reusing the input nodes.

What this IS: a stable two-pointer merge returning the merged head.
What this IS NOT: a merge that copies values into freshly allocated nodes.
"""

from __future__ import annotations

import ast

#: Module version.
LL_02_VERSION = "ll-02.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-02.v1"


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


def merge_two(a, b):
    """Merge two ascending lists; return the head of the merged list."""
    _check_head(a)
    _check_head(b)
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


def test_merge_basic():
    assert to_list(merge_two(from_list([1, 3, 5]), from_list([2, 4, 6]))) == [1, 2, 3, 4, 5, 6]


def test_merge_edge_cases():
    assert to_list(merge_two(from_list([]), from_list([1, 2]))) == [1, 2]
    assert to_list(merge_two(from_list([1, 2]), from_list([]))) == [1, 2]
    assert merge_two(None, None) is None
    assert to_list(merge_two(from_list([5]), from_list([3]))) == [3, 5]


def test_merge_duplicates():
    assert to_list(merge_two(from_list([1, 1, 2]), from_list([1, 3]))) == [1, 1, 1, 2, 3]


def test_merge_unequal_lengths():
    assert to_list(merge_two(from_list([1, 2, 3, 4, 5]), from_list([10]))) == [1, 2, 3, 4, 5, 10]


def test_merge_bad_input():
    try:
        merge_two("nope", None)
    except LlError:
        pass
    else:
        raise AssertionError("expected LlError")
    try:
        merge_two(from_list([1]), from_list(["a"]))
    except LlError:
        pass
    else:
        raise AssertionError("expected LlError for uncomparable values")


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
    test_merge_basic()
    test_merge_edge_cases()
    test_merge_duplicates()
    test_merge_unequal_lengths()
    test_merge_bad_input()
    assert stdlib_only()
    print("ll-02 OK")


if __name__ == "__main__":
    main()
