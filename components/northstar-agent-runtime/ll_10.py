"""Remove duplicates from unsorted list: keep first occurrence of each value.

Without sorted order, duplicates can hide anywhere, so a hash set tracks
values already seen and any later repeat is unlinked. Runs in O(n) time
with O(n) extra space for the set.

What this IS: a first-occurrence-wins dedup using a seen-set.
What this IS NOT: a sort-then-dedup that would reorder the values.
"""

from __future__ import annotations

import ast

#: Module version.
LL_10_VERSION = "ll-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-10.v1"


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


def delete_duplicates_unsorted(head):
    """Keep the first occurrence of each value; return the head."""
    _check_head(head)
    seen = set()
    dummy = Node(0)
    dummy.next = head
    prev = dummy
    cur = head
    while cur is not None:
        try:
            dup = cur.val in seen
        except TypeError:
            raise LlError("values must be hashable")
        if dup:
            prev.next = cur.next
        else:
            seen.add(cur.val)
            prev = cur
        cur = cur.next
    return dummy.next


def test_dedup_basic():
    assert to_list(delete_duplicates_unsorted(from_list([1, 2, 1, 3, 2]))) == [1, 2, 3]


def test_dedup_edge_cases():
    assert delete_duplicates_unsorted(None) is None
    assert to_list(delete_duplicates_unsorted(from_list([1]))) == [1]
    assert to_list(delete_duplicates_unsorted(from_list([1, 1, 1]))) == [1]
    assert to_list(delete_duplicates_unsorted(from_list([1, 2, 3]))) == [1, 2, 3]


def test_dedup_order_preserved():
    assert to_list(delete_duplicates_unsorted(from_list([3, 1, 2, 3, 1]))) == [3, 1, 2]


def test_dedup_strings():
    assert to_list(delete_duplicates_unsorted(from_list(["a", "b", "a", "c"]))) == ["a", "b", "c"]


def test_dedup_unhashable_raises():
    try:
        delete_duplicates_unsorted(from_list([[1], [1]]))
    except LlError:
        pass
    else:
        raise AssertionError("expected LlError for unhashable values")


def test_dedup_bad_input():
    try:
        delete_duplicates_unsorted(42)
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
    test_dedup_basic()
    test_dedup_edge_cases()
    test_dedup_order_preserved()
    test_dedup_strings()
    test_dedup_unhashable_raises()
    test_dedup_bad_input()
    assert stdlib_only()
    print("ll-10 OK")


if __name__ == "__main__":
    main()
