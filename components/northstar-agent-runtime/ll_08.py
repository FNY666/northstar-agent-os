"""Merge k sorted lists: merge k sorted lists via divide and conquer.

Pairs lists up repeatedly, merging each pair with the classic two-list
splice, halving the active set each round. Runs in O(N log k) time for
N total nodes with O(1) extra space beyond the input nodes.

What this IS: a pairwise divide-and-conquer k-way merge.
What this IS NOT: a heap-based merge or a collect-and-sort shortcut.
"""

from __future__ import annotations

import ast

#: Module version.
LL_08_VERSION = "ll-08.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-08.v1"


class LlError(Exception):
    """Fail-closed."""


class Node:
    def __init__(self, val):
        self.val = val
        self.next = None


def _check_head(head):
    if head is not None and not isinstance(head, Node):
        raise LlError("each list head must be a Node or None")


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


def merge_k(lists):
    """Merge k ascending lists; return the head of the merged list."""
    if not isinstance(lists, (list, tuple)):
        raise LlError("lists must be a list or tuple of heads")
    arr = []
    for h in lists:
        _check_head(h)
        arr.append(h)
    if not arr:
        return None
    interval = 1
    while interval < len(arr):
        for i in range(0, len(arr) - interval, interval * 2):
            arr[i] = _merge_two(arr[i], arr[i + interval])
        interval *= 2
    return arr[0]


def test_merge_k_basic():
    lists = [from_list([1, 4, 5]), from_list([1, 3, 4]), from_list([2, 6])]
    assert to_list(merge_k(lists)) == [1, 1, 2, 3, 4, 4, 5, 6]


def test_merge_k_edge_cases():
    assert merge_k([]) is None
    assert merge_k([None, None]) is None
    assert to_list(merge_k([from_list([1, 2])])) == [1, 2]
    assert to_list(merge_k([from_list([1]), None, from_list([0])])) == [0, 1]


def test_merge_k_many():
    lists = [from_list([i, i + 10, i + 20]) for i in range(7)]
    assert to_list(merge_k(lists)) == sorted(v for i in range(7) for v in (i, i + 10, i + 20))


def test_merge_k_singletons():
    lists = [from_list([v]) for v in (5, 1, 4, 2, 3)]
    assert to_list(merge_k(lists)) == [1, 2, 3, 4, 5]


def test_merge_k_bad_input():
    try:
        merge_k("nope")
    except LlError:
        pass
    else:
        raise AssertionError("expected LlError")
    try:
        merge_k([from_list([1]), "nope"])
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
    test_merge_k_basic()
    test_merge_k_edge_cases()
    test_merge_k_many()
    test_merge_k_singletons()
    test_merge_k_bad_input()
    assert stdlib_only()
    print("ll-08 OK")


if __name__ == "__main__":
    main()
