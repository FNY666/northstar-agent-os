"""Reverse nodes in k-group: reverse the list k nodes at a time.

Counts the nodes first; each full group of k is reversed with head-insert
rewiring while a trailing partial group is left untouched.
Runs in O(n) time with O(1) extra space.

What this IS: an in-place k-group reversal leaving a short tail as-is.
What this IS NOT: a reversal that pads or rotates the leftover tail.
"""

from __future__ import annotations

import ast

#: Module version.
LL_15_VERSION = "ll-15.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-15.v1"


class LlError(Exception):
    """Fail-closed."""


class Node:
    def __init__(self, val):
        self.val = val
        self.next = None


def _check_head(head):
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")


def _check_k(k):
    if isinstance(k, bool) or not isinstance(k, int) or k < 1:
        raise LlError("k must be a positive int")


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


def reverse_k_group(head, k):
    """Reverse the list in groups of k; return the new head."""
    _check_head(head)
    _check_k(k)
    n = 0
    cur = head
    while cur is not None:
        n += 1
        cur = cur.next
    dummy = Node(0)
    dummy.next = head
    prev = dummy
    while n >= k:
        tail = prev.next
        cur = tail.next
        for _ in range(k - 1):
            nxt = cur.next
            cur.next = prev.next
            prev.next = cur
            tail.next = nxt
            cur = nxt
        prev = tail
        n -= k
    return dummy.next


def test_k2():
    assert to_list(reverse_k_group(from_list([1, 2, 3, 4, 5]), 2)) == [2, 1, 4, 3, 5]


def test_k3():
    assert to_list(reverse_k_group(from_list([1, 2, 3, 4, 5]), 3)) == [3, 2, 1, 4, 5]


def test_k_edge_cases():
    assert reverse_k_group(None, 3) is None
    assert to_list(reverse_k_group(from_list([1, 2, 3]), 1)) == [1, 2, 3]
    assert to_list(reverse_k_group(from_list([1, 2, 3]), 3)) == [3, 2, 1]
    assert to_list(reverse_k_group(from_list([1, 2]), 5)) == [1, 2]


def test_k4_of_8():
    assert to_list(reverse_k_group(from_list([1, 2, 3, 4, 5, 6, 7, 8]), 4)) == [4, 3, 2, 1, 8, 7, 6, 5]


def test_bad_k():
    for bad in (0, -2, True, 2.0, "2"):
        try:
            reverse_k_group(from_list([1, 2, 3]), bad)
        except LlError:
            pass
        else:
            raise AssertionError(f"expected LlError for k={bad!r}")


def test_bad_input():
    try:
        reverse_k_group(42, 2)
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
    test_k2()
    test_k3()
    test_k_edge_cases()
    test_k4_of_8()
    test_bad_k()
    test_bad_input()
    assert stdlib_only()
    print("ll-15 OK")


if __name__ == "__main__":
    main()
