"""Rotate list right by k: move the last k nodes to the front.

Finds the tail and length in one pass, normalizes k modulo the length,
then cuts before the new head and re-links the old tail to the old head.
Runs in O(n) time with O(1) extra space.

What this IS: an in-place rotation returning the new head.
What this IS NOT: a value-shifting rotation that rewrites node values.
"""

from __future__ import annotations

import ast

#: Module version.
LL_13_VERSION = "ll-13.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-13.v1"


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
    if isinstance(k, bool) or not isinstance(k, int) or k < 0:
        raise LlError("k must be a non-negative int")


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


def rotate_right(head, k):
    """Rotate the list right by k places; return the new head."""
    _check_head(head)
    _check_k(k)
    if head is None or head.next is None:
        return head
    n = 1
    tail = head
    while tail.next is not None:
        tail = tail.next
        n += 1
    k = k % n
    if k == 0:
        return head
    new_tail = head
    for _ in range(n - k - 1):
        new_tail = new_tail.next
    new_head = new_tail.next
    new_tail.next = None
    tail.next = head
    return new_head


def test_rotate_basic():
    assert to_list(rotate_right(from_list([1, 2, 3, 4, 5]), 2)) == [4, 5, 1, 2, 3]


def test_rotate_edge_cases():
    assert rotate_right(None, 3) is None
    assert to_list(rotate_right(from_list([7]), 5)) == [7]
    assert to_list(rotate_right(from_list([1, 2, 3]), 0)) == [1, 2, 3]
    assert to_list(rotate_right(from_list([1, 2, 3]), 3)) == [1, 2, 3]


def test_rotate_k_larger_than_length():
    assert to_list(rotate_right(from_list([1, 2, 3, 4, 5]), 7)) == [4, 5, 1, 2, 3]
    assert to_list(rotate_right(from_list([0, 1, 2]), 4)) == [2, 0, 1]


def test_rotate_one():
    assert to_list(rotate_right(from_list([1, 2]), 1)) == [2, 1]


def test_rotate_bad_k():
    for bad in (-1, True, 1.5, "2"):
        try:
            rotate_right(from_list([1, 2, 3]), bad)
        except LlError:
            pass
        else:
            raise AssertionError(f"expected LlError for k={bad!r}")


def test_rotate_bad_input():
    try:
        rotate_right("nope", 1)
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
    test_rotate_basic()
    test_rotate_edge_cases()
    test_rotate_k_larger_than_length()
    test_rotate_one()
    test_rotate_bad_k()
    test_rotate_bad_input()
    assert stdlib_only()
    print("ll-13 OK")


if __name__ == "__main__":
    main()
