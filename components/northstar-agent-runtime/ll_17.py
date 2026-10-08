"""Odd-even linked list: group odd-indexed nodes before even-indexed ones.

Two runners collect the 1st/3rd/5th... and 2nd/4th/6th... nodes in order,
then the odd chain is stitched to the head of the even chain.
Runs in O(n) time with O(1) extra space, keeping relative order.

What this IS: a stable in-place odd/even index regrouping.
What this IS NOT: a regrouping by odd/even node values.
"""

from __future__ import annotations

import ast

#: Module version.
LL_17_VERSION = "ll-17.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-17.v1"


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


def odd_even_list(head):
    """Group odd-indexed nodes before even-indexed ones; return the head."""
    _check_head(head)
    if head is None:
        return None
    odd = head
    even = head.next
    even_head = even
    while even is not None and even.next is not None:
        odd.next = even.next
        odd = odd.next
        even.next = odd.next
        even = even.next
    odd.next = even_head
    return head


def test_odd_even_basic():
    assert to_list(odd_even_list(from_list([1, 2, 3, 4, 5]))) == [1, 3, 5, 2, 4]


def test_odd_even_even_length():
    assert to_list(odd_even_list(from_list([1, 2, 3, 4]))) == [1, 3, 2, 4]


def test_odd_even_edge_cases():
    assert odd_even_list(None) is None
    assert to_list(odd_even_list(from_list([1]))) == [1]
    assert to_list(odd_even_list(from_list([1, 2]))) == [1, 2]
    assert to_list(odd_even_list(from_list([1, 2, 3]))) == [1, 3, 2]


def test_odd_even_by_index_not_value():
    # even values at odd positions stay up front: regrouping is by index
    assert to_list(odd_even_list(from_list([2, 1, 4, 3, 6, 5]))) == [2, 4, 6, 1, 3, 5]


def test_odd_even_bad_input():
    try:
        odd_even_list("nope")
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
    test_odd_even_basic()
    test_odd_even_even_length()
    test_odd_even_edge_cases()
    test_odd_even_by_index_not_value()
    test_odd_even_bad_input()
    assert stdlib_only()
    print("ll-17 OK")


if __name__ == "__main__":
    main()
