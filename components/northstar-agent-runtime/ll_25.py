"""Reverse sublist between positions m and n: reverse one segment in place.

A dummy head anchors the walk to the node before position m; the segment
[m, n] is then reversed with head-insert rewiring, leaving the rest of the
list untouched. Runs in O(n) time with O(1) extra space.

What this IS: a one-pass in-place reversal of a single 1-based segment.
What this IS NOT: a whole-list reversal or a value-swap reversal.
"""

from __future__ import annotations

import ast

#: Module version.
LL_25_VERSION = "ll-25.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-25.v1"


class LlError(Exception):
    """Fail-closed."""


class Node:
    def __init__(self, val):
        self.val = val
        self.next = None


def _check_head(head):
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")


def _check_pos(p, name):
    if isinstance(p, bool) or not isinstance(p, int) or p < 1:
        raise LlError(f"{name} must be a positive int")


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


def reverse_between(head, m, n):
    """Reverse the 1-based segment [m, n] in place; return the head."""
    _check_head(head)
    _check_pos(m, "m")
    _check_pos(n, "n")
    if m > n:
        raise LlError("m must be <= n")
    length = 0
    cur = head
    while cur is not None:
        length += 1
        cur = cur.next
    if n > length:
        raise LlError("n exceeds list length")
    dummy = Node(0)
    dummy.next = head
    prev = dummy
    for _ in range(m - 1):
        prev = prev.next
    tail = prev.next
    cur = tail.next
    for _ in range(n - m):
        nxt = cur.next
        cur.next = prev.next
        prev.next = cur
        tail.next = nxt
        cur = nxt
    return dummy.next


def test_reverse_basic():
    assert to_list(reverse_between(from_list([1, 2, 3, 4, 5]), 2, 4)) == [1, 4, 3, 2, 5]


def test_reverse_whole_list():
    assert to_list(reverse_between(from_list([1, 2, 3, 4, 5]), 1, 5)) == [5, 4, 3, 2, 1]


def test_reverse_edge_cases():
    assert to_list(reverse_between(from_list([1, 2, 3]), 2, 2)) == [1, 2, 3]
    assert to_list(reverse_between(from_list([1, 2, 3]), 1, 1)) == [1, 2, 3]
    assert to_list(reverse_between(from_list([1, 2, 3]), 1, 2)) == [2, 1, 3]
    assert to_list(reverse_between(from_list([1, 2, 3]), 2, 3)) == [1, 3, 2]


def test_reverse_singleton_segment():
    assert to_list(reverse_between(from_list([9]), 1, 1)) == [9]


def test_reverse_bad_positions():
    for m, n in ((3, 2), (0, 2), (1, 6), (-1, 2), (True, 2), (1.5, 2)):
        try:
            reverse_between(from_list([1, 2, 3, 4, 5]), m, n)
        except LlError:
            pass
        else:
            raise AssertionError(f"expected LlError for m={m!r}, n={n!r}")


def test_reverse_bad_input():
    try:
        reverse_between("nope", 1, 2)
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
    test_reverse_basic()
    test_reverse_whole_list()
    test_reverse_edge_cases()
    test_reverse_singleton_segment()
    test_reverse_bad_positions()
    test_reverse_bad_input()
    assert stdlib_only()
    print("ll-25 OK")


if __name__ == "__main__":
    main()
