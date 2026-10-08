"""Remove nth node from end: delete the nth node from the tail in one pass.

A fast pointer runs n steps ahead of a slow pointer from a dummy head;
when fast reaches the end, slow sits right before the node to drop.
Runs in O(n) time with O(1) extra space.

What this IS: a single-pass two-pointer deletion returning the new head.
What this IS NOT: a two-pass length-then-index deletion.
"""

from __future__ import annotations

import ast

#: Module version.
LL_05_VERSION = "ll-05.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-05.v1"


class LlError(Exception):
    """Fail-closed."""


class Node:
    def __init__(self, val):
        self.val = val
        self.next = None


def _check_head(head):
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")


def _check_n(n):
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise LlError("n must be a positive int")


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


def remove_nth_from_end(head, n):
    """Remove the nth node from the end; return the new head."""
    _check_head(head)
    _check_n(n)
    dummy = Node(0)
    dummy.next = head
    fast = dummy
    for _ in range(n):
        fast = fast.next
        if fast is None:
            raise LlError("n exceeds list length")
    slow = dummy
    while fast.next is not None:
        fast = fast.next
        slow = slow.next
    slow.next = slow.next.next
    return dummy.next


def test_remove_middle():
    assert to_list(remove_nth_from_end(from_list([1, 2, 3, 4, 5]), 2)) == [1, 2, 3, 5]


def test_remove_head():
    assert to_list(remove_nth_from_end(from_list([1, 2, 3, 4, 5]), 5)) == [2, 3, 4, 5]


def test_remove_tail():
    assert to_list(remove_nth_from_end(from_list([1, 2, 3]), 1)) == [1, 2]


def test_remove_single():
    assert remove_nth_from_end(from_list([9]), 1) is None


def test_remove_edge_cases():
    assert to_list(remove_nth_from_end(from_list([1, 2]), 2)) == [2]
    assert to_list(remove_nth_from_end(from_list([1, 2]), 1)) == [1]


def test_remove_bad_n():
    for bad in (0, -1, 6, True, "2", 2.0):
        try:
            remove_nth_from_end(from_list([1, 2, 3, 4, 5]), bad)
        except LlError:
            pass
        else:
            raise AssertionError(f"expected LlError for n={bad!r}")


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
    test_remove_middle()
    test_remove_head()
    test_remove_tail()
    test_remove_single()
    test_remove_edge_cases()
    test_remove_bad_n()
    assert stdlib_only()
    print("ll-05 OK")


if __name__ == "__main__":
    main()
