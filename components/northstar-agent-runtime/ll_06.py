"""Middle of linked list: return the middle node with fast/slow pointers.

The fast pointer advances two steps per slow-pointer step, so when fast
reaches the end, slow sits on the middle (the second middle for even
lengths). Runs in O(n) time with O(1) extra space.

What this IS: a one-pass tortoise-and-hare middle finder.
What this IS NOT: a length-counting two-pass scan.
"""

from __future__ import annotations

import ast

#: Module version.
LL_06_VERSION = "ll-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-06.v1"


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


def middle_node(head):
    """Return the middle node (second middle on even length), or None."""
    _check_head(head)
    if head is None:
        return None
    slow = head
    fast = head
    while fast is not None and fast.next is not None:
        slow = slow.next
        fast = fast.next.next
    return slow


def test_middle_odd():
    assert middle_node(from_list([1, 2, 3, 4, 5])).val == 3


def test_middle_even():
    assert middle_node(from_list([1, 2, 3, 4, 5, 6])).val == 4


def test_middle_edge_cases():
    assert middle_node(None) is None
    assert middle_node(from_list([9])).val == 9
    assert middle_node(from_list([1, 2])).val == 2


def test_middle_returns_node_in_list():
    head = from_list([1, 2, 3, 4, 5])
    mid = middle_node(head)
    assert to_list(mid) == [3, 4, 5]


def test_middle_longer():
    head = from_list(list(range(1, 101)))
    assert middle_node(head).val == 51


def test_middle_bad_input():
    try:
        middle_node(123)
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
    test_middle_odd()
    test_middle_even()
    test_middle_edge_cases()
    test_middle_returns_node_in_list()
    test_middle_longer()
    test_middle_bad_input()
    assert stdlib_only()
    print("ll-06 OK")


if __name__ == "__main__":
    main()
