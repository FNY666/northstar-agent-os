"""Swap nodes in pairs: exchange every two adjacent nodes.

A dummy head anchors the walk; each pair is rewired so the second node
leads, with the previous pair's tail stitched to the new front.
Runs in O(n) time with O(1) extra space, swapping links not values.

What this IS: an in-place adjacent-pair link swap returning the new head.
What this IS NOT: a swap that copies values between nodes.
"""

from __future__ import annotations

import ast

#: Module version.
LL_14_VERSION = "ll-14.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-14.v1"


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


def swap_pairs(head):
    """Swap every two adjacent nodes; return the new head."""
    _check_head(head)
    dummy = Node(0)
    dummy.next = head
    prev = dummy
    while prev.next is not None and prev.next.next is not None:
        a = prev.next
        b = a.next
        prev.next = b
        a.next = b.next
        b.next = a
        prev = a
    return dummy.next


def test_swap_even():
    assert to_list(swap_pairs(from_list([1, 2, 3, 4]))) == [2, 1, 4, 3]


def test_swap_odd():
    assert to_list(swap_pairs(from_list([1, 2, 3]))) == [2, 1, 3]
    assert to_list(swap_pairs(from_list([1, 2, 3, 4, 5]))) == [2, 1, 4, 3, 5]


def test_swap_edge_cases():
    assert swap_pairs(None) is None
    assert to_list(swap_pairs(from_list([1]))) == [1]
    assert to_list(swap_pairs(from_list([1, 2]))) == [2, 1]


def test_swap_preserves_nodes():
    head = from_list([1, 2, 3, 4])
    nodes_before = []
    cur = head
    while cur is not None:
        nodes_before.append(cur)
        cur = cur.next
    out = swap_pairs(head)
    nodes_after = []
    cur = out
    while cur is not None:
        nodes_after.append(cur)
        cur = cur.next
    assert sorted(map(id, nodes_after)) == sorted(map(id, nodes_before))


def test_swap_bad_input():
    try:
        swap_pairs([1, 2])
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
    test_swap_even()
    test_swap_odd()
    test_swap_edge_cases()
    test_swap_preserves_nodes()
    test_swap_bad_input()
    assert stdlib_only()
    print("ll-14 OK")


if __name__ == "__main__":
    main()
