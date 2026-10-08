"""Cycle length: measure the cycle, 0 when there is none.

Floyd's pointers first detect a meeting inside the loop; from that node
one walk around the loop counts its nodes. Runs in O(n) time with
O(1) extra space and returns 0 for acyclic lists.

What this IS: a detect-then-measure loop-length computation.
What this IS NOT: a measure of the total list length.
"""

from __future__ import annotations

import ast

#: Module version.
LL_23_VERSION = "ll-23.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-23.v1"


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


def _make_cycle(vals, pos):
    """Build a list whose tail links back to index pos (-1 means no cycle)."""
    head = from_list(vals)
    if pos < 0 or head is None:
        return head
    target = head
    for _ in range(pos):
        if target is None:
            raise LlError("cycle position out of range")
        target = target.next
    tail = head
    while tail.next is not None:
        tail = tail.next
    tail.next = target
    return head


def cycle_length(head):
    """Return the number of nodes in the cycle, or 0 if there is none."""
    _check_head(head)
    slow = head
    fast = head
    while fast is not None and fast.next is not None:
        slow = slow.next
        fast = fast.next.next
        if slow is fast:
            n = 1
            cur = slow.next
            while cur is not slow:
                n += 1
                cur = cur.next
            return n
    return 0


def test_no_cycle():
    assert cycle_length(from_list([1, 2, 3, 4])) == 0
    assert cycle_length(None) == 0
    assert cycle_length(from_list([1])) == 0


def test_cycle_middle():
    assert cycle_length(_make_cycle([1, 2, 3, 4, 5], 2)) == 3


def test_cycle_at_head():
    assert cycle_length(_make_cycle([1, 2, 3], 0)) == 3


def test_self_loop():
    node = Node(9)
    node.next = node
    assert cycle_length(node) == 1


def test_single_node_cycle_in_tail():
    head = _make_cycle([1, 2, 3, 4], 3)
    assert cycle_length(head) == 1


def test_bad_input():
    try:
        cycle_length("nope")
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
    test_no_cycle()
    test_cycle_middle()
    test_cycle_at_head()
    test_self_loop()
    test_single_node_cycle_in_tail()
    test_bad_input()
    assert stdlib_only()
    print("ll-23 OK")


if __name__ == "__main__":
    main()
