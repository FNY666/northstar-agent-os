"""Find cycle start node: return the node where a cycle begins.

First Floyd's meeting finds any node inside the loop; then one pointer
restarts at the head and both walk one step until they reunite -- that
meeting point is the cycle entry. O(n) time, O(1) space.

What this IS: the Floyd phase-two entry finder returning the node or None.
What this IS NOT: a cycle-length measurer or a visited-set traversal.
"""

from __future__ import annotations

import ast

#: Module version.
LL_04_VERSION = "ll-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-04.v1"


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


def find_cycle_start(head):
    """Return the node where the cycle begins, or None if there is none."""
    _check_head(head)
    slow = head
    fast = head
    while fast is not None and fast.next is not None:
        slow = slow.next
        fast = fast.next.next
        if slow is fast:
            break
    else:
        return None
    slow = head
    while slow is not fast:
        slow = slow.next
        fast = fast.next
    return slow


def _node_at(head, idx):
    cur = head
    for _ in range(idx):
        cur = cur.next
    return cur


def test_start_middle():
    head = _make_cycle([1, 2, 3, 4, 5], 2)
    start = find_cycle_start(head)
    assert start is _node_at(head, 2)
    assert start.val == 3


def test_start_at_head():
    head = _make_cycle([1, 2, 3], 0)
    assert find_cycle_start(head) is head


def test_no_cycle():
    assert find_cycle_start(from_list([1, 2, 3])) is None
    assert find_cycle_start(None) is None
    assert find_cycle_start(from_list([1])) is None


def test_self_loop():
    node = Node(7)
    node.next = node
    assert find_cycle_start(node) is node


def test_start_single_before_loop():
    head = _make_cycle([10, 20, 30], 1)
    start = find_cycle_start(head)
    assert start is _node_at(head, 1)
    assert start.val == 20


def test_bad_input():
    try:
        find_cycle_start([1, 2])
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
    test_start_middle()
    test_start_at_head()
    test_no_cycle()
    test_self_loop()
    test_start_single_before_loop()
    test_bad_input()
    assert stdlib_only()
    print("ll-04 OK")


if __name__ == "__main__":
    main()
