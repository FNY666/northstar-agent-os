"""Intersection of two lists: find the shared node by reference.

Two lists intersect when their tails merge; aligning the starts by length
difference lets a lock-step walk meet exactly at the first shared node.
Runs in O(n + m) time with O(1) extra space. Inputs must be acyclic.

What this IS: a node-identity intersection finder returning the node/None.
What this IS NOT: a value-equality comparison of the two lists.
"""

from __future__ import annotations

import ast

#: Module version.
LL_11_VERSION = "ll-11.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-11.v1"


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


def _has_cycle(head):
    slow = head
    fast = head
    while fast is not None and fast.next is not None:
        slow = slow.next
        fast = fast.next.next
        if slow is fast:
            return True
    return False


def _length(head):
    n = 0
    cur = head
    while cur is not None:
        n += 1
        cur = cur.next
    return n


def _tail_of(head):
    tail = head
    while tail.next is not None:
        tail = tail.next
    return tail


def _with_shared_tail():
    shared = from_list([7, 8, 9])
    a = from_list([1, 2])
    b = from_list([3, 4, 5])
    _tail_of(a).next = shared
    _tail_of(b).next = shared
    return a, b, shared


def get_intersection(a, b):
    """Return the first node shared by both lists, or None."""
    _check_head(a)
    _check_head(b)
    if _has_cycle(a) or _has_cycle(b):
        raise LlError("inputs must be acyclic")
    la, lb = _length(a), _length(b)
    while la > lb:
        a = a.next
        la -= 1
    while lb > la:
        b = b.next
        lb -= 1
    while a is not None and b is not None:
        if a is b:
            return a
        a = a.next
        b = b.next
    return None


def test_intersect_basic():
    a, b, shared = _with_shared_tail()
    assert get_intersection(a, b) is shared
    assert get_intersection(a, b).val == 7


def test_no_intersection():
    assert get_intersection(from_list([1, 2]), from_list([1, 2])) is None
    assert get_intersection(None, from_list([1])) is None
    assert get_intersection(from_list([1]), None) is None
    assert get_intersection(None, None) is None


def test_same_list():
    head = from_list([1, 2, 3])
    assert get_intersection(head, head) is head


def test_intersect_at_head():
    shared = from_list([4, 5])
    b = from_list([1, 2, 3])
    _tail_of(b).next = shared
    assert get_intersection(shared, b) is shared


def test_cyclic_input_raises():
    node = Node(1)
    node.next = node
    try:
        get_intersection(node, from_list([1]))
    except LlError:
        pass
    else:
        raise AssertionError("expected LlError for cyclic input")


def test_bad_input():
    try:
        get_intersection([1], None)
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
    test_intersect_basic()
    test_no_intersection()
    test_same_list()
    test_intersect_at_head()
    test_cyclic_input_raises()
    test_bad_input()
    assert stdlib_only()
    print("ll-11 OK")


if __name__ == "__main__":
    main()
