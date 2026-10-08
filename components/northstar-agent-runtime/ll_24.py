"""Insert value into sorted list: keep the list sorted after insertion.

Walks until the first node whose value is not smaller than the new one,
then splices a fresh node in front of it; head insertion is handled too.
Runs in O(n) time with one new node allocated.

What this IS: a single-pass ordered insertion returning the head.
What this IS NOT: an append followed by a re-sort.
"""

from __future__ import annotations

import ast

#: Module version.
LL_24_VERSION = "ll-24.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-24.v1"


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


def insert_sorted(head, val):
    """Insert val into an ascending list, keeping it sorted; return head."""
    _check_head(head)
    new = Node(val)
    if head is None:
        return new
    try:
        at_head = val <= head.val
    except TypeError as e:
        raise LlError(f"val must be comparable with list values: {e}")
    if at_head:
        new.next = head
        return new
    cur = head
    while cur.next is not None:
        try:
            if cur.next.val >= val:
                break
        except TypeError as e:
            raise LlError(f"val must be comparable with list values: {e}")
        cur = cur.next
    new.next = cur.next
    cur.next = new
    return head


def test_insert_middle():
    assert to_list(insert_sorted(from_list([1, 3, 5]), 4)) == [1, 3, 4, 5]


def test_insert_edge_cases():
    assert to_list(insert_sorted(None, 2)) == [2]
    assert to_list(insert_sorted(from_list([2, 3]), 1)) == [1, 2, 3]
    assert to_list(insert_sorted(from_list([1, 2]), 5)) == [1, 2, 5]
    assert to_list(insert_sorted(from_list([1]), 1)) == [1, 1]


def test_insert_duplicate_stable():
    assert to_list(insert_sorted(from_list([1, 2, 2, 3]), 2)) == [1, 2, 2, 2, 3]


def test_insert_negative():
    assert to_list(insert_sorted(from_list([-5, 0, 5]), -1)) == [-5, -1, 0, 5]


def test_insert_uncomparable_raises():
    try:
        insert_sorted(from_list([1, 2]), "a")
    except LlError:
        pass
    else:
        raise AssertionError("expected LlError for uncomparable val")


def test_insert_bad_input():
    try:
        insert_sorted(42, 1)
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
    test_insert_middle()
    test_insert_edge_cases()
    test_insert_duplicate_stable()
    test_insert_negative()
    test_insert_uncomparable_raises()
    test_insert_bad_input()
    assert stdlib_only()
    print("ll-24 OK")


if __name__ == "__main__":
    main()
