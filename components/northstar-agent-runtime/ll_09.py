"""Remove duplicates from sorted list: keep one copy of each value.

Because the list is sorted, duplicates sit next to each other, so one
pass can unlink every node whose value equals its predecessor's.
Runs in O(n) time with O(1) extra space.

What this IS: an adjacent-dedup pass over an ascending list.
What this IS NOT: the "delete duplicates II" variant that drops all copies.
"""

from __future__ import annotations

import ast

#: Module version.
LL_09_VERSION = "ll-09.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-09.v1"


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


def delete_duplicates_sorted(head):
    """Drop adjacent duplicates; return the head."""
    _check_head(head)
    cur = head
    while cur is not None and cur.next is not None:
        if cur.val == cur.next.val:
            cur.next = cur.next.next
        else:
            cur = cur.next
    return head


def test_dedup_basic():
    assert to_list(delete_duplicates_sorted(from_list([1, 1, 2]))) == [1, 2]
    assert to_list(delete_duplicates_sorted(from_list([1, 1, 2, 3, 3]))) == [1, 2, 3]


def test_dedup_edge_cases():
    assert delete_duplicates_sorted(None) is None
    assert to_list(delete_duplicates_sorted(from_list([1]))) == [1]
    assert to_list(delete_duplicates_sorted(from_list([1, 1, 1]))) == [1]
    assert to_list(delete_duplicates_sorted(from_list([1, 2, 3]))) == [1, 2, 3]


def test_dedup_long_run():
    assert to_list(delete_duplicates_sorted(from_list([1, 1, 1, 2, 2, 3, 3, 3, 3]))) == [1, 2, 3]


def test_dedup_tail_run():
    assert to_list(delete_duplicates_sorted(from_list([1, 2, 3, 3]))) == [1, 2, 3]


def test_dedup_bad_input():
    try:
        delete_duplicates_sorted({"a": 1})
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
    test_dedup_basic()
    test_dedup_edge_cases()
    test_dedup_long_run()
    test_dedup_tail_run()
    test_dedup_bad_input()
    assert stdlib_only()
    print("ll-09 OK")


if __name__ == "__main__":
    main()
