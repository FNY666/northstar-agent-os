"""Delete duplicates II: drop every value that appears more than once.

In a sorted list, a run of equal values means duplication; the whole run
is skipped and only values appearing exactly once survive.
Runs in O(n) time with O(1) extra space.

What this IS: a run-skipping pass keeping only unique values.
What this IS NOT: the variant that keeps one copy of each duplicated value.
"""

from __future__ import annotations

import ast

#: Module version.
LL_22_VERSION = "ll-22.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-22.v1"


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


def delete_duplicates_ii(head):
    """Remove every node whose value is duplicated; return the new head."""
    _check_head(head)
    dummy = Node(0)
    dummy.next = head
    prev = dummy
    cur = head
    while cur is not None:
        if cur.next is not None and cur.val == cur.next.val:
            dup_val = cur.val
            while cur is not None and cur.val == dup_val:
                cur = cur.next
            prev.next = cur
        else:
            prev = cur
            cur = cur.next
    return dummy.next


def test_dedup_ii_basic():
    assert to_list(delete_duplicates_ii(from_list([1, 2, 3, 3, 4, 4, 5]))) == [1, 2, 5]


def test_dedup_ii_head_run():
    assert to_list(delete_duplicates_ii(from_list([1, 1, 1, 2, 3]))) == [2, 3]


def test_dedup_ii_edge_cases():
    assert delete_duplicates_ii(None) is None
    assert to_list(delete_duplicates_ii(from_list([1]))) == [1]
    assert delete_duplicates_ii(from_list([1, 1, 1])) is None
    assert to_list(delete_duplicates_ii(from_list([1, 2, 3]))) == [1, 2, 3]


def test_dedup_ii_tail_run():
    assert to_list(delete_duplicates_ii(from_list([1, 2, 3, 3]))) == [1, 2]


def test_dedup_ii_bad_input():
    try:
        delete_duplicates_ii([1, 1])
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
    test_dedup_ii_basic()
    test_dedup_ii_head_run()
    test_dedup_ii_edge_cases()
    test_dedup_ii_tail_run()
    test_dedup_ii_bad_input()
    assert stdlib_only()
    print("ll-22 OK")


if __name__ == "__main__":
    main()
