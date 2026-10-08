"""Remove all elements equal to value: filter the list by value.

A dummy head anchors the walk so leading matches are dropped cleanly;
every node whose value equals the target is unlinked in a single pass.
Runs in O(n) time with O(1) extra space.

What this IS: a single-pass filter dropping every matching node.
What this IS NOT: a filter that stops after the first match.
"""

from __future__ import annotations

import ast

#: Module version.
LL_21_VERSION = "ll-21.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-21.v1"


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


def remove_elements(head, val):
    """Remove every node whose value equals val; return the new head."""
    _check_head(head)
    dummy = Node(0)
    dummy.next = head
    prev = dummy
    cur = head
    while cur is not None:
        if cur.val == val:
            prev.next = cur.next
        else:
            prev = cur
        cur = cur.next
    return dummy.next


def test_remove_basic():
    assert to_list(remove_elements(from_list([1, 2, 6, 3, 4, 5, 6]), 6)) == [1, 2, 3, 4, 5]


def test_remove_edge_cases():
    assert remove_elements(None, 1) is None
    assert to_list(remove_elements(from_list([1, 2, 3]), 9)) == [1, 2, 3]
    assert remove_elements(from_list([6, 6, 6]), 6) is None
    assert to_list(remove_elements(from_list([6, 1, 2]), 6)) == [1, 2]
    assert to_list(remove_elements(from_list([1, 2, 6]), 6)) == [1, 2]


def test_remove_all_occurrences():
    assert to_list(remove_elements(from_list([1, 6, 6, 2, 6]), 6)) == [1, 2]


def test_remove_single_match():
    assert remove_elements(from_list([6]), 6) is None
    assert to_list(remove_elements(from_list([7]), 6)) == [7]


def test_remove_bad_input():
    try:
        remove_elements(object(), 1)
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
    test_remove_basic()
    test_remove_edge_cases()
    test_remove_all_occurrences()
    test_remove_single_match()
    test_remove_bad_input()
    assert stdlib_only()
    print("ll-21 OK")


if __name__ == "__main__":
    main()
