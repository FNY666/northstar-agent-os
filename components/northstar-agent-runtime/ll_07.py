"""Palindrome check: test whether the list reads the same forwards/backwards.

Finds the middle, reverses the second half in place, compares the halves,
then reverses the second half back so the input list is left unchanged.
Runs in O(n) time with O(1) extra space.

What this IS: an O(1)-space compare-and-restore palindrome test.
What this IS NOT: a copy-into-array comparison or a destructive check.
"""

from __future__ import annotations

import ast

#: Module version.
LL_07_VERSION = "ll-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-07.v1"


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


def _reverse(head):
    prev = None
    cur = head
    while cur is not None:
        nxt = cur.next
        cur.next = prev
        prev = cur
        cur = nxt
    return prev


def is_palindrome(head):
    """Return True iff the list is a palindrome; the list is restored."""
    _check_head(head)
    if head is None or head.next is None:
        return True
    slow = head
    fast = head
    while fast.next is not None and fast.next.next is not None:
        slow = slow.next
        fast = fast.next.next
    second = _reverse(slow.next)
    first = head
    cur = second
    ok = True
    while cur is not None:
        if first.val != cur.val:
            ok = False
            break
        first = first.next
        cur = cur.next
    slow.next = _reverse(second)
    return ok


def test_palindrome_true():
    assert is_palindrome(from_list([1, 2, 2, 1])) is True
    assert is_palindrome(from_list([1, 2, 3, 2, 1])) is True


def test_palindrome_false():
    assert is_palindrome(from_list([1, 2, 3, 4])) is False
    assert is_palindrome(from_list([1, 2, 3, 2, 2])) is False


def test_palindrome_edge_cases():
    assert is_palindrome(None) is True
    assert is_palindrome(from_list([5])) is True
    assert is_palindrome(from_list([1, 1])) is True
    assert is_palindrome(from_list([1, 2])) is False


def test_palindrome_restores_list():
    for vals in ([1, 2, 2, 1], [1, 2, 3, 2, 1], [1, 2, 3, 4]):
        head = from_list(vals)
        is_palindrome(head)
        assert to_list(head) == vals, "list must be unchanged after the check"


def test_palindrome_bad_input():
    try:
        is_palindrome(object())
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
    test_palindrome_true()
    test_palindrome_false()
    test_palindrome_edge_cases()
    test_palindrome_restores_list()
    test_palindrome_bad_input()
    assert stdlib_only()
    print("ll-07 OK")


if __name__ == "__main__":
    main()
